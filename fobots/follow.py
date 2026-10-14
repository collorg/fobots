# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Reading the logs: tail -F like following, and one thread per log."""
import os
import queue
import stat
import sys
import threading
import time


def follow(path, from_start=False, poll=0.5, grace=2.0):
    """Like `tail -F`: follows the file through rotation and truncation.

    After a rename (logrotate `create`), the server still writes to the old file until it
    reopens it: we read it `grace` more seconds before moving to the new one, so as not
    to lose any line."""
    f, inode, buf, first, rotated_at = None, None, b"", True, None
    while True:
        if f is None:
            try:
                f = open(path, "rb")
            except OSError:
                first = False  # the file will appear later: we will read it entirely
                time.sleep(poll)
                continue
            inode = os.fstat(f.fileno()).st_ino
            if first and not from_start:
                f.seek(0, os.SEEK_END)
            first, buf = False, b""
        line = f.readline()
        if line:
            buf += line
            if buf.endswith(b"\n"):  # otherwise the write is in progress: wait for the rest
                yield buf.decode(errors="replace")
                buf = b""
            continue
        try:
            st = os.stat(path)
        except OSError:
            st = None
        if st is None or st.st_ino != inode:  # rotation: we will move to the new file
            now = time.monotonic()
            rotated_at = rotated_at or now
            if now - rotated_at < grace:
                time.sleep(0.1)
                continue
            f.close()
            f, rotated_at = None, None
            if st is None:
                time.sleep(poll)
        elif st.st_size < f.tell():          # truncation (copytruncate)
            f.seek(0)
        else:
            time.sleep(poll)



def stdin_is_feed():
    """Is stdin a usable feed (pipe or file)? Neither a terminal, nor /dev/null, nor closed."""
    try:
        mode = os.fstat(sys.stdin.fileno()).st_mode
    except (OSError, ValueError, AttributeError):
        return False
    return stat.S_ISFIFO(mode) or stat.S_ISREG(mode)



def log_lines(args):
    if args.files:  # files given on the command line: read once (- = stdin)
        for path in args.files:
            f = sys.stdin if path == "-" else open(path, errors="replace")
            with f:
                yield from f
    else:
        yield from sys.stdin



def run_sites(det, sites, from_start, queue_size=200_000):
    """Follows all the logs (one thread per log); a single thread processes the lines, so
    the count per range stays global and lock-free. The bounded queue limits memory:
    if processing falls behind, the readers wait (nothing is lost)."""
    q = queue.Queue(maxsize=queue_size)

    def reader(site):
        for line in follow(site.log, from_start):
            q.put((site, line))

    for site in sites:
        threading.Thread(target=reader, args=(site,), daemon=True, name=f"log-{site.name}").start()
    while True:
        try:
            site, line = q.get(timeout=1)  # timeout: lets signals through
        except queue.Empty:
            continue
        det.feed_line(line, site)

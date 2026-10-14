# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Findings about monitored IPs caught in a ban (JSON lines file)."""
import json
import logging
import os
import time

log = logging.getLogger("fobots")


WATCH_FILE_KEEP = 30 * 86400  # the findings file is pruned beyond this (at startup)



def append_event(path, event):
    try:
        with open(path, "a") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError as e:
        log.warning("cannot write %s: %s", path, e)



def read_events(path, since):
    """Findings more recent than `since` (epoch); unreadable lines are ignored."""
    out = []
    try:
        f = open(path)
    except OSError:
        return out
    with f:
        for line in f:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if isinstance(ev, dict) and ev.get("t", 0) >= since:
                out.append(ev)
    return out



def trim_events(path, keep=WATCH_FILE_KEEP):
    """Removes findings that are too old (atomic write)."""
    if not os.path.exists(path):
        return
    events = read_events(path, time.time() - keep)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            for ev in events:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        os.replace(tmp, path)
    except OSError as e:
        log.warning("cannot prune %s: %s", path, e)

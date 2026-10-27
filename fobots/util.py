# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Small helpers: timestamps, durations, address ranges, welcome-list arithmetic."""
import argparse
import ipaddress
import os
import re
import tempfile
from datetime import datetime
from functools import lru_cache


@lru_cache(maxsize=4096)
def parse_ts(s):
    return int(datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").timestamp())



def parse_duration(s):
    m = re.fullmatch(r"(\d+)([smhd])", s)
    if not m:
        raise argparse.ArgumentTypeError(f"invalid duration: {s!r} (e.g. 30m, 1h, 1d)")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]



def addr_cls(ver):
    return ipaddress.IPv4Address if ver == 4 else ipaddress.IPv6Address



def range_nets(r):
    ver, start, end = r
    return list(ipaddress.summarize_address_range(addr_cls(ver)(start), addr_cls(ver)(end)))



def fmt_range(r):
    nets = range_nets(r)
    if len(nets) == 1:
        return str(nets[0])
    return f"{addr_cls(r[0])(r[1])}-{addr_cls(r[0])(r[2])}"



def prefix_of(addr):
    return ipaddress.ip_network((addr, 16 if addr.version == 4 else 32), strict=False)



def subtract(net, welcome):
    """Pieces of `net` that do not touch the welcome list (CIDR: included or disjoint)."""
    for w in welcome:
        if w.version == net.version and net.overlaps(w):
            if net.subnet_of(w):
                return []
            pieces = []
            for piece in net.address_exclude(w):
                pieces += subtract(piece, welcome)
            return pieces
    return [net]



def write_atomic(path, text):
    """Writes `text` to `path` through a temporary file of the same directory, then a rename.
    The temporary file is created exclusively (mkstemp): it never follows a link planted in the
    state directory, which belongs to `fobots` while the administration commands run as root."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)),
                               prefix=os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            os.fchmod(f.fileno(), 0o644)
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise



def append_text(path, text):
    """Appends `text` to `path`, refusing to follow a symbolic link (same reason as write_atomic)."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "a") as f:
        f.write(text)

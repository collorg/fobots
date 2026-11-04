# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Access of the service to the logs: the groups the paths require, those the unit gives, and
the drop-in that adds the missing ones (shared by `init` and `install`)."""
import os
import re
import subprocess

from .constants import ACCESS_DROPIN, PACKAGE_UNIT, SERVICE_USER, UNIT_PATH
from .util import log_access, write_atomic


def service_groups(units=(UNIT_PATH, PACKAGE_UNIT), dropins=UNIT_PATH + ".d", skip=None):
    """SupplementaryGroups the service gets: the unit (/etc wins over the package's in
    /usr/lib, as for systemd), then its drop-ins (systemctl edit) in the order systemd reads
    them; an empty assignment resets the list. `skip`: a drop-in left out (ours, to compute
    it again). adm, the one of the example unit, if no unit is installed."""
    files = [next((u for u in units if os.path.exists(u)), None)]
    try:
        files += sorted(os.path.join(dropins, n) for n in os.listdir(dropins)
                        if n.endswith(".conf") and os.path.join(dropins, n) != skip)
    except OSError:
        pass
    groups, seen = [], False
    for p in files:
        try:
            with open(p) as f:
                text = f.read()
        except (OSError, TypeError):
            continue
        for m in re.finditer(r"(?m)^\s*SupplementaryGroups\s*=(.*)$", text):
            seen, values = True, m.group(1).split()
            groups = groups + [g for g in values if g not in groups] if values else []
    return groups if seen else ["adm"]


def blocker_advice(blocker):
    return (f"is behind {blocker}, which no group opens: setfacl -m u:{SERVICE_USER}:x on "
            f"that directory (r on a file), or, in systemctl edit fobots: [Service] "
            f"AmbientCapabilities=CAP_DAC_READ_SEARCH and "
            f"CapabilityBoundingSet=CAP_DAC_READ_SEARCH (read everything, write nothing)")


def missing_groups(paths, have):
    """(groups the service lacks for these logs, [(path, blocker)] that no group opens).
    A missing log is left out: the daemon waits for it, and says so."""
    missing, blocked = [], []
    for path in paths:
        try:
            need, blocker = log_access(path)
        except OSError:
            continue
        if blocker:
            blocked.append((path, blocker))
        missing += [g for g in need if g not in have and g not in missing]
    return missing, blocked


def dropin_text(groups):
    return ("# Written by fobots (init, install): the groups that open the logs to the service,\n"
            "# computed from the directories crossed. Written again at each run; to give up: delete\n"
            "# this file, then systemctl daemon-reload.\n"
            f"[Service]\nSupplementaryGroups={' '.join(groups)}\n")


def sync_dropin(paths, path=ACCESS_DROPIN, dry=False, say=print, reload=True):
    """Gives the service the groups its logs require and the unit lacks, in our drop-in
    (written, rewritten, or deleted if no longer needed), then daemon-reload. Returns the
    logs that no group opens ([(path, blocker)]), to be told to the administrator."""
    have = service_groups(skip=path)
    missing, blocked = missing_groups(paths, have)
    want = dropin_text(missing) if missing else None
    try:
        with open(path) as f:
            current = f.read()
    except OSError:
        current = None
    if want == current:
        if missing:
            say("ok", f"groups {' '.join(missing)} already given to the service ({path})")
        return blocked
    if dry:
        say("..", f"would write {path}: SupplementaryGroups={' '.join(missing)}" if missing
            else f"would delete {path} (no longer needed)")
        return blocked
    if missing:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        write_atomic(path, want)
        say("ok", f"the logs need the group(s) {' '.join(missing)}, which the unit does not give "
            f"(it has: {' '.join(have) or 'none'}): added in {path}")
    else:
        os.remove(path)
        say("ok", f"{path} deleted: the unit gives the groups the logs need")
    if reload:
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        say("ok", "systemctl daemon-reload done; a running service takes them at its restart: "
            "systemctl restart fobots")
    return blocked

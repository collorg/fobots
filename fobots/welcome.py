# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Welcome list (ranges never banned) and the ban transaction logic."""
import ipaddress
import logging
import os
from datetime import datetime

from .nft import NftError
from .util import fmt_range, range_nets, subtract

log = logging.getLogger("fobots")


class Welcome:
    """List of CIDRs, reread automatically when the file changes."""

    def __init__(self, path):
        self.path, self.nets, self.mtime = path, [], "unset"
        self.reload()

    def reload(self):
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            mtime = None
        if mtime == self.mtime:
            return
        self.mtime, nets = mtime, []
        if mtime is not None:
            with open(self.path) as f:
                for line in f:
                    line = line.split("#")[0].strip()
                    if not line:
                        continue
                    try:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        log.warning("welcome list: line ignored %r", line)
        self.nets = nets
        log.info("welcome list: %d range(s) in %s%s", len(nets), os.path.abspath(self.path),
                 "" if mtime is not None else " (file missing)")

    @staticmethod
    def append(path, nets):
        with open(path, "a") as f:
            for n in nets:
                f.write(f"{n}  # added on {datetime.now():%Y-%m-%d %H:%M}\n")



class NoWelcome:
    """An empty list: nothing is protected."""
    nets = ()

    def reload(self):
        pass


NO_WELCOME = NoWelcome()



class Banner:
    def __init__(self, nft, welcome, ban_seconds):
        self.nft, self.welcome, self.ban_seconds = nft, welcome, ban_seconds

    def ban(self, rng, reason, seconds=None, welcome=None):
        """Bans the range (outside the welcome list, without duplicates or nft conflicts).
        `welcome`: another list than the usual one (trap bans have their own)."""
        seconds = seconds or self.ban_seconds
        welcome = welcome or self.welcome
        welcome.reload()
        ver = rng[0]
        pieces = []
        for n in range_nets(rng):
            pieces += subtract(n, welcome.nets)
        pieces = list(ipaddress.collapse_addresses(pieces))
        if not pieces:
            log.info("%s: entirely in the welcome list, no ban", fmt_range(rng))
            return False
        for attempt in (1, 2):
            elems = self.nft.elements(ver)
            existing = [n for n, _ in elems]
            adds, deletes = [], set()
            for p in pieces:
                if any(p.subnet_of(e) for e in existing):
                    continue  # already covered
                adds.append((p, seconds))
                deletes.update(e for e in existing if e.subnet_of(p))
            if not adds:
                log.debug("%s: already banned", fmt_range(rng))
                return False
            try:
                restore = [(n, e or seconds) for n, e in elems if n in deletes]
                self.nft.apply(ver, sorted(deletes, key=lambda n: n.network_address), adds, restore)
                break
            except NftError as e:
                # often an element expired between the read and the removal: read again
                log.warning("nft refused (attempt %d): %s", attempt, e)
                if attempt == 2:
                    raise
        log.info("BAN %s for %d s (%s)%s", ", ".join(str(a) for a, _ in adds),
                 seconds, reason,
                 f", {len(deletes)} included ban(s) replaced" if deletes else "")
        return True



def welcome_add(nft, net, ban_seconds):
    """Removes from the sets the bans that touch `net`; keeps the rest of the wider ones."""
    ver = net.version
    existing = nft.elements(ver)
    deletes, adds, restore = [], [], []
    for e, exp in existing:
        if not e.overlaps(net):
            continue
        deletes.append(e)
        restore.append((e, exp or ban_seconds))
        if not e.subnet_of(net):  # `net` is strictly inside e: look at the rest
            adds += [(p, exp or ban_seconds) for p in e.address_exclude(net)]
    if deletes:
        nft.apply(ver, deletes, adds, restore)
    return deletes, adds

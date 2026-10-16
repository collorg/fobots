# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Known IP ranges (cache on disk) and the background RDAP resolver."""
import ipaddress
import json
import logging
import os
import queue
import threading
import time
import urllib.error
import urllib.request
from collections import deque

from .util import fmt_range

log = logging.getLogger("fobots")


RDAP_URL = "https://rdap.org/ip/{}"  # redirects to the competent RIR

# An RDAP answer wider than this is rejected (safeguard against 0.0.0.0/0).
MIN_PREFIX = {4: 8, 6: 16}



class RangeStore:
    """Known ranges (version, start, end), persisted as JSON (atomic write)."""

    def __init__(self, path):
        self.path = path
        self.version = 0  # incremented on each addition (invalidates the memos)
        self._lock = threading.Lock()
        self.ranges = ()
        self.names = {}  # range -> name of the organisation (when known)
        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                self.ranges = tuple({tuple(r[:3]) for r in data})
                self.names = {tuple(r[:3]): r[3] for r in data if len(r) > 3 and r[3]}
            except (OSError, ValueError) as e:
                log.warning("cache %s unreadable (%s), starting from scratch", path, e)

    def find(self, addr):
        """Most specific range containing addr, or None."""
        a, best = int(addr), None
        for r in self.ranges:
            if r[0] == addr.version and r[1] <= a <= r[2]:
                if best is None or r[2] - r[1] < best[2] - best[1]:
                    best = r
        return best

    def name(self, r):
        return self.names.get(tuple(r[:3]), "")

    def add(self, r, name=""):
        with self._lock:
            new = r not in self.ranges
            if not new and (not name or self.names.get(r) == name):
                return
            if new:
                self.ranges = self.ranges + (r,)
                self.version += 1
            if name:
                self.names[r] = name
            if self.path:
                tmp = self.path + ".tmp"
                with open(tmp, "w") as f:
                    json.dump([list(x) + [self.names[x]] if x in self.names else list(x)
                               for x in self.ranges], f)
                os.replace(tmp, self.path)



class RdapError(Exception):
    def __init__(self, msg, retry=1800, pause=0):
        super().__init__(msg)
        self.retry = retry  # seconds before retrying this prefix
        self.pause = pause  # seconds of global pause (429)



def abuse_email(data):
    """Email of the entity with the `abuse` role (searched in nested entities), or ""."""
    for ent in data.get("entities") or []:
        if "abuse" in (ent.get("roles") or []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "email" and item[-1]:
                    return str(item[-1])
        found = abuse_email(ent)
        if found:
            return found
    return ""


def label(data):
    """Organisation as shown by `bans`: name of the allocation and abuse contact."""
    return " ".join(x for x in (str(data.get("name") or ""), abuse_email(data)) if x)


def fetch_rdap(ip):
    req = urllib.request.Request(RDAP_URL.format(ip),
                                 headers={"Accept": "application/rdap+json",
                                          "User-Agent": "fobots/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.load(r)
        return (ipaddress.ip_address(data["startAddress"]),
                ipaddress.ip_address(data["endAddress"]), label(data))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            ra = e.headers.get("Retry-After", "")
            pause = int(ra) if ra.isdigit() else 600
            raise RdapError("HTTP 429", retry=pause, pause=pause)
        raise RdapError(f"HTTP {e.code}", retry=1800)
    except (OSError, ValueError, KeyError) as e:
        raise RdapError(f"{type(e).__name__}: {e}", retry=300)



class Rdap(threading.Thread):
    """Queries RDAP in the background, with delay, hourly budget and pause on 429."""

    def __init__(self, store, delay, per_hour, fetch=None):
        super().__init__(daemon=True, name="rdap")
        self.store, self.delay, self.per_hour = store, delay, per_hour
        self.fetch = fetch or fetch_rdap
        self.q = queue.Queue()
        self.pending = set()  # prefixes waiting (one at a time)
        self.retry = {}       # prefix -> instant (monotonic) before a new attempt
        self.times = deque()  # instants of the last requests
        self.paused_until = 0.0

    def request(self, addr, prefix):
        if prefix in self.pending or self.retry.get(prefix, 0) > time.monotonic():
            return
        self.pending.add(prefix)
        self.q.put((addr, prefix))

    def _wait_budget(self):
        now = time.monotonic()
        if now < self.paused_until:
            time.sleep(self.paused_until - now)
        while True:
            now = time.monotonic()
            while self.times and now - self.times[0] > 3600:
                self.times.popleft()
            if len(self.times) < self.per_hour:
                break
            time.sleep(self.times[0] + 3600 - now + 1)
        if self.times:
            wait = self.times[-1] + self.delay - now
            if wait > 0:
                time.sleep(wait)
        self.times.append(time.monotonic())

    def run(self):
        while True:
            addr, prefix = self.q.get()
            try:
                self._wait_budget()
                start, end, *rest = self.fetch(str(addr))
                ver = addr.version
                if not int(start) <= int(addr) <= int(end):
                    raise RdapError("the range does not contain the IP", retry=3600)
                if int(end) - int(start) + 1 > 2 ** (addr.max_prefixlen - MIN_PREFIX[ver]):
                    raise RdapError(f"range too wide ({start}-{end})", retry=3600)
                r = (ver, int(start), int(end))
                self.store.add(r, rest[0] if rest else "")
                log.info("RDAP %s -> %s %s", addr, fmt_range(r), rest[0] if rest else "")
            except RdapError as e:
                log.warning("RDAP %s: %s", addr, e)
                self.retry[prefix] = time.monotonic() + e.retry
                if e.pause:
                    self.paused_until = time.monotonic() + e.pause
                    log.warning("RDAP paused for %d s", e.pause)
            except Exception:
                log.exception("RDAP %s: unexpected error", addr)
                self.retry[prefix] = time.monotonic() + 300
            finally:
                self.pending.discard(prefix)

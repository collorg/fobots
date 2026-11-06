# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Known IP ranges (cache on disk) and the background RDAP resolver."""
import ipaddress
import json
import logging
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque

from .util import fmt_range, printable, write_atomic

log = logging.getLogger("fobots")


RDAP_URL = "https://rdap.org/ip/{}"  # redirects to the competent RIR

# An RDAP answer wider than this is rejected (safeguard against 0.0.0.0/0).
MIN_PREFIX = {4: 8, 6: 16}

MAX_ANSWER = 1 << 20   # bytes: an RDAP answer is a few kB

MAX_PAUSE = 3600       # seconds: longest pause asked by a 429 (Retry-After) that is obeyed

# Finest counting block deduced inside a parent range (see RangeStore.find): an ISP that assigns
# a /29 to a customer is still counted by /24 (IPv6: /48), never IP by IP.
UNIT_FINEST = {4: 24, 6: 48}

# Types of an RDAP answer that are granted by the registry itself (PI, portable, direct, legacy,
# or the allocation of an ISP): their "parent" is a block of the registry, shared by unrelated
# operators, never a range to resolve with. Only a sub-assignment (ASSIGNMENT, ASSIGNED PA,
# REASSIGNMENT, ALLOCATED-BY-LIR…) gives the allocation of its ISP.
REGISTRY_TYPES = re.compile(r"PORTABLE|DIRECT|BY-RIR|LEGACY|\bPI\b|^ALLOCATED\b(?!-BY-LIR)", re.I)



def _most_specific(ranges, ver, a):
    best = None
    for r in ranges:
        if r[0] == ver and r[1] <= a <= r[2]:
            if best is None or r[2] - r[1] < best[2] - best[1]:
                best = r
    return best


def unit_of(ver, r):
    """Prefix length of the counting blocks deduced from the sub-assignment r: its size (rounded
    down to a power of two), never finer than UNIT_FINEST."""
    bits = ipaddress.IPV4LENGTH if ver == 4 else ipaddress.IPV6LENGTH
    return min(bits - ((r[2] - r[1] + 1).bit_length() - 1), UNIT_FINEST[ver])


class RangeStore:
    """Known ranges (version, start, end), persisted as JSON (atomic write).

    A range given by RDAP is a sub-assignment of an ISP when the registry knows its parent (the
    allocation of the ISP): the parent is kept too, with the size of that sub-assignment, so that
    the other IPs of the ISP resolve without an RDAP request each (see find). In the file, a parent
    is [version, start, end, name, prefix length of its blocks]."""

    def __init__(self, path):
        self.path = path
        self.version = 0  # incremented on each addition (invalidates the memos)
        self._lock = threading.Lock()
        self.ranges = ()
        self.names = {}  # range -> name of the organisation (when known)
        self.parents = {}  # parent range -> (prefix length of its counting blocks, name)
        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                plain = [r for r in data if len(r) < 5]
                self.ranges = tuple({tuple(r[:3]) for r in plain})
                self.names = {tuple(r[:3]): r[3] for r in plain if len(r) > 3 and r[3]}
                self.parents = {tuple(r[:3]): (int(r[4]), str(r[3])) for r in data if len(r) > 4}
            except (OSError, ValueError, TypeError) as e:
                log.warning("cache %s unreadable (%s), starting from scratch", path, e)

    def find(self, addr):
        """Most specific range containing addr, or None. An IP outside every known range but
        inside a known parent gets a deduced block: the aligned block of the parent's size that
        contains it, narrowed until it overlaps no known range (counted apart already)."""
        a, ver = int(addr), addr.version
        best = _most_specific(self.ranges, ver, a)
        if best is not None:
            return best
        parent = _most_specific(self.parents, ver, a)
        if parent is None:
            return None
        bits = addr.max_prefixlen
        for plen in range(self.parents[parent][0], bits + 1):
            size = 1 << (bits - plen)
            r = (ver, max(a - a % size, parent[1]), min(a - a % size + size - 1, parent[2]))
            if not any(x[0] == ver and x[1] <= r[2] and r[1] <= x[2] for x in self.ranges):
                return r
        return None  # unreachable: addr itself is in no known range

    def parent_of(self, r):
        """Parent a deduced block r comes from, or None (r given by RDAP, or unknown)."""
        if tuple(r[:3]) in self.ranges:
            return None
        return _most_specific(self.parents, r[0], r[1])

    def name(self, r):
        r = tuple(r[:3])
        if r in self.names:
            return self.names[r]
        parent = self.parent_of(r)
        return self.parents[parent][1] if parent else ""

    def add(self, r, name="", parent=None, parent_name=""):
        """Adds the range r given by RDAP, and its parent (the allocation of its ISP) if any.
        parent_name: what the blocks deduced in the parent are shown with, the abuse contact
        only (the name of r is that of one customer of the ISP, not of the other blocks)."""
        with self._lock:
            new = r not in self.ranges
            new_parent = parent is not None and parent not in self.parents
            if not new and not new_parent and (not name or self.names.get(r) == name):
                return
            if new:
                self.ranges = self.ranges + (r,)
            if new_parent:
                self.parents[parent] = (unit_of(r[0], r), parent_name)
            if new or new_parent:
                self.version += 1
            if name:
                self.names[r] = name
            if self.path:
                write_atomic(self.path, json.dumps(
                    [list(x) + [self.names[x]] if x in self.names else list(x)
                     for x in self.ranges]
                    + [list(p) + [n, u] for p, (u, n) in self.parents.items()]))



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


def parent_bounds(data):
    """(start, end) of the parent range of an RDAP answer (the allocation of the ISP), or None
    when the answer is not a sub-assignment or the registry does not say. ARIN gives it as the
    link rel="up" (…/ip/74.12.0.0/14), RIPE and AFRINIC as parentHandle ("90.0.0.0 - 90.71.255.255"
    or a CIDR); APNIC and LACNIC do not give it."""
    if REGISTRY_TYPES.search(str(data.get("type") or "")):
        return None
    for link in data.get("links") or []:
        if isinstance(link, dict) and link.get("rel") == "up":
            path = urllib.parse.unquote(urllib.parse.urlsplit(str(link.get("href") or "")).path)
            if "/ip/" in path:
                try:
                    n = ipaddress.ip_network(path.rsplit("/ip/", 1)[1], strict=False)
                    return n.network_address, n.broadcast_address
                except ValueError:
                    pass
    handle = str(data.get("parentHandle") or "")
    try:
        if " - " in handle:
            a, b = (ipaddress.ip_address(x.strip()) for x in handle.split(" - ", 1))
            return (a, b) if a.version == b.version else None
        if "/" in handle:
            n = ipaddress.ip_network(handle.strip(), strict=False)
            return n.network_address, n.broadcast_address
    except ValueError:
        pass
    return None


def label(data):
    """Organisation as shown by `bans`: name of the allocation and abuse contact (written by
    whoever registered the allocation: control characters are escaped)."""
    return printable(" ".join(x for x in (str(data.get("name") or ""), abuse_email(data)) if x))[:200]


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """rdap.org redirects to the RIR: a redirection to plain HTTP would let anyone on the path
    forge the range."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise RdapError(f"redirection to a non-HTTPS URL refused ({newurl[:100]})", retry=3600)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(HttpsOnlyRedirect)


def fetch_rdap(ip):
    req = urllib.request.Request(RDAP_URL.format(ip),
                                 headers={"Accept": "application/rdap+json",
                                          "User-Agent": "fobots/1.0"})
    try:
        with OPENER.open(req, timeout=15) as r:
            body = r.read(MAX_ANSWER + 1)
        if len(body) > MAX_ANSWER:
            raise RdapError(f"answer larger than {MAX_ANSWER} bytes", retry=3600)
        data = json.loads(body)
        return (ipaddress.ip_address(data["startAddress"]),
                ipaddress.ip_address(data["endAddress"]), label(data), parent_bounds(data),
                printable(abuse_email(data))[:200])
    except urllib.error.HTTPError as e:
        e.close()  # it holds the response and its socket
        if e.code == 429:
            ra = e.headers.get("Retry-After", "")
            pause = min(int(ra), MAX_PAUSE) if ra.isdigit() else 600
            raise RdapError("HTTP 429", retry=pause, pause=pause)
        raise RdapError(f"HTTP {e.code}", retry=1800)
    except (OSError, ValueError, KeyError, TypeError) as e:  # TypeError: data is not a dict
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
            self._wait_budget()
            self.resolve(addr, prefix)

    def resolve(self, addr, prefix):
        try:
            start, end, *rest = self.fetch(str(addr))
            name = rest[0] if rest else ""
            ver = addr.version
            if not int(start) <= int(addr) <= int(end):
                raise RdapError("the range does not contain the IP", retry=3600)
            if int(end) - int(start) + 1 > 2 ** (addr.max_prefixlen - MIN_PREFIX[ver]):
                raise RdapError(f"range too wide ({start}-{end})", retry=3600)
            r = (ver, int(start), int(end))
            parent = self.checked_parent(r, rest[1] if len(rest) > 1 else None)
            self.store.add(r, name, parent, rest[2] if len(rest) > 2 else "")
            log.info("RDAP %s -> %s %s%s", addr, fmt_range(r), name,
                     f" (in {fmt_range(parent)})" if parent else "")
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

    @staticmethod
    def checked_parent(r, bounds):
        """The parent (version, start, end) given with r, if it is usable: same family, strictly
        wider than r and containing it, no wider than MIN_PREFIX (a registry block such as
        0.0.0.0 - 255.255.255.255 is not an ISP); otherwise None."""
        if not bounds:
            return None
        a, b = bounds
        ver = r[0]
        if a.version != ver or b.version != ver:
            return None
        p = (ver, int(a), int(b))
        bits = ipaddress.IPV4LENGTH if ver == 4 else ipaddress.IPV6LENGTH
        if not (p[1] <= r[1] and r[2] <= p[2] and p[2] - p[1] > r[2] - r[1]) \
                or p[2] - p[1] + 1 > 2 ** (bits - MIN_PREFIX[ver]):
            return None
        return p

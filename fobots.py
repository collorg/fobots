#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
#
# This program is free software: you can redistribute it and/or modify it under the terms of
# the GNU General Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version. It is distributed WITHOUT
# ANY WARRANTY; see the file LICENSE or <https://www.gnu.org/licenses/>.
"""fobots: daemon that bans (nftables) overly aggressive IP ranges.

Continuously reads an access log in "combined" format (nginx / Apache / GitLab),
counts requests per IP range and per second, and adds the offending range to the
nftables set as soon as the threshold is exceeded. Bans expire by themselves (nft timeout).

  fobots.py run                      # follows the log given in fobots.conf
  tail -F /var/log/gitlab/nginx/gitlab_access.log | fobots.py run -t 5 -
  fobots.py setup                    # creates nft table, sets and rules (idempotent)
  fobots.py bans                     # active bans with remaining time
  fobots.py welcome add 17.0.0.0/8   # welcome list + removal of the bans concerned
  fobots.py welcome list

Ranges come from RDAP (the successor of whois), queried in the background only for a
/16 prefix (IPv6: /32) that already exceeds --prefix-threshold, with an hourly budget.
The ranges found are kept on disk. The ban state is read from nft: the daemon can be
restarted without losing anything.
Configuration: fobots.conf (see fobots.conf.example), looked up in the current directory
then in /etc/fobots/, or given with -f. The command line overrides it.
Signals: SIGUSR1 prints the most active ranges, SIGTERM/SIGINT stop the daemon.
"""
import argparse
import configparser
import ipaddress
import json
import logging
import os
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict, deque
from datetime import datetime
from functools import lru_cache

log = logging.getLogger("fobots")

LINE_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\]')
# End of a "combined" line: "METHOD /path PROTO" status size "referer" "user-agent"
REQ_RE = re.compile(r'"[A-Z]+ (\S+)[^"]*" \d+ \S+ "[^"]*" "([^"]*)"\s*$')
# First quoted string: the request line (common or combined format)
PATH_RE = re.compile(r'"[A-Z]+ (\S+)')
RDAP_URL = "https://rdap.org/ip/{}"  # redirects to the competent RIR
SETS = {4: "banned4", 6: "banned6"}
# An RDAP answer wider than this is rejected (safeguard against 0.0.0.0/0).
MIN_PREFIX = {4: 8, 6: 16}
CONF_DIR = "/etc/fobots"      # configuration and welcome list (decided by the administrator)
STATE_DIR = "/var/lib/fobots"  # RDAP cache and findings (written by the daemon)
INSTALL_DIR = "/opt/fobots"
UNIT_PATH = "/etc/systemd/system/fobots.service"
SERVICE_USER = "fobots"
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
RECENT_BAN_SECS = 60  # no new attempt for a range just banned
MAX_WATCHED = 5000    # "monitored" IPs kept in memory (opt-in --watch-*)
WATCH_RETENTION = 3600  # seconds (log time) during which they are remembered
WATCH_FILE_KEEP = 30 * 86400  # the findings file is pruned beyond this (at startup)
WATCH_EVENT_IPS = 200         # IPs recorded at most per ban
# ban_scope = observed: the IPs seen (`window`) are grouped into groups of bounded extent;
# the most active are banned, until they cover this share of the allocation's requests.
OBSERVED_COVERAGE = 0.8
OBSERVED_MAX_GROUPS = 4       # beyond: too scattered, fall back to wide blocks
OBSERVED_MAX_IPS = 200_000    # IPs tracked at most (memory)
OBSERVED_PREFIX6 = 48         # maximum width of a group in IPv6 (adjustable in IPv4)
OBSERVED_WIDE6 = 32           # maximum width of a fallback ban in IPv6 (adjustable in IPv4)
SCOPES = ("allocation", "observed")

NFT_SETUP = """\
add table inet fobots
add set inet fobots banned4 { type ipv4_addr; flags interval,timeout; }
add set inet fobots banned6 { type ipv6_addr; flags interval,timeout; }
add chain inet fobots input { type filter hook input priority -10; policy accept; }
add rule inet fobots input tcp dport { 80, 443 } ip saddr @banned4 drop
add rule inet fobots input tcp dport { 80, 443 } ip6 saddr @banned6 drop
"""


# --- utilities ---------------------------------------------------------------

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


def cluster_ips(ips, span):
    """Groups of IPs: [(integer address, requests)] -> [[start, end, requests, number of IPs]].
    Greedy sweep: a group grows as long as its extent stays under `span` addresses;
    it is bounded by its extreme IPs (observed interval), not by a CIDR prefix, so
    two neighbouring IPs on either side of a block boundary stay together."""
    out = []
    for a, n in sorted(ips):
        if out and a - out[-1][0] < span:
            c = out[-1]
            c[1], c[2], c[3] = a, c[2] + n, c[3] + 1
        else:
            out.append([a, a, n, 1])
    return out


def pick_groups(groups, coverage, max_groups):
    """The most active groups that cover `coverage` of the requests, or None if more than
    `max_groups` would be needed."""
    total = sum(g[2] for g in groups)
    picked, got = [], 0
    for g in sorted(groups, key=lambda g: -g[2]):
        picked.append(g)
        got += g[2]
        if got >= coverage * total:
            break
    return picked if len(picked) <= max_groups else None


def wide_blocks(ips, lo, hi, shift, coverage):
    """Fallback when the traffic is scattered: the aligned blocks of 2**shift addresses (cut at
    the bounds [lo, hi] of the allocation) that carry `coverage` of the requests -> [(start, end)]."""
    per = Counter()
    for a, n in ips:
        per[a >> shift] += n
    total, got, out = sum(per.values()), 0, []
    for b, n in per.most_common():
        out.append((max(b << shift, lo), min(((b + 1) << shift) - 1, hi)))
        got += n
        if got >= coverage * total:
            break
    return sorted(out)


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


# --- RDAP ranges -------------------------------------------------------------

class RangeStore:
    """Known ranges (version, start, end), persisted as JSON (atomic write)."""

    def __init__(self, path):
        self.path = path
        self.version = 0  # incremented on each addition (invalidates the memos)
        self._lock = threading.Lock()
        self.ranges = ()
        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    # tolerates the old format (version, start, end, name)
                    self.ranges = tuple({tuple(r[:3]) for r in json.load(f)})
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

    def add(self, r):
        with self._lock:
            if r in self.ranges:
                return
            self.ranges = self.ranges + (r,)
            self.version += 1
            if self.path:
                tmp = self.path + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(self.ranges, f)
                os.replace(tmp, self.path)


class RdapError(Exception):
    def __init__(self, msg, retry=1800, pause=0):
        super().__init__(msg)
        self.retry = retry  # seconds before retrying this prefix
        self.pause = pause  # seconds of global pause (429)


def fetch_rdap(ip):
    req = urllib.request.Request(RDAP_URL.format(ip),
                                 headers={"Accept": "application/rdap+json",
                                          "User-Agent": "fobots/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.load(r)
        return (ipaddress.ip_address(data["startAddress"]),
                ipaddress.ip_address(data["endAddress"]))
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
                start, end = self.fetch(str(addr))
                ver = addr.version
                if not int(start) <= int(addr) <= int(end):
                    raise RdapError("the range does not contain the IP", retry=3600)
                if int(end) - int(start) + 1 > 2 ** (addr.max_prefixlen - MIN_PREFIX[ver]):
                    raise RdapError(f"range too wide ({start}-{end})", retry=3600)
                r = (ver, int(start), int(end))
                self.store.add(r)
                log.info("RDAP %s -> %s", addr, fmt_range(r))
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


# --- nftables ----------------------------------------------------------------

class NftError(Exception):
    pass


def val_nets(val):
    if isinstance(val, str):
        return [ipaddress.ip_network(val, strict=False)]
    if "prefix" in val:
        p = val["prefix"]
        return [ipaddress.ip_network(f"{p['addr']}/{p['len']}", strict=False)]
    if "range" in val:
        a, b = (ipaddress.ip_address(x) for x in val["range"])
        return list(ipaddress.summarize_address_range(a, b))
    return []


def parse_elems(data):
    """[(network, remaining seconds or None)] from the output of `nft -j list set`."""
    out = []
    for item in data.get("nftables", []):
        for e in (item.get("set") or {}).get("elem", []):
            expires = None
            if isinstance(e, dict) and "elem" in e:
                expires, e = e["elem"].get("expires"), e["elem"]["val"]
            out += [(n, expires) for n in val_nets(e)]
    return out


class Nft:
    """Calls to nft; in dry-run mode, prints the scripts and simulates the sets in memory."""

    def __init__(self, binary="nft", dry_run=False):
        self.binary, self.dry_run = binary, dry_run
        self.sim = {4: [], 6: []}

    def _run(self, args, stdin=None):
        try:
            return subprocess.run([self.binary, *args], input=stdin, capture_output=True,
                                  text=True, timeout=15)
        except FileNotFoundError:
            raise NftError(f"command {self.binary!r} not found: install nftables "
                           "(e.g. apt install nftables) or give --nft-bin")
        except (OSError, subprocess.TimeoutExpired) as e:
            raise NftError(f"{self.binary}: {e}")

    def table_exists(self):
        return self._run(["list", "table", "inet", "fobots"]).returncode == 0

    def setup(self):
        r = self._run(["-f", "-"], NFT_SETUP)
        if r.returncode:
            raise NftError(r.stderr.strip())

    def selftest(self):
        """Checks on a throwaway table that nft handles interval sets with timeouts
        and that `nft -j` reads as the daemon expects. -> (ok, expires_visible, message)."""
        t, net = "fobots_selftest", ipaddress.ip_network("10.99.0.0/16")
        self._run(["delete", "table", "inet", t])  # left over from a previous attempt
        try:
            r = self._run(["-f", "-"], f"add table inet {t}\n"
                          f"add set inet {t} s {{ type ipv4_addr; flags interval,timeout; }}\n"
                          f"add element inet {t} s {{ {net} timeout 30s }}\n")
            if r.returncode:
                return False, False, r.stderr.strip() or "creation of the test table refused"
            r = self._run(["-j", "list", "set", "inet", t, "s"])
            if r.returncode:
                return False, False, "nft -j not available: " + (r.stderr.strip() or "failure")
            try:
                found = [(n, e) for n, e in parse_elems(json.loads(r.stdout))]
            except ValueError:
                return False, False, "output of nft -j unreadable"
            if not any(n == net for n, _ in found):
                return False, False, "element added but absent from the JSON output of nft"
            return True, any(e is not None for _, e in found), ""
        finally:
            self._run(["delete", "table", "inet", t])

    def elements(self, ver):
        if self.dry_run:
            return list(self.sim[ver])
        r = self._run(["-j", "list", "set", "inet", "fobots", SETS[ver]])
        if r.returncode:
            raise NftError(r.stderr.strip() or "set not found (run `setup`?)")
        return parse_elems(json.loads(r.stdout))

    def _script(self, script):
        if self.dry_run:
            print(script, end="", flush=True)
            return
        r = self._run(["-f", "-"], script)
        if r.returncode:
            raise NftError(r.stderr.strip())

    def apply(self, ver, deletes, adds, restore=()):
        """Removals then additions [(network, timeout in s)], in two transactions: nft 0.9.x
        refuses a single transaction that removes elements then adds one that overlaps them
        ("interval overlaps with an existing one"). If the addition fails, `restore`
        [(network, timeout)] puts the removed elements back."""
        name = SETS[ver]
        if deletes:
            self._script(f"delete element inet fobots {name} "
                         f"{{ {', '.join(str(n) for n in deletes)} }}\n")
            if self.dry_run:
                gone = set(deletes)
                self.sim[ver] = [(n, e) for n, e in self.sim[ver] if n not in gone]
        if adds:
            try:
                self._add(ver, adds)
            except NftError:
                if restore:
                    try:
                        self._add(ver, restore)
                    except NftError as e:
                        log.error("removed bans not restored: %s", e)
                raise

    def _add(self, ver, adds):
        elems = ", ".join(f"{n} timeout {max(1, int(t))}s" for n, t in adds)
        self._script(f"add element inet fobots {SETS[ver]} {{ {elems} }}\n")
        if self.dry_run:
            self.sim[ver] += [(n, t) for n, t in adds]


# --- welcome list and bans ---------------------------------------------------

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


class Banner:
    def __init__(self, nft, welcome, ban_seconds):
        self.nft, self.welcome, self.ban_seconds = nft, welcome, ban_seconds

    def ban(self, rng, reason, seconds=None):
        """Bans the range (outside the welcome list, without duplicates or nft conflicts)."""
        seconds = seconds or self.ban_seconds
        self.welcome.reload()
        ver = rng[0]
        pieces = []
        for n in range_nets(rng):
            pieces += subtract(n, self.welcome.nets)
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


# --- "monitored" findings (JSON lines file) -----------------------------------

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


# --- server load --------------------------------------------------------------

LOAD_DEFAULTS = {"psi": (20.0, 50.0), "loadavg": (1.0, 2.0)}  # (tense, critical)
LEVELS = ("normal", "tense", "critical")


def read_psi(resource):
    """Pressure `some avg10` (in %): share of the last 10 seconds spent waiting."""
    with open(f"/proc/pressure/{resource}") as f:
        for line in f:
            kind, *fields = line.split()
            if kind == "some":
                return float(dict(x.split("=") for x in fields)["avg10"])
    raise OSError(f"/proc/pressure/{resource}: 'some' line missing")


def read_load(signal):
    if signal == "psi":
        return max(read_psi("cpu"), read_psi("io"))
    return os.getloadavg()[0] / (os.cpu_count() or 1)


class LoadMonitor(threading.Thread):
    """Measures the load every `interval` s and derives a level (0, 1, 2).

    It goes up immediately, and goes down one level only after `recover` continuous
    seconds below the level (hysteresis), to avoid oscillations."""

    def __init__(self, signal, tense, critical, recover, factors, sampler=None,
                 interval=5.0, report=300.0):
        super().__init__(daemon=True, name="load")
        self.signal, self.thresholds = signal, (tense, critical)
        self.recover, self.factors = recover, (1.0, *factors)
        self.sampler = sampler or (lambda: read_load(signal))
        self.interval, self.report = interval, report
        self.level, self.value, self.below_since = 0, 0.0, None

    @property
    def factor(self):
        return self.factors[self.level]

    def describe(self):
        return f"{self.signal}={self.value:.2f}, level {LEVELS[self.level]} (x{self.factor:g})"

    def step(self, now):
        try:
            self.value = v = self.sampler()
        except (OSError, ValueError) as e:
            log.warning("cannot measure the load: %s", e)
            return
        target = sum(v >= t for t in self.thresholds)
        if target >= self.level:
            self.below_since = None
            if target > self.level:
                self.level = target
                log.warning("load: %s", self.describe())
        elif self.below_since is None:
            self.below_since = now
        elif now - self.below_since >= self.recover:
            self.level -= 1
            self.below_since = None
            log.info("load: %s", self.describe())

    def run(self):
        last_report = 0.0
        while True:
            now = time.monotonic()
            self.step(now)
            if now - last_report >= self.report:
                last_report = now
                log.info("load: %s", self.describe())
            time.sleep(self.interval)


class NoLoad:
    """Load ignored: thresholds and ban durations unchanged."""
    level, factor = 0, 1.0

    def describe(self):
        return "load not monitored"


# --- targets (one log per host) -----------------------------------------------

class Site:
    """A target: a log (one per virtual host) and its rules excluding requests from the count.
    A host reachable under several names (CNAME) has a single log, hence a single target."""

    def __init__(self, name, log_path, prefixes=(), regex=None, all=False):
        self.name, self.log, self.all = name, log_path, all
        self.prefixes = tuple(prefixes)
        self.regex = re.compile(regex) if regex else None
        self.lines = self.ignored = 0  # statistics (SIGUSR1)

    @property
    def has_path_rules(self):
        return bool(self.prefixes or self.regex)

    def ignores(self, path):
        if self.prefixes and path.startswith(self.prefixes):
            return True
        return self.regex is not None and self.regex.search(path) is not None

    def describe(self):
        if self.all:
            return "everything is excluded"
        parts = []
        if self.prefixes:
            parts.append("prefixes " + ", ".join(self.prefixes))
        if self.regex:
            parts.append(f"regex {self.regex.pattern!r}")
        return "; ".join(parts) or "no exclusion of its own"


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


# --- detection ---------------------------------------------------------------

class Detector:
    def __init__(self, threshold, prefix_threshold, sustain, window, store, banner, rdap,
                 load=None, min_threshold=1.0, min_ban_seconds=60, watch=None,
                 watch_file=None, ignore_path=None, sites=(), scope="allocation",
                 observed_prefix=20, escalate=4, wide_prefix=16):
        self.base_threshold, self.base_prefix_threshold = threshold, prefix_threshold
        self.load, self.min_threshold, self.min_ban = load or NoLoad(), min_threshold, min_ban_seconds
        self.sustain, self.window = sustain, window
        self.store, self.banner, self.rdap = store, banner, rdap
        self.counts = defaultdict(dict)  # key -> {second: n}
        self.over = defaultdict(set)     # range -> seconds above the threshold
        self.hits = Counter()
        self.recent_ban = {}
        self.memo, self.memo_version = {}, store.version
        self.latest = self.last_purge = 0
        self.skipped = self.ignored = 0
        self.ignore_path = ignore_path  # global regex: requests not counted (static pages)
        self.sites = tuple(sites)       # targets (SIGUSR1 statistics)
        self.observed = scope == "observed"
        self.span4 = 2 ** (32 - observed_prefix)
        self.span6 = 2 ** (128 - OBSERVED_PREFIX6)
        self.wide_shift4 = 32 - wide_prefix if wide_prefix else None  # None: whole allocation
        self.wide_shift6 = 128 - OBSERVED_WIDE6 if wide_prefix else None
        self.escalate = escalate        # recent partial bans of an allocation before banning it
        self.ips = {}      # ip -> [requests, start, last second, range] (observed mode)
        self.partial = {}  # range -> seconds of the partial bans
        self.watch = watch  # (agent regex or None, path regex or None); None = disabled
        self.watched = {}   # ip -> [requests, last second seen, example path]
        self.watch_file = watch_file  # findings written here (reread by `fobots.py watched`)

    def watch_match(self, m):
        """Path of the request (m: REQ_RE) if it matches the monitored patterns, else None.
        All the patterns given must match. The lines are counted like the others:
        we only keep a trace."""
        agent_re, path_re = self.watch
        if (agent_re is None or agent_re.search(m.group(2))) and \
                (path_re is None or path_re.search(m.group(1))):
            return m.group(1)
        return None

    def record_watched(self, ip, sec, path):
        e = self.watched.get(ip)
        if e:
            e[0] += 1
            e[1] = sec
        elif len(self.watched) < MAX_WATCHED:
            self.watched[ip] = [1, sec, path[:80]]

    def report_watched(self, key, seconds):
        """Logs the monitored IPs contained in the range that has just been banned."""
        ver, start, end = key
        hit = []
        for ip, (n, _, path) in self.watched.items():
            a = ipaddress.ip_address(ip)
            if a.version == ver and start <= int(a) <= end:
                hit.append((n, ip, path))
        if not hit:
            return
        hit.sort(reverse=True)
        if self.watch_file:
            append_event(self.watch_file, {
                "t": int(time.time()), "range": fmt_range(key), "seconds": seconds,
                "ips": [[ip, n, path] for n, ip, path in hit[:WATCH_EVENT_IPS]]})
        top = hit[:10]
        log.warning("WATCH %s banned: %d monitored IP(s), %d request(s): %s%s; "
                    "to protect them: fobots.py welcome add %s",
                    fmt_range(key), len(hit), sum(n for n, _, _ in hit),
                    ", ".join(f"{ip} ({n} req, {path})" for n, ip, path in top),
                    f" (+{len(hit) - len(top)} others)" if len(hit) > len(top) else "",
                    " ".join(str(ipaddress.ip_network(ip)) for _, ip, _ in top))

    @property
    def threshold(self):
        """Effective threshold: lowered when the load rises, without going below the floor."""
        return self._scaled(self.base_threshold, self.min_threshold)

    @property
    def prefix_threshold(self):
        return self._scaled(self.base_prefix_threshold, self.min_threshold)

    def _scaled(self, value, floor):
        return min(value, max(floor, value * self.load.factor))

    def ban_seconds(self):
        """Effective duration: shortened when the load rises (ranges are re-judged sooner)."""
        return int(self._scaled(self.banner.ban_seconds, self.min_ban))

    def feed_line(self, line, site=None):
        m = LINE_RE.match(line)
        if not m:
            self.skipped += 1
            return
        if site is not None:
            site.lines += 1
            if site.all:  # target entirely excluded from the count
                site.ignored += 1
                self.ignored += 1
                return
        if self.ignore_path is not None or (site is not None and site.has_path_rules):
            pm = PATH_RE.search(line)  # unreadable: the line is counted normally
            if pm:
                path = pm.group(1)
                if (self.ignore_path is not None and self.ignore_path.search(path)) or \
                        (site is not None and site.ignores(path)):
                    self.ignored += 1
                    if site is not None:
                        site.ignored += 1
                    return
        tag = None
        if self.watch:
            rm = REQ_RE.search(line)  # also needs the agent (combined format)
            if rm:
                tag = self.watch_match(rm)
        try:
            sec = parse_ts(m.group(2))
        except ValueError:
            self.skipped += 1
            return
        self.feed(m.group(1), sec, tag)

    def feed(self, ip, sec, tag=None):
        key = self.memo.get(ip)
        if self.memo_version != self.store.version or len(self.memo) > 200_000:
            self.memo.clear()
            self.memo_version, key = self.store.version, None
        addr = None
        if key is None:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                self.skipped += 1
                return
            if not addr.is_global:
                return
            key = self.store.find(addr) or prefix_of(addr)  # known range, otherwise prefix
            self.memo[ip] = key
        if sec > self.latest:
            self.latest = sec
            if sec - self.last_purge >= 10:
                self.purge()
        if tag:
            self.record_watched(ip, sec, tag)
        c = self.counts[key]
        n = c[sec] = c.get(sec, 0) + 1
        self.hits[key] += 1
        if isinstance(key, tuple):
            if self.observed:
                self.note_ip(ip, sec, key)
            if n > self.threshold:
                over = self.over[key]
                over.add(sec)
                over.intersection_update(range(sec - self.window + 1, sec + 1))
                if len(over) >= self.sustain:
                    self.trigger(key, sec, n, ip)
        elif n > self.prefix_threshold:
            self.rdap.request(addr or ipaddress.ip_address(ip), key)

    def note_ip(self, ip, sec, key):
        e = self.ips.get(ip)
        if e is None:
            if len(self.ips) < OBSERVED_MAX_IPS:
                self.ips[ip] = [1, sec, sec, key]
        elif sec - e[1] > self.window:  # coarse sliding window: start again from zero
            e[:] = [1, sec, sec, key]
        else:
            e[0] += 1
            e[2], e[3] = sec, key

    def targets(self, key, sec):
        """(ranges to ban, detail for the journal) for an allocation that has triggered."""
        if not self.observed:
            return [key], ""
        ver = key[0]
        ips = [(int(ipaddress.ip_address(s)), e[0]) for s, e in self.ips.items()
               if e[3] == key and e[2] >= sec - self.window]
        recent = [t for t in self.partial.get(key, ()) if sec - t < self.banner.ban_seconds]
        groups = cluster_ips(ips, self.span4 if ver == 4 else self.span6)
        picked = None
        why = f"escalation: {len(recent)} recent partial bans"
        if len(recent) < self.escalate and groups:
            picked = pick_groups(groups, OBSERVED_COVERAGE, OBSERVED_MAX_GROUPS)
            why = f"{len(groups)} group(s) of IPs, too scattered"
        if picked is None:  # fallback: wide blocks (or the whole allocation), never narrower
            self.partial.pop(key, None)
            shift = self.wide_shift4 if ver == 4 else self.wide_shift6
            if shift is None or not ips or (key[2] - key[1] + 1) <= (1 << shift):
                return [key], f", {why}: whole allocation"
            blocks = wide_blocks(ips, key[1], key[2], shift, OBSERVED_COVERAGE)
            return ([(ver, a, b) for a, b in blocks],
                    f", {why}: {len(blocks)} block(s) of /{(32 if ver == 4 else 128) - shift} "
                    f"instead of the allocation")
        self.partial[key] = recent + [sec]
        covered = sum(g[2] for g in picked) / sum(g[2] for g in groups)
        return ([(ver, g[0], g[1]) for g in picked],
                f", {len(ips)} IP(s) in {len(groups)} group(s), {len(picked)} banned "
                f"({covered:.0%} of the requests)")

    def trigger(self, key, sec, n, ip):
        if sec - self.recent_ban.get(key, -10**12) < RECENT_BAN_SECS:
            return
        self.recent_ban[key] = sec
        thr = self.threshold
        reason = f"{n} req/s > {thr:g}, seen with {ip}, {self.hits[key]} requests in total"
        if self.load.level:
            reason += f", load level {LEVELS[self.load.level]}"
        targets, detail = self.targets(key, sec)
        reason += detail
        try:
            seconds = self.ban_seconds()
            for t in targets:
                if self.banner.ban(t, reason, seconds) and self.watched:
                    self.report_watched(t, seconds)
        except NftError as e:
            log.error("cannot ban %s: %s", fmt_range(key), e)

    def purge(self):
        self.last_purge = cutoff = self.latest
        cutoff -= self.window
        for key in list(self.counts):
            d = self.counts[key]
            for s in [s for s in d if s < cutoff]:
                del d[s]
            if not d:
                del self.counts[key]
        for key in list(self.over):
            self.over[key] = {s for s in self.over[key] if s >= cutoff}
            if not self.over[key]:
                del self.over[key]
        self.recent_ban = {k: s for k, s in self.recent_ban.items() if s >= cutoff}
        if self.observed:
            self.ips = {ip: e for ip, e in self.ips.items() if e[2] >= cutoff}
            keep = self.latest - self.banner.ban_seconds
            self.partial = {k: v for k, v in
                            ((k, [t for t in v if t >= keep]) for k, v in self.partial.items()) if v}
        old = self.latest - WATCH_RETENTION
        for ip in [ip for ip, e in self.watched.items() if e[1] < old]:
            del self.watched[ip]

    def dump(self, top=30):
        log.info("--- %d ranges tracked, %d unreadable lines, %d excluded lines, "
                 "%d monitored IPs, %s ---", len(self.hits), self.skipped, self.ignored,
                 len(self.watched), self.load.describe())
        for site in self.sites:
            log.info("site %s: %d lines read, %d excluded", site.name, site.lines, site.ignored)
        for key, n in self.hits.most_common(top):
            label = fmt_range(key) if isinstance(key, tuple) else f"(unresolved) {key}"
            log.info("%10d  %s", n, label)


# --- reading the log ---------------------------------------------------------

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


# --- commands ----------------------------------------------------------------

def paths(args):
    """(RDAP cache, welcome list). The welcome list is next to the configuration used,
    otherwise in CONF_DIR: never relative to the current directory."""
    wl_base = os.path.dirname(os.path.abspath(args.config)) if args.config else CONF_DIR
    return (args.cache or os.path.join(args.dir, "ip_ranges.json"),
            args.welcome or os.path.join(wl_base, "welcome.txt"))


def ensure_dir(path):
    """Creates the directory (0750) if missing; stops with a clear message otherwise."""
    try:
        os.makedirs(path, mode=0o750, exist_ok=True)
    except OSError as e:
        sys.exit(f"cannot create {path}: {e} (create the directory with the right permissions, "
                 "or give --dir)")


def watch_file_path(args):
    return args.watch_file or os.path.join(args.dir, "watched.jsonl")


def cmd_run(args):
    cache, wl_path = paths(args)
    ensure_dir(os.path.dirname(os.path.abspath(cache)))
    ensure_dir(os.path.dirname(os.path.abspath(watch_file_path(args))))
    store, wl = RangeStore(cache), Welcome(wl_path)
    nft = Nft(args.nft_bin, args.dry_run)
    try:
        for ver in (4, 6):
            log.info("IPv%d: %d range(s) already banned", ver, len(nft.elements(ver)))
    except NftError as e:
        log.error("nft: %s", e)
        return 1
    rdap = Rdap(store, args.delay, args.rdap_per_hour)
    rdap.start()
    load = None
    if args.load_signal not in ("none", "psi", "loadavg"):
        log.error("invalid load_signal: %r (none, psi or loadavg)", args.load_signal)
        return 1
    if args.load_signal != "none":
        signal_name = args.load_signal
        try:
            read_load(signal_name)
        except (OSError, ValueError) as e:
            if signal_name != "psi":
                log.error("load: %s", e)
                return 1
            log.warning("PSI unavailable (%s), falling back to loadavg", e)
            signal_name = "loadavg"
        d_tense, d_crit = LOAD_DEFAULTS[signal_name]
        load = LoadMonitor(signal_name,
                           d_tense if args.load_tense is None else args.load_tense,
                           d_crit if args.load_critical is None else args.load_critical,
                           args.load_recover, (args.tense_factor, args.critical_factor))
        load.start()
        log.info("load monitoring: %s, levels %s, recovery after %d s",
                 signal_name, load.thresholds, args.load_recover)
    watch = None
    if args.watch_agent or args.watch_path:
        try:
            watch = (re.compile(args.watch_agent) if args.watch_agent else None,
                     re.compile(args.watch_path) if args.watch_path else None)
        except re.error as e:
            log.error("invalid regular expression: %s", e)
            return 1
        log.info("request monitoring: agent=%r path=%r (counted normally, "
                 "logged if their range is banned)", args.watch_agent, args.watch_path)
    ignore_path = None
    if args.ignore_path:
        try:
            ignore_path = re.compile(args.ignore_path)
        except re.error as e:
            log.error("invalid regular expression for ignore_path: %s", e)
            return 1
        log.info("requests excluded from the count (path): %r", args.ignore_path)
    sites = [Site(d["name"], d["log"], d["prefixes"], d["regex"], d["all"])
             for d in (getattr(args, "sites", None) or [])]
    if args.log:  # single log of [fobots] or --log: a target without rules of its own
        if any(x.log == args.log for x in sites):
            log.error("the log %s is both in [fobots] and in a [site:…] section", args.log)
            return 1
        sites.insert(0, Site("default", args.log))
    if args.files:
        sites = []  # files given as arguments: read once, not followed
    for x in sites:
        log.info("target %s: following %s (%s)", x.name, x.log, x.describe())
    if args.ban_scope not in SCOPES:
        log.error("invalid ban_scope: %r (%s)", args.ban_scope, " or ".join(SCOPES))
        return 1
    if not 8 <= args.observed_prefix <= 32:
        log.error("observed_prefix must be between 8 and 32 (IPv4)")
        return 1
    if args.observed_max_prefix and not 8 <= args.observed_max_prefix <= args.observed_prefix:
        log.error("observed_max_prefix must be 0 (whole allocation) or between 8 and "
                  "observed_prefix (%d)", args.observed_prefix)
        return 1
    if not sites and not args.files and not stdin_is_feed():
        log.error("no log to follow: define `log =` in [fobots] or in a [site:NAME] section "
                  "(configuration used: %s), or pass --log FILE; "
                  "to read stdin explicitly: `run -`", args.config or "none")
        return 1
    watch_file = watch_file_path(args) if watch else None
    if watch_file:
        trim_events(watch_file)
    det = Detector(args.threshold, args.prefix_threshold or args.threshold, args.sustain,
                   args.window, store, Banner(nft, wl, args.ban_seconds), rdap,
                   load, args.min_threshold, args.min_ban_seconds, watch, watch_file,
                   ignore_path, sites, args.ban_scope, args.observed_prefix, args.observed_escalate,
                   args.observed_max_prefix)
    if det.observed:
        log.info("ban_scope observed: groups of IPs of at most /%d (IPv6 /%d), fallback to blocks "
                 "of %s if scattered or after %d partial bans", args.observed_prefix,
                 OBSERVED_PREFIX6,
                 f"/{args.observed_max_prefix} (IPv6 /{OBSERVED_WIDE6})"
                 if args.observed_max_prefix else "the whole allocation", args.observed_escalate)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGUSR1, lambda *_: det.dump())
    if args.config:
        log.info("configuration: %s", args.config)
    log.info("daemon ready: threshold %s req/s, ban %d s, %d range(s) cached in %s",
             args.threshold, args.ban_seconds, len(store.ranges), os.path.abspath(cache))
    try:
        if sites:
            run_sites(det, sites, args.from_start)
        else:  # files (read once) or stdin
            for line in log_lines(args):
                det.feed_line(line)
    except KeyboardInterrupt:
        pass
    except OSError as e:  # stdin or file unreadable
        log.error("cannot read: %s", e)
        return 1
    log.info("stopping")
    return 0


def cmd_setup(args):
    nft = Nft(args.nft_bin, args.dry_run)
    if args.dry_run:
        print(NFT_SETUP, end="")
    elif nft.table_exists():
        print("table inet fobots already in place")
    else:
        nft.setup()
        print("table inet fobots created")
    return 0


def cmd_bans(args):
    nft = Nft(args.nft_bin, args.dry_run)
    for ver in (4, 6):
        for n, exp in sorted(nft.elements(ver), key=lambda e: e[0].network_address):
            print(f"{str(n):<24} {'' if exp is None else f'{exp} s left'}")
    return 0


def cmd_watched(args):
    """Monitored IPs caught in a ban (history + current state), to spot false positives."""
    path = watch_file_path(args)
    events = read_events(path, time.time() - args.since)
    if not events:
        print(f"no finding in {path} for this period (watch_agent / watch_path "
              "enabled in the daemon's configuration?)")
        return 0
    active, known = [], False
    if not args.dry_run:
        try:
            nft = Nft(args.nft_bin)
            active = [(n, e) for ver in (4, 6) for n, e in nft.elements(ver)]
            known = True
        except NftError as e:
            print(f"ban state unavailable ({e}): STATE column unknown", file=sys.stderr)
    agg = {}
    for ev in events:
        for ip, n, rpath in ev["ips"]:
            a = agg.setdefault(ip, {"bans": 0, "req": 0, "t": 0, "range": "", "path": ""})
            a["bans"] += 1
            a["req"] += n
            if ev["t"] >= a["t"]:
                a.update(t=ev["t"], range=ev["range"], path=rpath)
    rows = []
    for ip, a in agg.items():
        state = "?"
        if known:
            addr = ipaddress.ip_address(ip)
            left = [e for n, e in active if n.version == addr.version and addr in n]
            state = f"active ({max(e or 0 for e in left)} s)" if left else "expired"
        a["state"] = state
        rows.append((ip, a))
    if args.active:
        rows = [r for r in rows if r[1]["state"].startswith("active")]
    rows.sort(key=lambda r: (not r[1]["state"].startswith("active"), -r[1]["bans"], -r[1]["req"]))
    if not rows:
        print("no monitored IP in an active ban")
        return 0
    cmd = "fobots.py welcome add " + " ".join(str(ipaddress.ip_network(ip)) for ip, _ in rows)
    if args.config:
        cmd += f" -f {args.config}"
    if args.cmd:
        print(cmd)
        return 0
    print(f"{'IP':<40} {'BANS':>4} {'REQ':>6}  {'LAST BAN':<16} {'RANGE':<20} {'STATE':<14} ROUTE")
    for ip, a in rows:
        when = datetime.fromtimestamp(a["t"]).strftime("%Y-%m-%d %H:%M")
        print(f"{ip:<40} {a['bans']:>4} {a['req']:>6}  {when:<16} {a['range']:<20} "
              f"{a['state']:<14} {a['path']}")
    print(f"\n{len(rows)} IP(s) over {args.since / 86400:g} d. To protect them all:\n  {cmd}")
    return 0


class Installer:
    """Installation on Debian/Ubuntu: nftables, user, directories, program, configuration, unit."""

    def __init__(self, args):
        self.args = args
        self.dry = args.dry_run
        self.dest = args.destdir  # test prefix: writes the files without touching the system
        self.system = not self.dest and not self.dry

    def path(self, p):
        return os.path.join(self.dest, p.lstrip("/")) if self.dest else p

    def say(self, status, msg):
        if self.dry and status == "ok":  # nothing is done: do not claim otherwise
            status, msg = "..", f"(simulated) {msg}"
        print(f"[{status}] {msg}")

    def said_done(self, msg):
        """System action (apt, useradd…): "ok" only if it really took place."""
        self.say("ok" if self.system or self.dry else "..",
                 msg if self.system or self.dry else f"{msg} (not done: --destdir)")

    def confirm(self, question):
        if self.args.yes or self.dry:
            return True
        if sys.stdin.isatty():
            return input(f"{question} [y/N] ").strip().lower() in ("y", "yes", "o", "oui")
        sys.exit(f"{question}: cannot answer outside a terminal, run again with --yes")

    def run(self, cmd, check=True):
        """System command; with --dry-run or --destdir, it is only printed."""
        if not self.system:
            note = "" if self.dry else "   (ignored: --destdir)"
            print(f"  $ {' '.join(cmd)}{note}")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        r = subprocess.run(cmd, capture_output=True, text=True)
        if check and r.returncode:
            sys.exit(f"{' '.join(cmd)} failed:\n{r.stderr.strip()}")
        return r

    def ensure_dir(self, path, mode, owner=None):
        if self.dry:
            print(f"  create {path} (mode {mode:o})")
            return
        real = self.path(path)
        os.makedirs(real, exist_ok=True)
        os.chmod(real, mode)
        if owner and self.system:
            shutil.chown(real, *owner)

    def write(self, path, content, mode):
        if self.dry:
            print(f"  write {path} (mode {mode:o})")
            return
        real = self.path(path)
        os.makedirs(os.path.dirname(real), exist_ok=True)
        tmp = real + ".tmp"
        with open(tmp, "w") as f:
            f.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, real)

    @staticmethod
    def template(name):
        p = os.path.join(SRC_DIR, name)
        if not os.path.exists(p):
            sys.exit(f"{name} not found next to {os.path.abspath(__file__)}: "
                     "run the installation from a clone of the repository")
        with open(p) as f:
            return f.read()

    def read(self, path):
        try:
            with open(self.path(path)) as f:
                return f.read()
        except OSError:
            return None

    def check_python(self):
        v = sys.version_info
        if v < (3, 7):
            sys.exit(f"Python 3.7 or later required (found {v.major}.{v.minor})")
        self.say("ok", f"Python {v.major}.{v.minor}.{v.micro}")

    def ensure_nft(self):
        binary = self.args.nft_bin
        found = shutil.which(binary)
        if found:
            self.say("ok", f"nft: {found}")
            return
        if not shutil.which("apt-get"):
            self.say("!!", "nft not found and apt-get absent: install the nftables package by hand")
            if self.system:
                sys.exit(1)
            return
        if not self.confirm("nft is missing. Install the nftables package with apt-get?"):
            sys.exit("nftables is required")
        self.run(["apt-get", "install", "-y", "nftables"])
        self.said_done("nftables installed")

    def selftest(self):
        if not self.system:
            self.say("..", "nft test (interval sets with timeouts): done at the real installation")
            return
        ok, expires, msg = Nft(self.args.nft_bin).selftest()
        if not ok:
            sys.exit(f"[!!] nft is not suitable: {msg}\n"
                     "     (kernel without nf_tables, nftables package too old, or permissions?)")
        self.say("ok", "nft: interval sets with timeouts, readable JSON output")
        if not expires:
            self.say("..", "this version of nft does not show the remaining time of bans "
                     "(`bans` and `watched` therefore do not show it)")

    def ensure_user(self):
        import pwd
        try:
            pwd.getpwnam(SERVICE_USER)
            self.say("ok", f"user {SERVICE_USER} exists")
        except KeyError:
            self.run(["useradd", "--system", "--user-group", "--no-create-home",
                      "--shell", "/usr/sbin/nologin", SERVICE_USER])
            self.said_done(f"user {SERVICE_USER} created")

    def log_paths(self):
        if self.args.log:
            return [self.args.log]
        text = self.read(os.path.join(CONF_DIR, "fobots.conf")) or self.template("fobots.conf.example")
        return re.findall(r"(?m)^\s*log\s*=\s*(\S+)", text)

    @staticmethod
    def group_for(log_file):
        """Group giving access to this log if it is not public (and not root), otherwise adm."""
        import grp
        try:
            st = os.stat(log_file)
            name = grp.getgrgid(st.st_gid).gr_name
            if not st.st_mode & 0o004 and name != "root":
                return name
        except (OSError, KeyError, TypeError):
            pass
        return "adm"

    def log_groups(self):
        """Access groups for all the logs (--log-group imposes its own)."""
        if self.args.log_group:
            return [self.args.log_group]
        groups = []
        for log_file in self.log_paths():
            g = self.group_for(log_file)
            if g not in groups:
                groups.append(g)
        return groups or ["adm"]

    def install_files(self):
        self.ensure_dir(INSTALL_DIR, 0o755)
        dst = os.path.join(INSTALL_DIR, "fobots.py")
        src = os.path.abspath(__file__)
        if os.path.abspath(self.path(dst)) == src:
            self.say("ok", f"program already in place: {dst}")
        else:
            with open(src) as f:
                self.write(dst, f.read(), 0o755)
            self.say("ok", f"program: {dst}")

        self.ensure_dir(CONF_DIR, 0o755)
        conf = os.path.join(CONF_DIR, "fobots.conf")
        if self.read(conf) is not None:
            self.say("ok", f"{conf} exists: kept as is")
            if self.args.log:
                self.say("!!", f"--log ignored: edit the `log =` line of {conf} by hand")
        else:
            text = self.template("fobots.conf.example")
            if self.args.log:
                text = re.sub(r"(?m)^log\s*=.*$", lambda m: f"log = {self.args.log}", text)
            self.write(conf, text, 0o644)
            self.say("ok", f"configuration: {conf}")
        wl = os.path.join(CONF_DIR, "welcome.txt")
        if self.read(wl) is None:
            self.write(wl, "# Ranges never to ban, one CIDR per line.\n"
                       "# Add with: fobots.py welcome add CIDR (also removes the bans concerned)\n", 0o644)
            self.say("ok", f"welcome list: {wl}")

        self.ensure_dir(STATE_DIR, 0o750, (SERVICE_USER, SERVICE_USER))
        self.say("ok", f"state directory: {STATE_DIR}")

        unit = re.sub(r"(?m)^SupplementaryGroups=.*$", f"SupplementaryGroups={' '.join(self.log_groups())}",
                      self.template("fobots.service.example"))
        if self.read(UNIT_PATH) == unit:
            self.say("ok", f"systemd unit up to date: {UNIT_PATH}")
        else:
            self.write(UNIT_PATH, unit, 0o644)
            self.say("ok", f"systemd unit: {UNIT_PATH} (log access groups: {' '.join(self.log_groups())})")
            self.run(["systemctl", "daemon-reload"])

    def check_log_access(self):
        logs = self.log_paths()
        if not logs:
            self.say("..", "no log configured: the daemon will read stdin")
            return
        for log_file in logs:
            if not self.system:
                self.say("..", f"access of {SERVICE_USER} to {log_file}: checked at the real installation")
                continue
            if not os.path.exists(log_file):
                self.say("!!", f"{log_file} does not exist yet (the daemon will wait for it): check the path")
                continue
            group = self.args.log_group or self.group_for(log_file)
            r = self.run(["runuser", "-u", SERVICE_USER, "-g", group, "--",
                          "test", "-r", log_file], check=False)
            if r.returncode == 0:
                self.say("ok", f"{SERVICE_USER} can read {log_file}")
            else:
                self.say("!!", f"{SERVICE_USER} cannot read {log_file}: grant access, e.g. "
                         f"`setfacl -m u:{SERVICE_USER}:r {log_file}` (and x on the parent directories), "
                         "or --log-group")

    def run_all(self):
        if self.system and os.geteuid() != 0:
            sys.exit("the installation needs root rights: sudo ./fobots.py install")
        if self.dry:
            print("--dry-run: nothing is modified, here is what would be done\n")
        self.check_python()
        self.ensure_nft()
        self.selftest()
        self.ensure_user()
        self.install_files()
        self.check_log_access()
        if self.args.start:
            self.run(["systemctl", "enable", "--now", "fobots"])
            self.said_done("service enabled and started")
        elif self.args.enable:
            self.run(["systemctl", "enable", "fobots"])
            self.said_done("service enabled at boot (not started)")
        print(f"""
Next steps:
  1. check / adapt {CONF_DIR}/fobots.conf (log, thresholds)
  2. add your networks to {CONF_DIR}/welcome.txt (administrators, CI, monitoring)
  3. trial without banning anything: {INSTALL_DIR}/fobots.py run --dry-run
  4. start: systemctl enable --now fobots      follow: journalctl -u fobots -f""")


def cmd_install(args):
    Installer(args).run_all()
    return 0


def cmd_welcome(args):
    _, wl_path = paths(args)
    if args.action == "list":
        for n in Welcome(wl_path).nets:
            print(n)
        return 0
    nets = []
    for x in args.nets:
        try:
            nets.append(ipaddress.ip_network(x, strict=False))
        except ValueError:
            print(f"invalid range: {x}", file=sys.stderr)
            return 2
    try:
        os.makedirs(os.path.dirname(os.path.abspath(wl_path)), exist_ok=True)
        Welcome.append(wl_path, nets)  # first: the daemon stops banning it
    except OSError as e:
        print(f"cannot write {wl_path}: {e} (permissions? run with sudo)",
              file=sys.stderr)
        return 1
    nft = Nft(args.nft_bin, args.dry_run)
    for net in nets:
        try:
            deletes, adds = welcome_add(nft, net, args.ban_seconds)
        except NftError as e:
            print(f"{net} added to {wl_path}, but nft failed: {e}", file=sys.stderr)
            return 1
        print(f"{net}: welcome list; {len(deletes)} ban(s) removed"
              + (f", {len(adds)} piece(s) of the rest kept" if adds else ""))
    return 0


CONF_KEYS = {  # file key -> (argparse destination, conversion)
    "dir": ("dir", str), "cache": ("cache", str), "welcome": ("welcome", str),
    "log": ("log", str), "nft_bin": ("nft_bin", str),
    "ban_time": ("ban_seconds", parse_duration),
    "threshold": ("threshold", float), "prefix_threshold": ("prefix_threshold", float),
    "sustain": ("sustain", int), "window": ("window", int),
    "rdap_per_hour": ("rdap_per_hour", int), "delay": ("delay", float),
    "load_signal": ("load_signal", str), "load_tense": ("load_tense", float),
    "load_critical": ("load_critical", float), "load_recover": ("load_recover", parse_duration),
    "tense_factor": ("tense_factor", float), "critical_factor": ("critical_factor", float),
    "min_threshold": ("min_threshold", float), "min_ban_time": ("min_ban_seconds", parse_duration),
    "ignore_path": ("ignore_path", str),
    "ban_scope": ("ban_scope", str), "observed_prefix": ("observed_prefix", int),
    "observed_escalate": ("observed_escalate", int),
    "observed_max_prefix": ("observed_max_prefix", int),
    "watch_agent": ("watch_agent", str), "watch_path": ("watch_path", str),
    "watch_file": ("watch_file", str),
    "from_start": ("from_start", lambda v: v.lower() in ("1", "true", "yes", "oui", "on")),
}
PATH_KEYS = {"dir", "cache", "welcome", "log", "watch_file"}
# /etc first: the result does not depend on the current directory (./fobots.conf is for development)
CONF_SEARCH = (os.path.join(CONF_DIR, "fobots.conf"), "fobots.conf")


SITE_KEYS = ("log", "ignore_prefix", "ignore_path", "ignore_all")
TRUE_VALUES = ("1", "true", "yes", "oui", "on")


def load_config(path):
    """Reads [fobots] and the [site:NAME] sections; relative paths are relative to the file."""
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#", ";"))
    try:
        with open(path) as f:
            cp.read_file(f)
    except (OSError, configparser.Error) as e:
        sys.exit(f"configuration {path} unreadable: {e}")
    if not cp.has_section("fobots"):
        sys.exit(f"{path}: section [fobots] missing")
    base = os.path.dirname(os.path.abspath(path))

    def fix_path(v):
        v = os.path.expanduser(v.strip())
        return v if os.path.isabs(v) else os.path.join(base, v)

    out = {}
    for key, val in cp["fobots"].items():
        if key not in CONF_KEYS:
            sys.exit(f"{path}: unknown option {key!r} (known: {', '.join(CONF_KEYS)})")
        if not val.strip():
            continue
        dest, conv = CONF_KEYS[key]
        if key in PATH_KEYS:
            val = fix_path(val)
        try:
            out[dest] = conv(val.strip())
        except (ValueError, argparse.ArgumentTypeError) as e:
            sys.exit(f"{path}: invalid value for {key} ({val!r}): {e}")

    sites, seen = [], {}
    for section in cp.sections():
        if section == "fobots":
            continue
        name = section[5:].strip() if section.startswith("site:") else ""
        if not name:
            sys.exit(f"{path}: unknown section [{section}] (expected: [fobots] or [site:NAME])")
        opts = cp[section]
        for key in opts:
            if key not in SITE_KEYS:
                sys.exit(f"{path}: [{section}] unknown option {key!r} "
                         f"(known: {', '.join(SITE_KEYS)})")
        if not opts.get("log", "").strip():
            sys.exit(f"{path}: [{section}]: `log` is required")
        log_file = fix_path(opts["log"])
        if log_file in seen:
            sys.exit(f"{path}: [{section}] and [site:{seen[log_file]}] follow the same log {log_file}")
        seen[log_file] = name
        prefixes = [x for x in re.split(r"[,\s]+", opts.get("ignore_prefix", "").strip()) if x]
        for x in prefixes:
            if not x.startswith("/"):
                sys.exit(f"{path}: [{section}] ignore_prefix {x!r} must start with /")
        regex = opts.get("ignore_path", "").strip() or None
        if regex:
            try:
                re.compile(regex)
            except re.error as e:
                sys.exit(f"{path}: [{section}] invalid ignore_path: {e}")
        sites.append({"name": name, "log": log_file, "prefixes": prefixes, "regex": regex,
                      "all": opts.get("ignore_all", "").strip().lower() in TRUE_VALUES})
    if out.get("log") in seen:
        sys.exit(f"{path}: the log {out['log']} is both in [fobots] and in [site:{seen[out['log']]}]")
    if sites:
        out["sites"] = sites
    return out


def main(argv=None):
    pre = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    pre.add_argument("-f", "--config")
    conf_path = pre.parse_known_args(argv)[0].config
    if conf_path is None:
        conf_path = next((c for c in CONF_SEARCH if os.path.exists(c)), None)
    elif not os.path.exists(conf_path):
        sys.exit(f"configuration not found: {conf_path}")
    conf = load_config(conf_path) if conf_path else {}

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-f", "--config", help="configuration file "
                        "(default: /etc/fobots/fobots.conf, then ./fobots.conf)")
    common.add_argument("--dir", default=STATE_DIR,
                        help=f"state directory: ip_ranges.json, watched.jsonl (default: {STATE_DIR})")
    common.add_argument("-c", "--cache", help="file of RDAP ranges (default: DIR/ip_ranges.json)")
    common.add_argument("-w", "--welcome", help="welcome list (default: welcome.txt next to the configuration, "
                        f"otherwise {CONF_DIR}/welcome.txt)")
    common.add_argument("--watch-file",
                        help="file of monitoring findings (default: DIR/watched.jsonl)")
    common.add_argument("--ban-time", dest="ban_seconds", type=parse_duration, default=3600,
                        help="duration of a ban: 30m, 1h, 1d… (default: 1h)")
    common.add_argument("--nft-bin", default="nft", help="nft binary (default: nft)")
    common.add_argument("--dry-run", action="store_true",
                        help="does not call nft: prints the commands (simulated sets)")
    common.add_argument("-v", "--verbose", action="store_true")

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", parents=[common], help="daemon: reads the log and bans")
    r.add_argument("files", nargs="*",
                   help="logs read once (- = stdin); otherwise --log is followed, otherwise stdin")
    r.add_argument("-l", "--log", help="log to follow continuously (rotation handled, like tail -F)")
    r.add_argument("--from-start", action="store_true",
                   help="with --log: first reads the existing content (default: end of the file)")
    r.add_argument("-t", "--threshold", type=float, default=5.0,
                   help="req/s of a range above which it is banned (default: 5)")
    r.add_argument("-p", "--prefix-threshold", type=float,
                   help="req/s of an unresolved /16 prefix that trigger an RDAP request "
                        "(default: = --threshold)")
    r.add_argument("--sustain", type=int, default=1,
                   help="number of seconds above the threshold required (default: 1)")
    r.add_argument("--window", type=int, default=60,
                   help="window in seconds for --sustain (default: 60)")
    r.add_argument("--load-signal", choices=["none", "psi", "loadavg"], default="none",
                   help="hardens the rules according to the load: psi (reactive), loadavg "
                        "(load/cores) or none (default)")
    r.add_argument("--load-tense", type=float,
                   help="signal value at the tense level (default: 20 %% for psi, 1.0 for loadavg)")
    r.add_argument("--load-critical", type=float,
                   help="value at the critical level (default: 50 %% for psi, 2.0 for loadavg)")
    r.add_argument("--load-recover", type=parse_duration, default=300,
                   help="time below the level before going down one level (default: 5m)")
    r.add_argument("--tense-factor", type=float, default=0.5,
                   help="multiplier of the threshold AND of the ban duration at the tense level (default: 0.5)")
    r.add_argument("--critical-factor", type=float, default=0.25,
                   help="same at the critical level (default: 0.25)")
    r.add_argument("--min-threshold", type=float, default=1.0,
                   help="floor of the effective threshold in req/s (default: 1)")
    r.add_argument("--min-ban-time", dest="min_ban_seconds", type=parse_duration, default=60,
                   help="floor of the effective ban duration (default: 1m)")
    r.add_argument("--ignore-path", metavar="REGEX",
                   help="opt-in: does not count the requests whose path matches "
                        "(cheap static pages, e.g. ^/(assets|uploads)/)")
    r.add_argument("--watch-agent", metavar="REGEX",
                   help="opt-in: logs (WATCH) the IPs whose user agent matches when "
                        "their range is banned (e.g. ^gitlab-runner); does not change the count")
    r.add_argument("--watch-path", metavar="REGEX",
                   help="restricts --watch-agent to the matching paths (e.g. ^/api/v4/); "
                        "if both are given, both must match")
    r.add_argument("--ban-scope", choices=SCOPES, default="allocation",
                   help="allocation: the whole RDAP range is banned (default); observed: only "
                        "the groups of IPs seen, inside the allocation")
    r.add_argument("--observed-prefix", type=int, default=20,
                   help="ban_scope=observed: maximum width of a group of IPs, as an IPv4 prefix "
                        "(default: 20, i.e. 4096 addresses; IPv6: /48)")
    r.add_argument("--observed-escalate", type=int, default=4,
                   help="ban_scope=observed: partial bans of the same allocation (within the duration "
                        "of a ban) before falling back to wide blocks (default: 4)")
    r.add_argument("--observed-max-prefix", type=int, default=16,
                   help="ban_scope=observed: if the traffic is scattered, blocks of this width are "
                        "banned (IPv4 prefix, default: 16; IPv6: /32) instead of the whole "
                        "allocation; 0 = whole allocation")
    r.add_argument("--rdap-per-hour", type=int, default=100,
                   help="budget of RDAP requests per hour (default: 100)")
    r.add_argument("--delay", type=float, default=2.0,
                   help="minimum seconds between two RDAP requests (default: 2)")
    r.set_defaults(fn=cmd_run)

    sub.add_parser("setup", parents=[common],
                   help="creates the nft table if absent").set_defaults(fn=cmd_setup)
    sub.add_parser("bans", parents=[common], help="lists the active bans").set_defaults(fn=cmd_bans)

    ins = sub.add_parser("install", parents=[common],
                         help="installs fobots (nftables, user, directories, configuration, systemd unit)")
    ins.add_argument("--log", help="log to follow, written in the configuration created (default: the example's)")
    ins.add_argument("--log-group", help="group giving access to the log (default: detected, otherwise adm)")
    ins.add_argument("--yes", action="store_true", help="answers yes to the questions (apt installation)")
    ins.add_argument("--enable", action="store_true", help="enables the service at boot")
    ins.add_argument("--start", action="store_true", help="enables AND starts the service")
    ins.add_argument("--destdir", help="writes the files under this prefix without touching the system (test)")
    ins.set_defaults(fn=cmd_install)

    wd = sub.add_parser("watched", parents=[common],
                        help="monitored IPs (watch_*) caught in a ban: possible false positives")
    wd.add_argument("--since", type=parse_duration, default=7 * 86400,
                    help="period to consider: 12h, 3d… (default: 7d)")
    wd.add_argument("--active", action="store_true", help="only those whose ban is active")
    wd.add_argument("--cmd", action="store_true",
                    help="only prints the corresponding `welcome add` command")
    wd.set_defaults(fn=cmd_watched)

    w = sub.add_parser("welcome", parents=[common], help="manages the welcome list")
    w.add_argument("action", choices=["add", "list"])
    w.add_argument("nets", nargs="*", help="CIDRs to add (add)")
    w.set_defaults(fn=cmd_welcome)

    for p in sub.choices.values():
        p.set_defaults(config=conf_path, **conf)  # command line > configuration > defaults
    args = ap.parse_args(argv)
    if args.cmd == "run":
        for name in ("tense_factor", "critical_factor"):
            if not 0 < getattr(args, name) <= 1:
                ap.error(f"--{name.replace('_', '-')} must be in ]0, 1]")
    if args.cmd == "welcome" and args.action == "add" and not args.nets:
        ap.error("welcome add: give at least one range")
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    try:
        return args.fn(args)
    except NftError as e:  # nft missing, kernel refusal, insufficient permissions…
        log.error("nft: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())

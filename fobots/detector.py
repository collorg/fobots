# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Detection: counting requests per range and deciding what to ban."""
import ipaddress
import logging
import re
import time
from collections import Counter, defaultdict

from .events import append_event
from .grouping import cluster_ips, pick_groups, wide_blocks
from .load import LEVELS, NoLoad
from .nft import NftError
from .util import fmt_range, parse_ts, prefix_of

log = logging.getLogger("fobots")


LINE_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\]')

# End of a "combined" line: "METHOD /path PROTO" status size "referer" "user-agent"
REQ_RE = re.compile(r'"[A-Z]+ (\S+)[^"]*" \d+ \S+ "[^"]*" "([^"]*)"\s*$')

# First quoted string: the request line (common or combined format)
PATH_RE = re.compile(r'"[A-Z]+ (\S+)')

RECENT_BAN_SECS = 60  # no new attempt for a range just banned

MAX_WATCHED = 5000    # "monitored" IPs kept in memory (opt-in --watch-*)

WATCH_RETENTION = 3600  # seconds (log time) during which they are remembered

WATCH_EVENT_IPS = 200         # IPs recorded at most per ban

# ban_scope = observed: the IPs seen (`window`) are grouped into groups of bounded extent;
# the most active are banned, until they cover this share of the allocation's requests.
OBSERVED_COVERAGE = 0.8

OBSERVED_MAX_GROUPS = 4       # beyond: too scattered, fall back to wide blocks

OBSERVED_MAX_IPS = 200_000    # IPs tracked at most (memory)

OBSERVED_PREFIX6 = 48         # maximum width of a group in IPv6 (adjustable in IPv4)

OBSERVED_WIDE6 = 32           # maximum width of a fallback ban in IPv6 (adjustable in IPv4)

SCOPES = ("allocation", "observed")



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

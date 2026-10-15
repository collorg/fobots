# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""`fobots analyse`: reads a log once and suggests settings (threshold, ignore_path…)."""
import ipaddress
import re
from collections import Counter, defaultdict

from .util import fmt_range, parse_ts, prefix_of

# common or combined format; the duration, if any, is the LAST field (Apache: %D at the end of
# the LogFormat, in microseconds; nginx: $request_time, in seconds)
FULL_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+)[^"]*" (\d{3}) (\S+)'
    r'(?: "[^"]*" "([^"]*)"(?:\s+(\d+(?:\.\d+)?))?)?\s*$')

STATIC_RE = re.compile(r"\.(js|css|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|map|mp4|webm)$",
                       re.I)

THRESHOLDS = (1, 2, 3, 5, 8, 10, 20, 50)  # grid of the "what if" table

SLOW_RATES = (0.1, 0.2, 0.3, 0.5, 1, 2)  # grid of average rates (req/s) of the slow-scraper table

MAX_AGENT_SET = 5000     # IPs / ranges remembered per user agent

MAX_AGENTS = 50_000      # distinct user agents kept
MAX_RANGE_IPS = 1000     # IPs remembered per range (only used to give an order of magnitude)
MIN_DIR_SHARE = 0.01     # a directory is suggested for exclusion from this share of the lines
STATIC_SHARE = 0.9       # ... if this share of its requests are static files
CHEAP_MS = 50            # ... and, when the log has durations, below this mean time

UNITS_MS = {"us": 0.001, "ms": 1.0, "s": 1000.0}


def dir_key(path):
    """Directory of a request path, at most two levels (`/collorg/images/`); a file at the root
    is its own key (`/robots.txt`)."""
    parts = path.split("?", 1)[0].split("/")[1:]
    dirs = parts[:-1]
    if not dirs:
        return "/" + parts[0] if parts and parts[0] else "/"
    return "/" + "/".join(dirs[:2]) + "/"


def sustained_rate(per_second, k):
    """Highest rate R such that the range was above R req/s for k consecutive seconds
    (= it would be banned by any threshold below R): max over the windows of k consecutive
    seconds of the minimum of the window."""
    best = 0
    secs = sorted(per_second)
    for i, s in enumerate(secs):
        if i + k > len(secs) or secs[i + k - 1] != s + k - 1:
            continue
        best = max(best, min(per_second[s + j] for j in range(k)))
    return best


def average_rate(per_second, window):
    """Highest average rate (req/s) over `window` consecutive seconds: catches the scraper that
    stays at about one request per second for hours, below any per-second threshold."""
    secs = sorted(per_second)
    best = total = i = 0
    for j, s in enumerate(secs):
        total += per_second[s]
        while s - secs[i] >= window:
            total -= per_second[secs[i]]
            i += 1
        best = max(best, total)
    return best / window


class Analysis:
    def __init__(self, store, ignore_path=None, sustain=5, time_unit="auto", slow_window=600):
        self.store, self.ignore_path, self.sustain, self.time_unit = store, ignore_path, sustain, time_unit
        self.slow_window = slow_window
        self.agent_ips, self.agent_ranges = defaultdict(set), defaultdict(set)
        self.lines = self.unreadable = self.private = self.ignored = 0
        self.first = self.last = None
        self.ranges = defaultdict(lambda: defaultdict(int))   # range -> {second: n}
        self.range_hits, self.range_ips = Counter(), defaultdict(set)
        self.dirs = {}       # directory -> [hits, static, ignored, time_ms, timed, bytes]
        self.agents = Counter()
        self.timed = 0       # lines with a duration
        self.memo = {}

    def feed(self, line, site=None):
        m = FULL_RE.match(line)
        if not m:
            self.unreadable += 1
            return
        ip, ts, _method, path, _status, size, agent, dur = m.groups()
        try:
            sec = parse_ts(ts)
        except ValueError:
            self.unreadable += 1
            return
        self.lines += 1
        self.first = sec if self.first is None else min(self.first, sec)
        self.last = sec if self.last is None else max(self.last, sec)
        ignored = (self.ignore_path is not None and self.ignore_path.search(path) is not None) \
            or (site is not None and (site.all or site.ignores(path)))
        d = self.dirs.setdefault(dir_key(path), [0, 0, 0, 0.0, 0, 0])
        d[0] += 1
        d[1] += STATIC_RE.search(path.split("?", 1)[0]) is not None
        d[2] += ignored
        if size.isdigit():
            d[5] += int(size)
        if dur is not None:
            unit = self.time_unit if self.time_unit != "auto" else ("s" if "." in dur else "us")
            d[3] += float(dur) * UNITS_MS[unit]
            d[4] += 1
            self.timed += 1
        if agent is not None and (agent in self.agents or len(self.agents) < MAX_AGENTS):
            self.agents[agent[:90]] += 1
        if ignored:
            self.ignored += 1
            return
        key = self.memo.get(ip)
        if key is None:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                self.unreadable += 1
                return
            if not addr.is_global:
                self.private += 1
                return
            key = self.memo[ip] = self.store.find(addr) or prefix_of(addr)
        self.ranges[key][sec] += 1
        self.range_hits[key] += 1
        ips = self.range_ips[key]
        if len(ips) < MAX_RANGE_IPS:
            ips.add(ip)
        if agent is not None and agent[:90] in self.agents:
            a = agent[:90]
            if len(self.agent_ips[a]) < MAX_AGENT_SET:
                self.agent_ips[a].add(ip)
                self.agent_ranges[a].add(key)

    # --- results -------------------------------------------------------------------------

    def rates(self):
        """[(sustained rate, range)] decreasing."""
        return sorted(((sustained_rate(c, self.sustain), k) for k, c in self.ranges.items()),
                      key=lambda e: -e[0])

    def ban_table(self, rates, thresholds):
        """[(threshold, ranges banned, share of the counted requests)]."""
        total = sum(self.range_hits.values()) or 1
        rows = []
        for t in thresholds:
            hit = [k for r, k in rates if r > t]
            rows.append((t, len(hit), sum(self.range_hits[k] for k in hit) / total))
        return rows

    def slow_rates(self, window):
        """[(average rate over `window`, range)] decreasing."""
        return sorted(((average_rate(c, window), k) for k, c in self.ranges.items()),
                      key=lambda e: -e[0])

    def static_dirs(self):
        """Directories to suggest for ignore_path: frequent, almost only static files, cheap,
        and not already excluded. [(directory, hits)]."""
        out = []
        for key, (hits, static, ignored, ms, timed, _size) in self.dirs.items():
            if hits < MIN_DIR_SHARE * self.lines or ignored > hits / 2:
                continue
            if static < STATIC_SHARE * hits:
                continue
            if timed and ms / timed > CHEAP_MS:
                continue
            out.append((key, hits))
        return sorted(out, key=lambda e: -e[1])

    def suggested_regex(self, dirs):
        return "^(" + "|".join(re.escape(d) for d, _ in dirs) + ")"


def label(key):
    return fmt_range(key) if isinstance(key, tuple) else str(key)


def report(an, threshold, top=10):
    """Text of the report (list of lines)."""
    out = []
    add = out.append
    if not an.lines:
        return [f"no readable line ({an.unreadable} unreadable): is it a common/combined log?"]
    span = max(1, an.last - an.first + 1)
    dur = f"{span / 3600:.1f} h" if span >= 3600 else f"{span / 60:.0f} min"
    add(f"{an.lines} requests over {dur} ({an.lines / span:.2f} req/s on average), "
        f"{an.unreadable} unreadable line(s), {an.private} private IP(s) skipped, "
        f"{an.ignored} excluded by your ignore rules ({an.ignored / an.lines:.0%})")
    add("")
    # --- ranges
    rates = an.rates()
    grid = sorted(set(THRESHOLDS) | {threshold})
    add(f"Ranges (an allocation, or a /16 when unknown) above the threshold for "
        f"{an.sustain} consecutive seconds:")
    add("  threshold   ranges banned   share of requests")
    table = an.ban_table(rates, grid)
    for t, n, share in table:
        mark = "   <- current" if t == threshold else ""
        add(f"  {t:>6g} req/s {n:>10}   {share:>12.1%}{mark}")
    calm = next((t for t, n, _ in table if n <= 5), None)
    if calm is not None:
        add(f"  Heuristic: from {calm:g} req/s at most 5 ranges would have been banned over this "
            "period, which is easy to review by hand.")
    add("")
    add(f"Busiest ranges (sustained rate over {an.sustain} s):")
    add("  rate   requests    IPs  range")
    for r, k in rates[:top]:
        n_ips = len(an.range_ips[k])
        add(f"  {r:>4}  {an.range_hits[k]:>9}  {n_ips if n_ips < MAX_RANGE_IPS else str(MAX_RANGE_IPS) + '+':>5}  {label(k)}")
    add("")
    # --- slow scrapers
    window = max(1, min(an.slow_window, span))
    slow = an.slow_rates(window)
    total = sum(an.range_hits.values()) or 1
    add(f"Slow scrapers: average rate of a range over {window / 60:g} min "
        "(invisible to the per-second threshold):")
    add("  average rate   ranges   share of requests")
    for t in SLOW_RATES:
        hit = [k for r, k in slow if r >= t]
        add(f"  >= {t:>4g} req/s {len(hit):>8}   {sum(an.range_hits[k] for k in hit) / total:>12.1%}")
    add("  rate    requests    IPs  range")
    for r, k in slow[:top]:
        n_ips = len(an.range_ips[k])
        add(f"  {r:>5.2f}  {an.range_hits[k]:>9}  {n_ips if n_ips < MAX_RANGE_IPS else str(MAX_RANGE_IPS) + '+':>5}  {label(k)}")
    add("")
    # --- paths
    add("Busiest directories:" + ("  (mean time per request)" if an.timed else ""))
    for key, (hits, static, ignored, ms, timed, size) in sorted(
            an.dirs.items(), key=lambda e: -e[1][0])[:top]:
        extra = f"  {ms / timed:7.0f} ms" if timed else ""
        add(f"  {hits:>9} {hits / an.lines:>6.1%}  static {static / hits:>4.0%}  "
            f"excluded {ignored / hits:>4.0%}{extra}  {key}")
    if an.timed:
        add("")
        add("Most time-consuming directories (total time):")
        total_ms = sum(d[3] for d in an.dirs.values()) or 1
        for key, d in sorted(an.dirs.items(), key=lambda e: -e[1][3])[:5]:
            add(f"  {d[3] / total_ms:>6.1%} of the time  {d[0]:>9} requests  {key}")
    else:
        add("")
        add("No request duration in this log. To see which paths are expensive, add it as the "
            "LAST field of the format: Apache `%D` (µs), nginx `$request_time` (s), e.g. "
            '`LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\" %D" combined`.')
    add("")
    # --- agents
    if an.agents:
        add("Most frequent user agents (and over how many IPs / ranges they are spread):")
        spread = []
        for agent, n in an.agents.most_common(5):
            ips, rngs = len(an.agent_ips[agent]), len(an.agent_ranges[agent])
            add(f"  {n:>9} {n / an.lines:>6.1%}  {ips:>6} IPs {rngs:>5} ranges  {agent}")
            if n >= 0.1 * an.lines and rngs >= 10:
                spread.append((agent, n, rngs))
        for agent, n, rngs in spread:
            add(f"  -> {n / an.lines:.0%} of the requests come from ONE user agent spread over "
                f"{rngs}+ ranges: a distributed scraper, to look at ({agent[:40]}…)")
        add("")
    # --- suggestions
    add("Suggestions:")
    dirs = an.static_dirs()
    if dirs:
        share = sum(h for _, h in dirs) / an.lines
        add(f"  ignore_path = {an.suggested_regex(dirs)}")
        add(f"    ({share:.0%} of the requests: frequent directories that serve almost only static "
            f"files{' and answer fast' if an.timed else ''}; check that they really are cheap)")
    else:
        add("  no frequent directory of cheap static files left to exclude.")
    return out

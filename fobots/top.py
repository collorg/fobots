# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""`fobots top`: the paths (GitLab projects, otherwise directories) that receive the most requests,
counting the API calls a page triggers (Referer) against that page."""
import re
import time
from collections import defaultdict

from .analyse import dir_key
from .util import VHOST, parse_ts, printable

# common or combined format; only the referer is needed beyond analyse's fields
TOP_RE = re.compile('^' + VHOST + r'(\S+) \S+ \S+ \[([^\]]+)\] "[A-Z]+ (\S+)[^"]*" (\d{3}) \S+'
                    r'(?: "([^"]*)")?')

REFERER_RE = re.compile(r"https?://[^/\s]+(/\S*)?")

GIT_RE = re.compile(r"^(/.+?)\.git(?:/|$)")         # /group/project.git/info/refs (git over HTTP)

SHA_RE = re.compile(r"/[0-9a-f]{40}(?:/|$)")        # a page pinned to a commit

VIA_DEFAULT = "^/api/"


def path_key(path):
    """What a request belongs to: the GitLab project (everything before `/-/`, subgroups
    included; `/group/project.git/…` for git), otherwise its directory as in `analyse`."""
    p = path.split("?", 1)[0]
    i = p.find("/-/")
    if i > 0:
        return p[:i] + "/"
    m = GIT_RE.match(p)
    if m:
        return m.group(1) + "/"
    return dir_key(p)


def norm_key(path):
    """`adac/gem5` or `/adac/gem5` given on the command line -> `/adac/gem5/`."""
    return "/" + path.strip("/") + "/" if path.strip("/") else "/"


class Stats:
    __slots__ = ("requests", "via", "sha", "aborted", "ips")

    def __init__(self):
        self.requests = self.via = self.sha = self.aborted = 0
        self.ips = set()

    def add(self, ip, via, sha, status):
        self.requests += 1
        self.via += via
        self.sha += sha
        self.aborted += status == "499"
        self.ips.add(ip)


class Top:
    def __init__(self, ignore_path=None, via=VIA_DEFAULT, hourly=None):
        self.ignore_path = ignore_path
        self.via = re.compile(via) if via else None
        self.hourly = hourly  # None: no hourly table; "": every request; else a norm_key
        self.paths = defaultdict(Stats)
        self.hours = defaultdict(Stats)
        self.lines = self.unreadable = self.ignored = 0
        self.first = self.last = None

    def feed(self, line, site=None):
        m = TOP_RE.match(line)
        if not m:
            self.unreadable += 1
            return
        ip, ts, path, status, referer = m.groups()
        try:
            sec = parse_ts(ts)
        except ValueError:
            self.unreadable += 1
            return
        self.lines += 1
        self.first = sec if self.first is None else min(self.first, sec)
        self.last = sec if self.last is None else max(self.last, sec)
        if (self.ignore_path is not None and self.ignore_path.search(path)) or \
                (site is not None and (site.all or site.ignores(path))):
            self.ignored += 1
            return
        via = False
        if self.via is not None and referer and self.via.search(path):
            r = REFERER_RE.match(referer)
            if r:  # charged to the page that made the call
                key, via = path_key(r.group(1) or "/"), True
        if not via:
            key = path_key(path)
        sha = not via and SHA_RE.search(path.split("?", 1)[0]) is not None
        self.paths[key].add(ip, via, sha, status)
        if self.hourly is not None and self.hourly in ("", key):
            self.hours[sec - sec % 3600].add(ip, via, sha, status)


def row(s):
    n = s.requests
    direct = n - s.via
    return (f"{n:>10} {s.via:>8} {s.sha / direct if direct else 0:>5.0%} {s.aborted / n:>5.0%} "
            f"{len(s.ips):>8} {n / len(s.ips):>7.1f}")


HEADER = "  requests      via   sha   499      IPs  req/IP"


def report(top, n=20):
    """Text of the report (list of lines)."""
    out = []
    add = out.append
    if not top.lines:
        return [f"no readable line ({top.unreadable} unreadable): is it a common/combined log?"]
    span = max(1, top.last - top.first + 1)
    dur = f"{span / 3600:.1f} h" if span >= 3600 else f"{span / 60:.0f} min" if span >= 60 else f"{span} s"
    add(f"{top.lines} requests over {dur} ({top.lines / span:.2f} req/s on average), "
        f"{top.unreadable} unreadable line(s), "
        f"{top.ignored} excluded by your ignore rules ({top.ignored / top.lines:.0%})")
    counted = top.lines - top.ignored
    if counted:
        via = sum(s.via for s in top.paths.values())
        if top.via is not None:
            add(f"{via} requests matching {top.via.pattern} ({via / counted:.0%}) are charged to the "
                "page that made them (Referer)")
        add("")
        add(HEADER + "  share  path")
        for key, s in sorted(top.paths.items(), key=lambda kv: (-kv[1].requests, kv[0]))[:n]:
            add(f"{row(s)}  {s.requests / counted:>5.0%}  {printable(key)}")
        if len(top.paths) > n:
            add(f"  ({len(top.paths) - n} more path(s): --top)")
    if top.hourly is not None:
        add("")
        add(f"Per hour, {printable(top.hourly) if top.hourly else 'every path'}:")
        if not top.hours:
            add("  no request")
        add(HEADER + "  hour")
        for h in sorted(top.hours):
            add(f"{row(top.hours[h])}  {time.strftime('%Y-%m-%d %H:00', time.localtime(h))}")
    add("")
    add("path: the GitLab project (before /-/), otherwise the directory. via: requests charged")
    add("through their Referer. sha: share of the other ones pinned to a commit (40 hex digits),")
    add("what scrapers enumerate. 499: the client left before the answer.")
    return out

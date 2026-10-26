# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Learning of "trap" paths: routes that only scanners ask for.

A path is a trap candidate when many distinct IPs, from different networks, get a 404 or a 403
for it. What the site actually serves (2xx, 3xx) protects: an exact path that answered once is
never a trap, and neither is a path of the same *shape* as the ones that answered. The shape
replaces the variable segments by a type (`/post/{uuid}`), so that a deleted post is not taken
for a vulnerability scan. Only fixed types are learned (no free regular expression): a segment
with `..`, `%`, `.env`, `.git`… never matches one.

This module only observes and decides who deserves a ban; the Detector acts (or only logs, until
`trap_ban` is on). An IP is flagged once it has asked for `hits` distinct established traps.
`fobots traps` shows what was learned and who was flagged."""
import ipaddress
import re
from functools import lru_cache

from .util import parse_ts

# ip - - [time] "METHOD /path PROTO" status
ACCESS_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "[A-Z]+ (\S+)[^"]*" (\d{3}) ')

FAILED = (403, 404)   # the route does not exist (or is forbidden): candidate trap
EXTRA_EXISTS = (401, 405)  # besides < 400: the route exists, the request is refused

MAX_PATH = 200           # characters of a path kept
MAX_OK = 50_000          # literal paths seen answering
MAX_TEMPLATES = 2_000    # shapes learned
MAX_VALUES = 50          # distinct values kept per shape
MAX_TRAPS = 20_000       # candidate paths followed
MAX_TRAP_IPS = 200       # IPs followed per candidate
PURGE_EVERY = 600        # seconds (log time) between two purges
MAX_SCORES = 50_000      # IPs followed for the traps they asked for
MAX_OFFENDERS = 100      # flagged IPs kept in the snapshot
STRIKES_KEEP = 7 * 86400 # seconds (log time) during which a flagged IP is remembered (recidive)

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
INT_RE = re.compile(r"[0-9]+")
ULID_RE = re.compile(r"(?=.*[0-9])[0-9a-hjkmnp-tv-z]{26}")  # Crockford alphabet, lowercase
HEX_RE = re.compile(r"(?=.*[0-9])(?=.*[a-f])[0-9a-f]{8,}")  # hashes, object ids
SLUG_RE = re.compile(r"(?=.*[0-9])[a-z0-9]+(?:[-_][a-z0-9]+)+")  # my-post-42 (not wp-admin)
EXT_RE = re.compile(r"(.+)\.([a-z0-9]{1,5})$")

SEGMENT_TYPES = (("{uuid}", UUID_RE), ("{int}", INT_RE), ("{ulid}", ULID_RE),
                 ("{hex}", HEX_RE), ("{slug}", SLUG_RE))


def segment_type(seg):
    """Type of a variable segment (`{uuid}`, `{int}`…), None if it is a literal."""
    for name, rx in SEGMENT_TYPES:
        if rx.fullmatch(seg):
            return name
    return None


def shape(path):
    """(normalized path, template, values): lowercase, without query string nor trailing slash.
    The template replaces each variable segment by its type; values are those segments."""
    p = path.split("?", 1)[0].split("#", 1)[0].lower()[:MAX_PATH]
    if len(p) > 1:
        p = p.rstrip("/") or "/"
    segs, vals = p.split("/"), []
    last = len(segs) - 1
    for i, seg in enumerate(segs):
        ext = ""
        if i == last:  # 123.json -> {int}.json
            m = EXT_RE.match(seg)
            if m:
                seg, ext = m.group(1), "." + m.group(2)
        kind = segment_type(seg)
        if kind:
            vals.append(seg)
            segs[i] = kind + ext
    return p, "/".join(segs), tuple(vals)


@lru_cache(maxsize=65536)
def net_of(ip):
    """Network of a public IP (/16, IPv6 /32), None otherwise: distinct networks tell a
    scan spread over many hosts from one noisy client."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not a.is_global:
        return None
    return (a.version, int(a) >> (16 if a.version == 4 else 96))


class TrapLearner:
    """The routes of one site: what it serves, and which missing routes many IPs ask for."""

    def __init__(self, min_ips=5, min_nets=3, window=6 * 3600, template_min=3, hits=2,
                 ignore=None, exempt=None):
        self.min_ips, self.min_nets = min_ips, min_nets
        self.window, self.template_min = window, template_min
        self.hits = hits        # distinct established traps asked for before an IP is flagged
        self.ignore = ignore    # regex: matching paths are never traps (written by hand)
        self.exempt = exempt    # ip -> bool: welcome list, never counted nor flagged
        self.established = set()  # trap paths that meet the thresholds now
        self.scores = {}        # ip -> {trap path: last second}
        self.muted = {}         # ip -> second until which it is not flagged again
        self.strikes = {}       # ip -> [times flagged, last second]
        self.pending = []       # offenders to deal with (the Detector drains it)
        self.offenders = []     # last flagged IPs, for the snapshot
        self.ok = set()         # literal paths that answered
        self.templates = {}     # template -> set of the values that answered
        self.traps = {}         # path -> [requests, {ip: last second}]
        self.lines = self.excused = self.ignored = self.welcomed = 0
        self.latest = self.last_purge = 0

    def feed_line(self, line):
        m = ACCESS_RE.match(line)
        if m:
            try:
                sec = parse_ts(m.group(2))
            except ValueError:
                return
            self.feed(m.group(1), sec, m.group(3), int(m.group(4)))

    def feed(self, ip, sec, path, status):
        self.lines += 1
        if sec > self.latest:
            self.latest = sec
            if sec - self.last_purge >= PURGE_EVERY:
                self.purge()
        if status < 400 or status in EXTRA_EXISTS:
            self.learn_served(*shape(path))
        elif status in FAILED:
            self.learn_missing(ip, sec, *shape(path))

    def learn_served(self, p, tpl, vals):
        if not vals:
            if len(self.ok) < MAX_OK:
                self.ok.add(p)
            self.traps.pop(p, None)
            self.established.discard(p)
            return
        seen = self.templates.get(tpl)
        if seen is None:
            if len(self.templates) >= MAX_TEMPLATES:
                return
            seen = self.templates[tpl] = set()
        if len(seen) < MAX_VALUES:
            seen.add(vals)

    def is_served(self, p, tpl, vals):
        """Does the site serve this path, or paths of the same shape?"""
        if p in self.ok:
            return True
        seen = self.templates.get(tpl) if vals else None
        return bool(seen) and (vals in seen or len(seen) >= self.template_min)

    def learn_missing(self, ip, sec, p, tpl, vals):
        if self.ignore is not None and self.ignore.search(p):
            self.ignored += 1
            return
        if self.is_served(p, tpl, vals):
            self.excused += 1
            return
        if net_of(ip) is None:
            return
        if self.exempt is not None and self.exempt(ip):
            self.welcomed += 1
            return
        t = self.traps.get(p)
        if t is None:
            if len(self.traps) >= MAX_TRAPS:
                return
            t = self.traps[p] = [0, {}]
        t[0] += 1
        if ip in t[1] or len(t[1]) < MAX_TRAP_IPS:
            t[1][ip] = sec
        if p in self.established:
            self.credit(ip, sec, p)
        elif len(t[1]) >= self.min_ips and self.qualifies(t[1], sec - self.window):
            self.established.add(p)  # the IPs that made it a trap are credited too
            for other, s in list(t[1].items()):
                if s >= sec - self.window:
                    self.credit(other, s, p)

    def qualifies(self, ips, cutoff):
        """Enough recent IPs, from enough networks?"""
        recent = [ip for ip, s in ips.items() if s >= cutoff]
        return len(recent) >= self.min_ips and len({net_of(ip) for ip in recent}) >= self.min_nets

    def credit(self, ip, sec, p):
        """The IP asked for the established trap `p`: flagged once it has asked for `hits`."""
        if self.muted.get(ip, 0) > sec:
            return
        h = self.scores.get(ip)
        if h is None:
            if len(self.scores) >= MAX_SCORES:
                return
            h = self.scores[ip] = {}
        h[p] = max(sec, h.get(p, 0))
        cutoff = sec - self.window
        recent = sorted(q for q, s in h.items() if s >= cutoff)
        if len(recent) >= self.hits:
            n = self.strikes.get(ip, [0, 0])[0] + 1
            self.strikes[ip] = [n, sec]
            del self.scores[ip]
            off = {"ip": ip, "paths": recent, "t": sec, "strikes": n, "banned": False,
                   "seconds": 0}
            self.pending.append(off)
            self.offenders = (self.offenders + [off])[-MAX_OFFENDERS:]

    def take_offenders(self):
        out, self.pending = self.pending, []
        return out

    def mute(self, ip, until):
        """Not flagged again before `until` (the ban, or the one that would have been)."""
        self.muted[ip] = until

    def purge(self):
        self.last_purge = self.latest
        cutoff = self.latest - self.window
        for p in list(self.traps):
            t = self.traps[p]
            t[1] = {ip: s for ip, s in t[1].items() if s >= cutoff}
            if not t[1]:
                del self.traps[p]
        self.established = {p for p in self.established
                            if p in self.traps and self.qualifies(self.traps[p][1], cutoff)}
        for ip in list(self.scores):
            h = self.scores[ip] = {q: s for q, s in self.scores[ip].items() if s >= cutoff}
            if not h:
                del self.scores[ip]
        self.muted = {ip: u for ip, u in self.muted.items() if u > self.latest}
        keep = self.latest - STRIKES_KEEP
        self.strikes = {ip: v for ip, v in self.strikes.items() if v[1] >= keep}

    def found(self, min_ips=None, min_nets=None):
        """Candidate traps over the window: [{path, ips, nets, requests, last}], the most
        asked for first. Re-checked against what is served now (a 200 may have come since)."""
        min_ips = self.min_ips if min_ips is None else min_ips
        min_nets = self.min_nets if min_nets is None else min_nets
        cutoff = self.latest - self.window
        out = []
        for p, (n, ips) in self.traps.items():
            recent = [ip for ip, s in ips.items() if s >= cutoff]
            if len(recent) < min_ips or self.is_served(*shape(p)):
                continue
            nets = {net_of(ip) for ip in recent}
            if len(nets) >= min_nets:
                out.append({"path": p, "ips": len(recent), "nets": len(nets), "requests": n,
                            "last": max(ips[ip] for ip in recent)})
        out.sort(key=lambda e: (-e["ips"], -e["nets"], e["path"]))
        return out

    def learned_templates(self):
        """Shapes that protect a missing path: [{template, values}] (values: capped)."""
        out = [{"template": t, "values": len(v)} for t, v in self.templates.items()
               if len(v) >= self.template_min]
        out.sort(key=lambda e: (-e["values"], e["template"]))
        return out

    def snapshot(self):
        return {"lines": self.lines, "excused": self.excused, "served": len(self.ok),
                "ignored": self.ignored, "welcomed": self.welcomed, "latest": self.latest, "traps": self.found(),
                "offenders": self.offenders,
                "templates": self.learned_templates()}

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""`fobots probe --record` / `--report`: what the machine looks like when the service slows down.

The recorder measures the response time of a page, and keeps in memory the last two minutes of
system readings (/proc only: it must stay cheap when the server suffers). When the response time
reaches the tense level it writes those readings, then a full snapshot every few seconds while
the slowdown lasts. `report` tells which reading moved first, and by how long, to choose the
signals and thresholds of the daemon."""
import collections
import http.client
import json
import logging
import math
import os
import re
import socket
import statistics
import time

from .load import read_psi, summarize

log = logging.getLogger("fobots")

PRE_SECONDS = 120        # readings written before the start of a slowdown
BASE_EVERY = 300         # seconds between two readings of normal times (for comparison)
SNAP_EVERY = 10          # seconds between two snapshots during a slowdown
GAP_FACTOR = 3           # a measure later than this x the interval is recorded as a gap
MAX_BYTES = 20 << 20     # the file is renamed FILE.1 above this size
WEB_PORTS = (80, 443)
TOP_PROCS = 8
MIN_MEASURES = 500       # normal measures needed before suggesting levels
MIN_SPAN = 7200          # seconds recorded needed before suggesting levels
SEVERE = 5.0            # seconds: a slowdown this slow is an incident by itself
SEVERE_EPISODES = 3      # of them: enough to suggest levels without a long record of normal times
MIN_EPISODES = 3         # slowdowns needed before comparing the other signals
MIN_FEW = 30             # normal measures needed to use their p99 at all
MIN_KNOWN = 10           # normal readings needed to judge the false alarms of a reading
SHORT_EPISODE = 20       # seconds: a slowdown this short or less is an excursion, not an incident
MAX_FALSE = 0.05         # false alarms accepted of a reading proposed as a signal
LEAD_SHARE = 2 / 3       # share of the slowdowns it must precede
MIN_LEAD = 20            # seconds of median advance
SIM_MAX_STEP = 30        # seconds counted for one sample in the replay
EPISODE_GAP = 120        # seconds without snapshot: the next slowdown is another episode

LOG_RE = re.compile(r'^(\S+) .*?"[A-Z]+ [^"]*" (\d{3}) ')
MIN_LOG_SECONDS = 0.5    # a rate over less than this would be meaningless
LOG_MAX_READ = 8 << 20   # bytes read from one log per measure (the rest is read next time)

# Reference values to judge when a reading "moved" (not recommendations).
ALARMS = {
    "load average / core": (lambda s: s.get("load"), 1.0, ">="),
    "pressure cpu": (lambda s: (s.get("psi") or {}).get("cpu"), 20.0, ">="),
    "pressure io": (lambda s: (s.get("psi") or {}).get("io"), 20.0, ">="),
    "pressure memory": (lambda s: (s.get("psi") or {}).get("memory"), 5.0, ">="),
    "memory available %": (lambda s: s.get("avail_pct"), 15.0, "<="),
    "swap pages/s": (lambda s: s.get("swap_rate"), 100.0, ">="),
    "accept queue 80/443": (lambda s: s.get("lq"), 1, ">="),
    "listen overflows": (lambda s: s.get("lovf"), 1, ">="),
    "requests/s (log)": (lambda s: s.get("req_s"), None, ">="),  # 2 x the normal median
    "5xx share % (log)": (lambda s: s.get("e5"), 5.0, ">="),
}



def alarm(name, s, limits=None):
    get, limit, op = ALARMS[name]
    limit = (limits or {}).get(name, limit)
    v = get(s)
    if v is None or limit is None:
        return None
    return v >= limit if op == ">=" else v <= limit



# readings ---------------------------------------------------------------------------------

def _meminfo(root):
    out = {}
    with open(f"{root}/meminfo") as f:
        for line in f:
            k, _, v = line.partition(":")
            out[k] = int(v.split()[0])
    return out



def _vmstat(root, *keys):
    out = {}
    with open(f"{root}/vmstat") as f:
        for line in f:
            k, _, v = line.partition(" ")
            if k in keys:
                out[k] = int(v)
    return out



def _listen_queue(root):
    """Longest accept queue among the listening sockets of the web ports."""
    best = None
    for name in ("tcp", "tcp6"):
        try:
            f = open(f"{root}/net/{name}")
        except OSError:
            continue
        with f:
            next(f, None)
            for line in f:
                cols = line.split()
                if len(cols) > 4 and cols[3] == "0A" and int(cols[1].rpartition(":")[2], 16) in WEB_PORTS:
                    best = max(best or 0, int(cols[4].partition(":")[2], 16))
    return best



def _listen_drops(root):
    with open(f"{root}/net/netstat") as f:
        rows = [line.split() for line in f]
    for head, vals in zip(rows, rows[1:]):
        if head[0] == "TcpExt:" and "ListenOverflows" in head:
            d = dict(zip(head[1:], map(int, vals[1:])))
            return d["ListenOverflows"] + d.get("ListenDrops", 0)
    raise OSError("TcpExt not found")



def read_sys(root="/proc", prev=None, now=None):
    """(readings, state for the next call). A reading that cannot be made is None."""
    now = time.time() if now is None else now
    prev = prev or {}
    s, state = {}, {"t": now}

    def attempt(key, fn):
        try:
            return fn()
        except (OSError, ValueError, KeyError, IndexError, StopIteration):
            return None
    def loadavg():
        with open(f"{root}/loadavg") as f:
            return float(f.read().split()[0])
    la = attempt("load", loadavg)
    s["load"] = None if la is None else round(la / (os.cpu_count() or 1), 2)
    mem = attempt("mem", lambda: _meminfo(root))
    if mem:
        s["avail_pct"] = round(100 * mem["MemAvailable"] / mem["MemTotal"], 1)
        s["swap_mb"] = (mem.get("SwapTotal", 0) - mem.get("SwapFree", 0)) // 1024
    pages = attempt("vm", lambda: _vmstat(root, "pswpin", "pswpout"))
    if pages and len(pages) == 2:
        state["swap"] = pages["pswpin"] + pages["pswpout"]
        if "swap" in prev and now > prev["t"]:
            s["swap_rate"] = round(max(0, state["swap"] - prev["swap"]) / (now - prev["t"]), 1)
    psi = {r: attempt(r, lambda r=r: read_psi(r, root)) for r in ("cpu", "io", "memory")}
    s["psi"] = psi if any(v is not None for v in psi.values()) else None
    s["lq"] = attempt("lq", lambda: _listen_queue(root))
    drops = attempt("drops", lambda: _listen_drops(root))
    if drops is not None:
        state["drops"] = drops
        if "drops" in prev:
            s["lovf"] = max(0, drops - prev["drops"])
    return s, state



def scan_procs(root="/proc", prev=None):
    """([top groups by memory], cumulative CPU per group). A group = processes of one name
    (e.g. 'php-fpm8.1', 'nginx'): {name, n, rss_mb, cpu_s since the previous scan}."""
    page = os.sysconf("SC_PAGE_SIZE")
    tick = os.sysconf("SC_CLK_TCK")
    groups = {}
    try:
        pids = [p for p in os.listdir(root) if p.isdigit()]
    except OSError:
        return [], {}
    for pid in pids:
        try:
            with open(f"{root}/{pid}/stat") as f:
                raw = f.read()
            with open(f"{root}/{pid}/statm") as f:
                rss = int(f.read().split()[1]) * page
        except (OSError, ValueError, IndexError):
            continue  # the process ended meanwhile
        name = raw[raw.index("(") + 1:raw.rindex(")")]
        rest = raw[raw.rindex(")") + 2:].split()
        g = groups.setdefault(name, [0, 0, 0.0])
        g[0] += 1
        g[1] += rss
        g[2] += (int(rest[11]) + int(rest[12])) / tick
    cpu = {k: g[2] for k, g in groups.items()}
    top = sorted(groups.items(), key=lambda kv: -kv[1][1])[:TOP_PROCS]
    prev = prev or {}
    return ([{"name": k, "n": g[0], "rss_mb": g[1] >> 20,
              "cpu_s": round(max(0.0, g[2] - prev[k]), 1) if k in prev else None}
             for k, g in top], cpu)



class LogTail:
    """Counts what the logs received since the previous call: requests/s, share of 5xx, IPs.
    Starts at the end of the files; follows a rotation (new inode or smaller file)."""

    def __init__(self, paths):
        self.files = {}
        for p in paths:
            try:
                st = os.stat(p)
                self.files[p] = (st.st_ino, st.st_size)
            except OSError:
                self.files[p] = (None, 0)
        self.t = None

    def read(self, now):
        count = errors = 0
        ips = set()
        for p, (ino, pos) in list(self.files.items()):
            try:
                with open(p, "rb") as f:
                    st = os.fstat(f.fileno())
                    if ino != st.st_ino or st.st_size < pos:
                        pos = 0  # rotated
                    f.seek(pos)
                    data = f.read(LOG_MAX_READ)
                    if len(data) == LOG_MAX_READ:  # too much at once: stop at a line end
                        data = data[:data.rfind(b"\n") + 1]
                    self.files[p] = (st.st_ino, pos + len(data))
            except OSError:
                continue
            for line in data.decode("utf-8", "replace").splitlines():
                m = LOG_RE.match(line)
                if m:
                    count += 1
                    errors += m.group(2).startswith("5")
                    ips.add(m.group(1))
        dt, self.t = (None if self.t is None else now - self.t), now
        if dt is None or dt < MIN_LOG_SECONDS:
            return {}  # first call, or too short an interval to give a rate
        return {"req_s": round(count / dt, 1), "e5": round(100 * errors / count, 1) if count else None,
                "ips": len(ips)}



# recorder ---------------------------------------------------------------------------------

class Recorder:
    """One call to `step()` per measure; writes JSON lines (kinds: base, pre, snap, end, gap)."""

    def __init__(self, probe, path, tense=1.0, critical=3.0, interval=5.0, root="/proc",
                 max_bytes=MAX_BYTES, logs=()):
        self.probe, self.path, self.tense, self.critical = probe, path, tense, critical
        self.interval, self.root, self.max_bytes = interval, root, max_bytes
        self.ring = collections.deque(maxlen=max(1, int(PRE_SECONDS / interval)))
        self.state, self.cpu = None, None
        self.episode, self.written_t = False, 0.0
        self.last_base = self.last_snap = self.snap_level = None
        self.last_step = None
        self.logs = LogTail(logs) if logs else None
        self.rts = []  # response times of the normal measures since the last reading of normal times

    def start(self, url, timeout):
        """Header of a recording: what the report needs to write a configuration."""
        self.write({"t": round(time.time(), 1), "kind": "start", "url": url, "interval": self.interval,
                    "tense": self.tense, "critical": self.critical, "timeout": timeout,
                    "logs": list(self.logs.files) if self.logs else []})

    def measure(self):
        """(worst response time, error text or None); a timeout counts as the timeout."""
        worst, err = 0.0, None
        for host, url in self.probe.targets:
            try:
                status, seconds = self.probe.fetch(host, url)
                if status >= 500:
                    err = f"HTTP {status}"
            except socket.timeout:
                seconds = self.probe.timeout
            except (OSError, http.client.HTTPException) as e:
                seconds, err = 0.0, str(e) or type(e).__name__
            worst = max(worst, seconds)
        return worst, err

    def write(self, entry):
        try:
            if os.path.getsize(self.path) > self.max_bytes:
                os.replace(self.path, self.path + ".1")
        except OSError:
            pass
        with open(self.path, "a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        self.written_t = max(self.written_t, entry["t"])

    def step(self, mono=None, wall=None):
        mono = time.monotonic() if mono is None else mono
        wall = time.time() if wall is None else wall
        if self.last_step is not None and mono - self.last_step > GAP_FACTOR * self.interval + self.probe.timeout:
            self.write({"t": round(wall, 1), "kind": "gap", "seconds": round(mono - self.last_step, 1)})
        self.last_step = mono
        rt, err = self.measure()
        readings, self.state = read_sys(self.root, self.state, wall)
        if self.logs:
            readings.update(self.logs.read(wall))
        entry = {"t": round(wall, 1), "rt": round(rt, 3), "sys": readings}
        if err:
            entry["err"] = err
        level = 2 if err or rt >= self.critical else 1 if rt >= self.tense else 0
        entry["level"] = level
        if level:
            if not self.episode:
                self.episode = True
                for e in self.ring:
                    if e["t"] > self.written_t:
                        self.write({**e, "kind": "pre"})
                self.last_snap = self.snap_level = None
            if self.last_snap is None or mono - self.last_snap >= SNAP_EVERY or level > self.snap_level:
                self.last_snap, self.snap_level = mono, level
                procs, self.cpu = scan_procs(self.root, self.cpu)
                self.write({**entry, "kind": "snap", "procs": procs})
        else:
            if self.episode:
                self.episode = False
                self.write({**entry, "kind": "end"})
            else:
                self.rts.append(entry["rt"])
                if self.last_base is None or mono - self.last_base >= BASE_EVERY:
                    self.last_base = mono
                    self.write({**entry, "kind": "base", "rts": self.rts})
                    self.rts = []
        self.ring.append(entry)
        return entry

    def run(self):
        while True:
            t0 = time.monotonic()
            self.step()
            time.sleep(max(0.0, self.interval - (time.monotonic() - t0)))



# report -----------------------------------------------------------------------------------

def read_records(path):
    out = []
    for p in (path + ".1", path):
        try:
            with open(p) as f:
                for line in f:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass  # a line cut by a crash
        except OSError:
            pass
    return out



def episodes(records):
    """[{pre, snaps, end}] : slowdowns, with the readings that preceded them."""
    eps, pre, cur = [], [], None
    for r in records:
        kind = r.get("kind")
        if kind == "pre":
            pre.append(r)
        elif kind == "snap":
            if cur is None or r["t"] - cur["snaps"][-1]["t"] > EPISODE_GAP:
                cur = {"pre": pre, "snaps": [], "end": None}
                eps.append(cur)
            cur["snaps"].append(r)
            pre = []
        elif kind == "end" and cur is not None:
            cur["end"] = r
            cur = None
        elif kind == "base":
            pre = []
    return eps



def lead_stats(eps, normal, fn):
    """How a reading (fn: system readings -> bool or None) behaves around the slowdowns:
    (before, same, late, never, leads, false alarm share or None)."""
    before = same = late = never = 0
    leads = []
    for e in eps:
        t0 = e["snaps"][0]["t"]
        hits = [r["t"] for r in e["pre"] + e["snaps"] if fn(r["sys"])]
        if not hits:
            never += 1
        elif min(hits) < t0:
            before += 1
            leads.append(t0 - min(hits))
        elif min(hits) == t0:
            same += 1
        else:
            late += 1
    known = [fn(s) for s in normal if fn(s) is not None]
    return before, same, late, never, leads, (sum(known) / len(known) if len(known) >= MIN_KNOWN else None)



def ceil_half(x):
    return math.ceil(x * 2 - 1e-9) / 2



def quantile(values, q):
    v = sorted(values)
    return v[min(len(v) - 1, int(q * len(v)))]



def series(records, interval):
    """[(time, response time)] of everything recorded, in order. The measures of normal times
    are only stored by batch in each reading: spread them back at the measure interval."""
    out = []
    for r in records:
        kind = r.get("kind")
        if kind == "base":
            rts = r.get("rts") or [r.get("rt")]
            out += [(r["t"] - (len(rts) - 1 - i) * interval, v) for i, v in enumerate(rts) if v is not None]
        elif kind in ("pre", "snap", "end") and r.get("rt") is not None:
            out.append((r["t"], 99.0 if r.get("err") else r["rt"]))
    return sorted(out)



def simulate(points, tense, critical, recover, interval):
    """Replays what LoadMonitor would have done: ([seconds at normal, tense, critical], level-ups)."""
    level, below, spent, ups = 0, None, [0.0, 0.0, 0.0], 0
    for i, (t, v) in enumerate(points):
        target = (v >= tense) + (v >= critical)
        if target >= level:
            below = None
            if target > level:
                ups += level == 0
                level = target
        elif below is None:
            below = t
        elif t - below >= recover:
            level, below = level - 1, None
        nxt = points[i + 1][0] - t if i + 1 < len(points) else interval
        spent[level] += min(nxt, SIM_MAX_STEP)
    return spent, ups



def suggest(records, base, eps, times, normal, out, recover=300):
    """The configuration the recording supports. Says so when it does not support one."""
    start = next((r for r in reversed(records) if r.get("kind") == "start"), {})
    interval = start.get("interval") or 5.0
    span = records[-1]["t"] - records[0]["t"]
    out("\nSuggested configuration")
    severe = sum(max(r["rt"] if not r.get("err") else 99.0 for r in e["snaps"]) >= SEVERE for e in eps)
    enough = len(times) >= MIN_MEASURES and span >= MIN_SPAN
    if not enough and severe < SEVERE_EPISODES:
        out(f"  Not enough data yet ({len(times)} normal measures over {span / 3600:.1f} h: need "
            f"{MIN_MEASURES} over {MIN_SPAN // 3600} h, or {SEVERE_EPISODES} slowdowns of {SEVERE:g} s or more, "
            f"{severe} so far). Let the recorder run.")
        return
    floor = max(start.get("tense") or 1.0, 1.0)
    if len(times) >= MIN_FEW:
        p99 = quantile(times, 0.99)
        floor = max(floor, ceil_half(2 * p99))
        why_t = f"twice the p99 of {len(times)} normal measures ({p99:.2f} s)"
    else:
        why_t = f"default: only {len(times)} normal measures recorded"
    if not enough:
        out(f"  Short recording ({len(times)} normal measures over {span / 3600:.1f} h), but "
            f"{severe} slowdowns of {SEVERE:g} s or more: levels suggested from them.")
    tense = floor
    longs = [e for e in eps if e["snaps"][-1]["t"] - e["snaps"][0]["t"] > SHORT_EPISODE]
    shorts = [e for e in eps if e not in longs]
    peak = lambda e: max(r["rt"] if not r.get("err") else 99.0 for r in e["snaps"])
    note = ""
    if shorts:
        sp = max(peak(e) for e in shorts)
        cand = max(floor, ceil_half(sp * 1.05))
        if cand > floor:
            if not longs or cand <= 0.8 * min(peak(e) for e in longs):
                tense, why_t = cand, (f"above the {len(shorts)} short excursion(s) of {SHORT_EPISODE} s or "
                                      f"less (up to {sp:.1f} s), which are not slowdowns")
            else:
                note = (f"  Warning: short excursions up to {sp:.1f} s cannot be told from the start of the "
                        "real slowdowns: they will raise the tense level.")
    if longs:
        peaks = [peak(e) for e in longs]
        critical = min(max(peaks), max(2 * tense, ceil_half(0.8 * statistics.median(peaks))))
        why_c = f"under the median peak of the {len(longs)} slowdown(s) lasting more than {SHORT_EPISODE} s " \
                f"({', '.join(f'{x:.1f}' for x in sorted(peaks))} s)"
    else:
        critical, why_c = 3 * tense, "default ratio (no slowdown lasting more than "f"{SHORT_EPISODE} s recorded yet)"
    out("  [fobots]")
    out("  load_signal = probe")
    out(f"  load_probe_url = {start.get('url') or '<the URL given to --url>'}")
    out(f"  load_tense = {tense:g}       # {why_t}")
    out(f"  load_critical = {critical:g}    # {why_c}")
    if note:
        out(note)
    pts = series(records, interval)
    for label, (ts, cs) in (("defaults 1 s / 3 s", (1.0, 3.0)), (f"suggested {tense:g} s / {critical:g} s", (tense, critical))):
        spent, ups = simulate(pts, ts, cs, recover, interval)
        tot = sum(spent) or 1.0
        out(f"  replay, {label}: tense or critical {100 * (spent[1] + spent[2]) / tot:.1f} % of the time "
            f"({ups} rise(s), critical {100 * spent[2] / tot:.1f} %), load_recover = {recover // 60} min")
    if len(eps) < MIN_EPISODES:
        out(f"  Other signals: {len(eps)} slowdown(s) recorded, {MIN_EPISODES} needed to compare them.")
        return
    usable = {"psi": ("pressure cpu or io >= 20 %, as the daemon computes it", "load_tense = 20, load_critical = 50",
                      lambda s: _either(alarm("pressure cpu", s), alarm("pressure io", s))),
              "loadavg": ("load average per core >= 1", "load_tense = 1, load_critical = 2",
                          lambda s: alarm("load average / core", s))}
    for name, (what, values, fn) in usable.items():
        res = lead_stats(eps, normal, fn)
        if good_lead(res, len(eps)):
            out(f"  Alternative: `load_signal = {name}` ({what}) moved {lead_text(res, len(eps))}; "
                f"{values}.")
            out("    The daemon takes one signal: keep `probe` to measure what the users see, "
                "or switch if earlier matters more.")
    for name in ALARMS:
        if name in ("pressure cpu", "pressure io", "load average / core"):
            continue
        res = lead_stats(eps, normal, lambda s, n=name: alarm(n, s, _limits(base)))
        if good_lead(res, len(eps)):
            out(f"  Observed: {name} moved {lead_text(res, len(eps))}. The daemon cannot use it as a signal yet.")



def _either(a, b):
    return None if a is None and b is None else bool(a) or bool(b)



def _limits(base):
    req = [r["sys"]["req_s"] for r in base if r["sys"].get("req_s") is not None]
    return {"requests/s (log)": max(1.0, 2 * statistics.median(req))} if req else {}



def good_lead(res, n):
    before, _, _, _, leads, false = res
    return (false is not None and false < MAX_FALSE and before >= LEAD_SHARE * n
            and statistics.median(leads) >= MIN_LEAD)



def lead_text(res, n):
    before, _, _, _, leads, false = res
    return (f"before the page in {before} of {n} slowdowns (median {statistics.median(leads):.0f} s ahead, "
            f"{100 * false:.0f} % false alarms)")



def report(path, out=print):
    records = read_records(path)
    if not records:
        out(f"{path}: nothing recorded")
        return 1
    base = [r for r in records if r.get("kind") == "base"]
    eps = episodes(records)
    gaps = [r for r in records if r.get("kind") == "gap"]
    span = records[-1]["t"] - records[0]["t"]
    out(f"{path}: {len(records)} records over {span / 3600:.1f} h, "
        f"{len(base)} reading(s) of normal times, {len(eps)} slowdown(s)"
        + (f", {len(gaps)} gap(s) in the measures (the machine or the recorder stalled)" if gaps else ""))
    times = [t for r in base for t in (r.get("rts") or [r.get("rt")]) if t is not None]
    normal = [r["sys"] for r in base]
    if times:
        med, p95, mx = summarize(times)
        out(f"\nNormal times ({len(times)} measures): median {med:.2f} s, p95 {p95:.2f} s, max {mx:.2f} s")
    if not eps:
        out("\nNo slowdown recorded yet: let the recorder run until one happens.")
        suggest(records, base, eps, times, normal, out)
        return 0
    limits = _limits(base)
    req = [r["sys"]["req_s"] for r in base if r["sys"].get("req_s") is not None]
    out("\nSlowdowns:")
    for i, e in enumerate(eps, 1):
        peak = max(e["snaps"], key=lambda r: (r["rt"], r["level"]))
        end = e["end"]["t"] if e["end"] else e["snaps"][-1]["t"]
        t0 = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["snaps"][0]["t"]))
        out(f"  {i}. {t0}, {max(0, end - e['snaps'][0]['t']):.0f} s, peak {peak['rt']:.1f} s"
            + (f" ({peak['err']})" if peak.get("err") else "") + ("" if e["end"] else ", not ended"))
        ps = peak["sys"]
        if ps.get("req_s") is not None:
            out(f"       at the peak: {ps['req_s']:g} requests/s"
                + (f" (normal median {statistics.median(req):.1f})" if req else "")
                + (f", {ps['e5']:g} % of 5xx" if ps.get("e5") is not None else "")
                + f", {ps.get('ips', 0)} distinct IP(s)")
        for g in (peak.get("procs") or [])[:3]:
            out(f"       at the peak: {g['name']} x{g['n']}, {g['rss_mb']} MB"
                + ("" if g["cpu_s"] is None else f", {g['cpu_s']:g} s of CPU"))
    out("\nWhich reading moved first (reference values, not recommendations)?")
    out(f"  {'reading':<34}{'before':>8}{'same':>6}{'late':>6}{'never':>7}{'lead':>9}{'false alarms':>14}")
    for name, (_, limit, op) in ALARMS.items():
        if not any(ALARMS[name][0](r["sys"]) is not None for r in records if "sys" in r):
            out(f"  {name:<34}not available" + (" (give --log)" if "(log)" in name else " on this machine"))
            continue
        before, same, late, never, leads, false = lead_stats(
            eps, normal, lambda s, n=name: alarm(n, s, limits))
        false = "?" if false is None else f"{100 * false:.0f} %"
        lead = f"{statistics.median(leads):.0f} s" if leads else "-"
        label = f"{name} {op} " + ("2x normal" if limit is None else str(limit))
        out(f"  {label:<34}{before:>8}{same:>6}{late:>6}{never:>7}{lead:>9}{false:>14}")
    out("\nbefore = crossed before the response time did; lead = median advance; "
        "false alarms = share of normal readings already beyond the value.")
    suggest(records, base, eps, times, normal, out)
    return 0

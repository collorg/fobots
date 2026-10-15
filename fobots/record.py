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
    if times:
        med, p95, mx = summarize(times)
        tense = max(1.0, float(-(-2 * p95 // 1)))
        out(f"\nNormal times ({len(times)} measures): median {med:.2f} s, p95 {p95:.2f} s, max {mx:.2f} s -> "
            f"load_tense = {tense:g}, load_critical = {3 * tense:g} would stay quiet.")
    if not eps:
        out("\nNo slowdown recorded yet: let the recorder run until one happens.")
        return 0
    req = [r["sys"]["req_s"] for r in base if r["sys"].get("req_s") is not None]
    limits = {"requests/s (log)": max(1.0, 2 * statistics.median(req))} if req else {}
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
    normal = [r["sys"] for r in base]
    for name, (_, limit, op) in ALARMS.items():
        before, same, late, never, leads = 0, 0, 0, 0, []
        for e in eps:
            t0 = e["snaps"][0]["t"]
            hits = [r["t"] for r in e["pre"] + e["snaps"] if alarm(name, r["sys"], limits)]
            if not hits:
                never += 1
            elif min(hits) < t0:
                before += 1
                leads.append(t0 - min(hits))
            elif min(hits) == t0:
                same += 1
            else:
                late += 1
        known = [alarm(name, s, limits) for s in normal if alarm(name, s, limits) is not None]
        if not any(ALARMS[name][0](r["sys"]) is not None for r in records if "sys" in r):
            out(f"  {name:<34}not available" + (" (give --log)" if "(log)" in name else " on this machine"))
            continue
        false = f"{100 * sum(known) / len(known):.0f} %" if known else "?"
        lead = f"{statistics.median(leads):.0f} s" if leads else "-"
        label = f"{name} {op} " + ("2x normal" if limit is None else str(limit))
        out(f"  {label:<34}{before:>8}{same:>6}{late:>6}{never:>7}{lead:>9}{false:>14}")
    out("\nbefore = crossed before the response time did; lead = median advance; "
        "false alarms = share of normal readings already beyond the value.")
    return 0

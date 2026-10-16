# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""`fobots replay`: replays the GET requests of an access log against a server, with a rising load.

The log gives the mix of requests and their timing. A window of it (by default its busiest five
minutes) is replayed in loop at ×1, ×1.5, ×2… of its own speed: each stage sends the same requests,
faster. The response time of every request is measured, by type of request and by stage, which
shows what is costly and at which load the service gives way. The replay stops by itself as soon
as the service suffers (see Replay.check). The status and size logged for each request are
compared to what the server answers now: a request refused for lack of a session is cheaper than
the real one, and the report says how much of the replay is faithful."""
import collections
import concurrent.futures
import http.client
import json
import re
import socket
import ssl
import statistics
import threading
import time
from urllib.parse import urlsplit

from .analyse import dir_key
from .load import summarize
from .util import parse_ts

LOG_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+)[^"]*" (\d{3}) (\S+) "[^"]*" "([^"]*)"')

DEFAULT_SPEEDS = (1.0, 1.5, 2.0, 3.0)
MIN_WINDOW_REQUESTS = 20   # fewer requests than this: not a load
MAX_BODY = 8 << 20         # bytes read of a response
RECENT = 50                # completed requests the stop criteria look at
MEDIAN_OVER = 20
MIN_JUDGED = 20            # completed requests needed before judging the error rate
SIZE_TOLERANCE = 0.2



class Req:
    __slots__ = ("ts", "path", "status", "size", "agent")

    def __init__(self, ts, path, status, size, agent):
        self.ts, self.path, self.status, self.size, self.agent = ts, path, status, size, agent



def parse_speeds(text):
    try:
        speeds = [float(x) for x in text.split(",") if x.strip()]
    except ValueError:
        raise ValueError(f"invalid --speed {text!r} (e.g. 1,1.5,2,3)")
    if not speeds or any(s <= 0 for s in speeds):
        raise ValueError(f"invalid --speed {text!r}: positive numbers expected")
    return speeds



def read_requests(paths, agent_re=None, exclude_re=None):
    """The GET requests of the logs, in time order. Other methods are not replayed: their body
    is not in the log."""
    reqs = []
    for path in paths:
        with open(path, errors="replace") as f:
            for line in f:
                m = LOG_RE.match(line)
                if not m or m.group(3) != "GET":
                    continue
                if exclude_re and exclude_re.search(m.group(4)):
                    continue
                if agent_re and not agent_re.search(m.group(7)):
                    continue
                try:
                    ts = parse_ts(m.group(2))
                except ValueError:
                    continue
                size = int(m.group(6)) if m.group(6).isdigit() else 0
                reqs.append(Req(ts, m.group(4), int(m.group(5)), size, m.group(7)))
    reqs.sort(key=lambda r: r.ts)
    return reqs



def select_window(reqs, seconds, since=None, until=None):
    """The requests to replay: those between since and until, and if that is longer than `seconds`,
    the busiest stretch of that length. -> (requests, first ts, last ts)"""
    if since is not None:
        reqs = [r for r in reqs if r.ts >= since]
    if until is not None:
        reqs = [r for r in reqs if r.ts <= until]
    if not reqs:
        return [], 0, 0
    best_i = best_n = j = 0
    for i in range(len(reqs)):
        while reqs[i].ts - reqs[j].ts >= seconds:
            j += 1
        if i - j + 1 > best_n:
            best_n, best_i = i - j + 1, j
    chosen = [r for r in reqs[best_i:best_i + best_n]]
    return chosen, chosen[0].ts, chosen[-1].ts



def schedule(window, speed, step):
    """[(seconds from the start of the stage, request)] over `step` seconds: the window, in loop,
    at `speed` times its own speed."""
    t0 = window[0].ts
    span = max(1.0, window[-1].ts - t0 + 1.0)
    out, loop = [], 0
    while loop * span / speed < step:
        for r in window:
            when = loop * span / speed + (r.ts - t0) / speed
            if when >= step:
                return out
            out.append((when, r))
        loop += 1
    return out



def make_fetcher(base, host=None, timeout=20.0, insecure=False, user_agent=None):
    u = urlsplit(base)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError(f"invalid --base {base!r} (expected https://host[:port])")
    ctx = None
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        if insecure or u.hostname in ("127.0.0.1", "localhost", "::1"):
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE

    def fetch(path, agent):
        if u.scheme == "https":
            conn = http.client.HTTPSConnection(u.hostname, u.port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
        t0 = time.monotonic()
        try:
            conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", host or u.netloc)
            conn.putheader("User-Agent", user_agent or agent or "fobots-replay")
            conn.putheader("Accept", "*/*")
            conn.putheader("Connection", "close")
            conn.endheaders()
            resp = conn.getresponse()
            body = resp.read(MAX_BODY)
            return resp.status, len(body), time.monotonic() - t0
        finally:
            conn.close()
    return fetch



class Replay:
    """The replay itself. It stops, finishing the requests in flight, when: the median response
    time of the last 20 requests reaches `stop_latency`; or `stop_errors` of the last 50 failed
    (no answer, 5xx); or the probe page (optional) takes `stop_latency`; or `max_inflight`
    requests wait for an answer (the server no longer follows)."""

    def __init__(self, window, fetch, speeds=DEFAULT_SPEEDS, step=180.0, stop_latency=3.0,
                 stop_errors=0.2, max_inflight=100, timeout=20.0, probe=None, out=None, say=print):
        self.window, self.fetch, self.speeds, self.step = window, fetch, list(speeds), step
        self.stop_latency, self.stop_errors = stop_latency, stop_errors
        self.max_inflight, self.timeout, self.probe, self.out, self.say = max_inflight, timeout, probe, out, say
        self.lock, self.halted = threading.Lock(), threading.Event()
        self.reason = None
        self.inflight = 0
        self.recent = collections.deque(maxlen=RECENT)
        self.results = []
        self.probe_last = self.probe_max = 0.0

    def write(self, entry):
        if self.out:
            with open(self.out, "a") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")

    def halt(self, reason):
        if not self.halted.is_set():
            self.reason = reason
            self.halted.set()
            self.say(f"STOP: {reason}")

    def check(self):
        with self.lock:
            recent = list(self.recent)
            inflight = self.inflight
        if len(recent) >= MEDIAN_OVER:
            med = statistics.median(d for d, _ in recent[-MEDIAN_OVER:])
            if med >= self.stop_latency:
                self.halt(f"median response time {med:.1f} s over the last {MEDIAN_OVER} requests")
        if len(recent) >= MIN_JUDGED:
            bad = sum(f for _, f in recent) / len(recent)
            if bad >= self.stop_errors:
                self.halt(f"{100 * bad:.0f} % of the last {len(recent)} requests failed")
        if self.probe and self.probe_last >= self.stop_latency:
            self.halt(f"the probe page takes {self.probe_last:.1f} s")
        if inflight >= self.max_inflight:
            self.halt(f"{inflight} requests waiting for an answer: the server no longer follows")

    def work(self, stage, when, rq):
        t0 = time.monotonic()
        err = None
        try:
            status, nbytes, seconds = self.fetch(rq.path, rq.agent)
        except socket.timeout:
            status, nbytes, seconds, err = None, 0, time.monotonic() - t0, "timeout"
        except (OSError, http.client.HTTPException) as e:
            status, nbytes, seconds, err = None, 0, time.monotonic() - t0, type(e).__name__
        with self.lock:
            self.inflight -= 1
            self.recent.append((seconds, status is None or status >= 500))
            self.results.append({"kind": "req", "s": stage, "t": round(when, 2), "k": dir_key(rq.path),
                                 "p": rq.path[:200], "ls": rq.status, "lb": rq.size, "st": status,
                                 "b": nbytes, "d": round(seconds, 3), "e": err})

    def watch_probe(self):
        while not self.halted.wait(5.0):
            try:
                self.probe_last = self.probe.measure()
                self.probe_max = max(self.probe_max, self.probe_last)
            except (OSError, ValueError):
                pass

    def run(self):
        self.write({"kind": "run", "t": round(time.time(), 1), "speeds": self.speeds, "step": self.step,
                    "window": [self.window[0].ts, self.window[-1].ts, len(self.window)],
                    "stop_latency": self.stop_latency})
        if self.probe:
            threading.Thread(target=self.watch_probe, daemon=True).start()
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_inflight + 8)
        try:
            for n, speed in enumerate(self.speeds, 1):
                if self.halted.is_set():
                    break
                self.stage(pool, n, speed)
        finally:
            self.halted.set()  # also ends the probe thread
            pool.shutdown(wait=True)
            self.write({"kind": "stop" if self.reason else "end", "reason": self.reason})
        return self.reason

    def stage(self, pool, n, speed):
        plan = schedule(self.window, speed, self.step)
        self.say(f"stage {n}/{len(self.speeds)}: x{speed:g}, {len(plan) / self.step:.1f} requests/s "
                 f"for {self.step:.0f} s")
        start, last_check, sent = time.monotonic(), 0.0, 0
        with self.lock:
            self.results = []
            self.recent.clear()
        self.probe_max = 0.0
        for when, rq in plan:
            delay = start + when - time.monotonic()
            if delay > 0 and self.halted.wait(delay):
                break
            if self.halted.is_set():
                break
            with self.lock:
                self.inflight += 1
            pool.submit(self.work, n, when, rq)
            sent += 1
            if when - last_check >= 1.0:
                last_check = when
                self.check()
        elapsed = time.monotonic() - start
        if not self.halted.is_set():
            elapsed = max(elapsed, self.step)  # the log window can end before the stage does
        deadline = time.monotonic() + self.timeout * 1.2
        while time.monotonic() < deadline:  # the requests in flight finish
            with self.lock:
                if not self.inflight:
                    break
            time.sleep(0.05)
        self.check()
        with self.lock:
            done = list(self.results)
        for r in done:
            self.write(r)
        st = stage_stats(done)
        self.write({"kind": "stage", "s": n, "speed": speed, "sent": sent, "seconds": round(elapsed, 1),
                    "probe_max": round(self.probe_max, 2) if self.probe else None})
        self.say(f"  sent {sent} ({sent / max(elapsed, 1e-9):.1f}/s), {st['text']}"
                 + (f", probe up to {self.probe_max:.1f} s" if self.probe else ""))



# statistics and report --------------------------------------------------------------------

def failed(r):
    return r["st"] is None or r["st"] >= 500



def faithful(r):
    """Same status as in the log (a page refused or redirected now is cheaper than the real one)."""
    return r["st"] == r["ls"]



def stage_stats(rs):
    if not rs:
        return {"n": 0, "text": "no answer"}
    ok = [r["d"] for r in rs if r["st"] is not None]
    bad = sum(failed(r) for r in rs)
    same = sum(faithful(r) for r in rs)
    if ok:
        med, p95, mx = summarize(ok)
        text = f"median {med:.2f} s, p95 {p95:.2f} s, max {mx:.2f} s"
    else:
        med = p95 = mx = None
        text = "no response"
    text += f", {100 * bad / len(rs):.0f} % failed, {100 * same / len(rs):.0f} % same status as in the log"
    return {"n": len(rs), "med": med, "p95": p95, "max": mx, "failed": bad / len(rs),
            "same": same / len(rs), "text": text}



def read_results(path):
    out = []
    with open(path) as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out



def report(path, out=print, top=10):
    recs = read_results(path)
    runs = [r for r in recs if r.get("kind") == "run"]
    if not runs:
        out(f"{path}: no replay recorded")
        return 1
    run = runs[-1]
    recs = recs[recs.index(run):]
    stages = [r for r in recs if r.get("kind") == "stage"]
    reqs = [r for r in recs if r.get("kind") == "req"]
    end = next((r for r in recs if r.get("kind") in ("stop", "end")), None)
    w = run["window"]
    out(f"{path}: window of {w[1] - w[0] + 1:.0f} s of the log, {w[2]} requests, replayed at x"
        + ", x".join(f"{s:g}" for s in run["speeds"]) + f" for {run['step']:.0f} s each")
    out(f"\n  {'stage':<8}{'req/s':>7}{'requests':>10}{'median':>9}{'p95':>8}{'max':>8}{'failed':>8}"
        f"{'same status':>13}{'probe max':>11}")
    for st in stages:
        rs = [r for r in reqs if r["s"] == st["s"]]
        s = stage_stats(rs)
        if not s["n"] or s["med"] is None:
            out(f"  x{st['speed']:<7g}{st['sent'] / max(st['seconds'], 1e-9):>7.1f}{st['sent']:>10}   no response")
            continue
        probe = "" if st.get("probe_max") is None else f"{st['probe_max']:.1f} s"
        out(f"  x{st['speed']:<7g}{st['sent'] / max(st['seconds'], 1e-9):>7.1f}{s['n']:>10}{s['med']:>8.2f}s"
            f"{s['p95']:>7.2f}s{s['max']:>7.1f}s{100 * s['failed']:>7.0f}%{100 * s['same']:>12.0f}%{probe:>11}")
    if end and end.get("reason"):
        out(f"\nStopped: {end['reason']}.")
    held = [st for st in stages if not (end and end.get("reason") and st is stages[-1])]
    if held:
        top_st = held[-1]
        out(f"Held up to x{top_st['speed']:g} ({top_st['sent'] / max(top_st['seconds'], 1e-9):.1f} requests/s "
            "replayed, on top of the real traffic).")
    elif end and end.get("reason"):
        out("The first stage was already too much.")
    first, final = (stages[0]["s"], stages[-1]["s"]) if stages else (None, None)
    byk = collections.defaultdict(list)
    for r in reqs:
        byk[r["k"]].append(r)
    out(f"\nCost by type of request (first stage -> last stage, the {top} with the highest p95 of the last stage):")
    out(f"  {'directory':<34}{'requests':>9}{'p95 first':>11}{'p95 last':>10}{'same status':>13}")
    rows = []
    for k, rs in byk.items():
        a = [r["d"] for r in rs if r["s"] == first and r["st"] is not None]
        b = [r["d"] for r in rs if r["s"] == final and r["st"] is not None]
        if len(b) < 3:
            continue
        rows.append((summarize(b)[1], k, len(rs), summarize(a)[1] if len(a) >= 3 else None,
                     sum(faithful(r) for r in rs) / len(rs)))
    for p95, k, n, p95a, same in sorted(rows, reverse=True)[:top]:
        out(f"  {k[:33]:<34}{n:>9}{('-' if p95a is None else f'{p95a:.2f} s'):>11}{p95:>9.2f}s{100 * same:>12.0f}%")
    odd = collections.Counter((r["ls"], r["st"]) for r in reqs if not faithful(r))
    if odd:
        total = sum(odd.values())
        out(f"\nNot faithful: {total} of {len(reqs)} requests ({100 * total / len(reqs):.0f} %) got another status "
            "than in the log; the most frequent (logged -> now):")
        for (ls, st), n in odd.most_common(5):
            out(f"  {ls} -> {st if st is not None else 'no answer'}: {n}")
        out("These are probably requests refused or redirected for lack of a session: cheaper than the real "
            "ones, so the load measured is a lower bound.")
    else:
        out("\nEvery request got the status it had in the log.")
    sizes = [r for r in reqs if r["st"] == 200 and r["ls"] == 200 and r["lb"]]
    if sizes:
        far = sum(abs(r["b"] - r["lb"]) > SIZE_TOLERANCE * r["lb"] for r in sizes)
        out(f"Size: {100 * (len(sizes) - far) / len(sizes):.0f} % of the 200 answers within "
            f"{100 * SIZE_TOLERANCE:.0f} % of the logged size (compression and session can make it differ).")
    return 0

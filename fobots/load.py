# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Server load measurement for load-based hardening."""
import http.client
import logging
import os
import re
import socket
import ssl
import statistics
import threading
import time
from urllib.parse import urlsplit

log = logging.getLogger("fobots")


LOAD_DEFAULTS = {"psi": (20.0, 50.0), "loadavg": (1.0, 2.0), "probe": (1.0, 3.0)}  # (tense, critical)

SIGNALS = ("none", "psi", "loadavg", "probe")

UNITS = {"probe": " s"}

PROBE_FAILS = 3           # consecutive failures before an unreachable service counts as critical

PROBE_MAX_BODY = 1 << 20  # bytes read from the page (the whole response time is measured)

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



def parse_probe_urls(text):
    """[(Host header or None, url)] from `URL` or `HOST@URL` entries separated by spaces/commas."""
    targets = []
    for entry in re.split(r"[,\s]+", (text or "").strip()):
        if not entry:
            continue
        host, sep, rest = entry.partition("@")
        if not sep or "://" in host:  # no `HOST@`: the whole entry is the URL
            host, rest = None, entry
        if urlsplit(rest).scheme not in ("http", "https") or not urlsplit(rest).hostname:
            raise ValueError(f"invalid probe URL {entry!r} (expected [HOST@]http://127.0.0.1/path)")
        targets.append((host, rest))
    return targets



class Probe:
    """The load signal 'probe': response time (s) of the service itself, the worst of the URLs.

    One GET per URL and per measure. A timeout counts as `timeout` seconds; a connection error
    or an HTTP 5xx keeps the previous value, and only counts as critical after PROBE_FAILS
    consecutive failures (an incident of a second is not a critical load)."""

    def __init__(self, targets, timeout=10.0, critical=3.0):
        self.targets, self.timeout, self.critical = list(targets), timeout, critical
        self.fails, self.last = {}, {}

    def fetch(self, host, url):
        """(HTTP status, seconds for the whole response); socket errors are raised."""
        u = urlsplit(url)
        ctx = None
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            if u.hostname in ("127.0.0.1", "localhost", "::1"):  # certificate of the vhost name
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = http.client.HTTPSConnection(u.hostname, u.port, timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(u.hostname, u.port, timeout=self.timeout)
        t0 = time.monotonic()
        try:
            conn.putrequest("GET", (u.path or "/") + (f"?{u.query}" if u.query else ""),
                            skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", host or u.netloc)
            conn.putheader("User-Agent", "fobots-probe")
            conn.putheader("Connection", "close")
            conn.endheaders()
            resp = conn.getresponse()
            resp.read(PROBE_MAX_BODY)
            return resp.status, time.monotonic() - t0
        finally:
            conn.close()

    def measure(self, strict=False):
        """Worst response time (s). strict (startup check): any failure, or a status other than
        2xx (redirection, 404: the measured time would mean nothing), raises OSError."""
        worst = 0.0
        for host, url in self.targets:
            try:
                status, seconds = self.fetch(host, url)
                if strict and not 200 <= status < 300:
                    raise OSError(f"{url}: HTTP {status} (the probe needs a page answering 2xx)")
                failed = status >= 500
            except socket.timeout:
                status, seconds, failed = None, self.timeout, False  # very slow: its own signal
            except (OSError, http.client.HTTPException) as e:
                if strict:
                    raise OSError(f"{url}: {e}") from e
                status, seconds, failed = None, 0.0, True
            if failed:
                n = self.fails[url] = self.fails.get(url, 0) + 1
                if n == PROBE_FAILS:
                    log.warning("probe %s: %d consecutive failures (HTTP %s): counted as critical",
                                url, n, status or "no answer")
                seconds = max(self.timeout, self.critical) if n >= PROBE_FAILS \
                    else self.last.get(url, 0.0)
            else:
                if self.fails.get(url):
                    log.info("probe %s: answers again", url)
                self.fails[url] = 0
                self.last[url] = seconds
            worst = max(worst, seconds)
        return worst



def summarize(samples):
    """(median, p95, maximum) of a list of seconds."""
    s = sorted(samples)
    return statistics.median(s), s[min(len(s) - 1, int(0.95 * len(s)))], s[-1]



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
        return f"{self.signal}={self.value:.2f}{UNITS.get(self.signal, '')}, level {LEVELS[self.level]} (x{self.factor:g})"

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

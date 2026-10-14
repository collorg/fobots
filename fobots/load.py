# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Server load measurement for load-based hardening."""
import logging
import os
import threading
import time

log = logging.getLogger("fobots")


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

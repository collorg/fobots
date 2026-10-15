# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Targets: one log per virtual host, with its own exclusion rules."""
import re


class Site:
    """A target: a log (one per virtual host) and its rules excluding requests from the count.
    A host reachable under several names (CNAME) has a single log, hence a single target."""

    def __init__(self, name, log_path, regex=None, all=False, watch=None):
        self.name, self.log, self.all = name, log_path, all
        self.regex = re.compile(regex) if regex else None
        # (agent regex or None, path regex or None) of this target; overrides the global one
        self.watch = (re.compile(watch[0]) if watch[0] else None,
                      re.compile(watch[1]) if watch[1] else None) if watch and any(watch) else None
        self.lines = self.ignored = 0  # statistics (SIGUSR1)

    @property
    def has_path_rules(self):
        return self.regex is not None

    def ignores(self, path):
        return self.regex is not None and self.regex.search(path) is not None

    def describe(self):
        if self.all:
            return "everything is excluded"
        parts = []
        if self.regex:
            parts.append(f"regex {self.regex.pattern!r}")
        if self.watch:
            parts.append(f"watch agent={self.watch[0] and self.watch[0].pattern!r} "
                         f"path={self.watch[1] and self.watch[1].pattern!r}")
        return "; ".join(parts) or "no exclusion of its own"

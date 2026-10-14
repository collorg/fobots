# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Targets: one log per virtual host, with its own exclusion rules."""
import re


class Site:
    """A target: a log (one per virtual host) and its rules excluding requests from the count.
    A host reachable under several names (CNAME) has a single log, hence a single target."""

    def __init__(self, name, log_path, prefixes=(), regex=None, all=False):
        self.name, self.log, self.all = name, log_path, all
        self.prefixes = tuple(prefixes)
        self.regex = re.compile(regex) if regex else None
        self.lines = self.ignored = 0  # statistics (SIGUSR1)

    @property
    def has_path_rules(self):
        return bool(self.prefixes or self.regex)

    def ignores(self, path):
        if self.prefixes and path.startswith(self.prefixes):
            return True
        return self.regex is not None and self.regex.search(path) is not None

    def describe(self):
        if self.all:
            return "everything is excluded"
        parts = []
        if self.prefixes:
            parts.append("prefixes " + ", ".join(self.prefixes))
        if self.regex:
            parts.append(f"regex {self.regex.pattern!r}")
        return "; ".join(parts) or "no exclusion of its own"

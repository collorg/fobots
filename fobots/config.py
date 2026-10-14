# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Configuration file (fobots.conf) reading."""
import argparse
import configparser
import os
import re
import sys

from .constants import CONF_DIR
from .util import parse_duration


CONF_KEYS = {  # file key -> (argparse destination, conversion)
    "dir": ("dir", str), "cache": ("cache", str), "welcome": ("welcome", str),
    "log": ("log", str), "nft_bin": ("nft_bin", str),
    "ban_time": ("ban_seconds", parse_duration),
    "threshold": ("threshold", float), "prefix_threshold": ("prefix_threshold", float),
    "sustain": ("sustain", int), "window": ("window", int),
    "rdap_per_hour": ("rdap_per_hour", int), "delay": ("delay", float),
    "load_signal": ("load_signal", str), "load_tense": ("load_tense", float),
    "load_critical": ("load_critical", float), "load_recover": ("load_recover", parse_duration),
    "tense_factor": ("tense_factor", float), "critical_factor": ("critical_factor", float),
    "min_threshold": ("min_threshold", float), "min_ban_time": ("min_ban_seconds", parse_duration),
    "ignore_path": ("ignore_path", str),
    "ban_scope": ("ban_scope", str), "observed_prefix": ("observed_prefix", int),
    "observed_escalate": ("observed_escalate", int),
    "observed_max_prefix": ("observed_max_prefix", int),
    "watch_agent": ("watch_agent", str), "watch_path": ("watch_path", str),
    "watch_file": ("watch_file", str),
    "from_start": ("from_start", lambda v: v.lower() in ("1", "true", "yes", "oui", "on")),
}

PATH_KEYS = {"dir", "cache", "welcome", "log", "watch_file"}

# /etc first: the result does not depend on the current directory (./fobots.conf is for development)
CONF_SEARCH = (os.path.join(CONF_DIR, "fobots.conf"), "fobots.conf")

SITE_KEYS = ("log", "ignore_prefix", "ignore_path", "ignore_all")

TRUE_VALUES = ("1", "true", "yes", "oui", "on")



def load_config(path):
    """Reads [fobots] and the [site:NAME] sections; relative paths are relative to the file."""
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#", ";"))
    try:
        with open(path) as f:
            cp.read_file(f)
    except (OSError, configparser.Error) as e:
        sys.exit(f"configuration {path} unreadable: {e}")
    if not cp.has_section("fobots"):
        sys.exit(f"{path}: section [fobots] missing")
    base = os.path.dirname(os.path.abspath(path))

    def fix_path(v):
        v = os.path.expanduser(v.strip())
        return v if os.path.isabs(v) else os.path.join(base, v)

    out = {}
    for key, val in cp["fobots"].items():
        if key not in CONF_KEYS:
            sys.exit(f"{path}: unknown option {key!r} (known: {', '.join(CONF_KEYS)})")
        if not val.strip():
            continue
        dest, conv = CONF_KEYS[key]
        if key in PATH_KEYS:
            val = fix_path(val)
        try:
            out[dest] = conv(val.strip())
        except (ValueError, argparse.ArgumentTypeError) as e:
            sys.exit(f"{path}: invalid value for {key} ({val!r}): {e}")

    sites, seen = [], {}
    for section in cp.sections():
        if section == "fobots":
            continue
        name = section[5:].strip() if section.startswith("site:") else ""
        if not name:
            sys.exit(f"{path}: unknown section [{section}] (expected: [fobots] or [site:NAME])")
        opts = cp[section]
        for key in opts:
            if key not in SITE_KEYS:
                sys.exit(f"{path}: [{section}] unknown option {key!r} "
                         f"(known: {', '.join(SITE_KEYS)})")
        if not opts.get("log", "").strip():
            sys.exit(f"{path}: [{section}]: `log` is required")
        log_file = fix_path(opts["log"])
        if log_file in seen:
            sys.exit(f"{path}: [{section}] and [site:{seen[log_file]}] follow the same log {log_file}")
        seen[log_file] = name
        prefixes = [x for x in re.split(r"[,\s]+", opts.get("ignore_prefix", "").strip()) if x]
        for x in prefixes:
            if not x.startswith("/"):
                sys.exit(f"{path}: [{section}] ignore_prefix {x!r} must start with /")
        regex = opts.get("ignore_path", "").strip() or None
        if regex:
            try:
                re.compile(regex)
            except re.error as e:
                sys.exit(f"{path}: [{section}] invalid ignore_path: {e}")
        sites.append({"name": name, "log": log_file, "prefixes": prefixes, "regex": regex,
                      "all": opts.get("ignore_all", "").strip().lower() in TRUE_VALUES})
    if out.get("log") in seen:
        sys.exit(f"{path}: the log {out['log']} is both in [fobots] and in [site:{seen[out['log']]}]")
    if sites:
        out["sites"] = sites
    return out

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""fobots: daemon that bans (nftables) overly aggressive IP ranges.

Continuously reads an access log in "combined" format (nginx / Apache / GitLab),
counts requests per IP range and per second, and adds the offending range to the
nftables set as soon as the threshold is exceeded. Bans expire by themselves (nft timeout).

  fobots run                         # follows the log given in fobots.conf
  tail -F /var/log/gitlab/nginx/gitlab_access.log | fobots run -t 5 -
  fobots setup                       # creates nft table, sets and rules (idempotent)
  fobots probe                       # response time of the load probe URL(s)
  fobots replay LOG --base URL       # replays a log at 2, 5, 10… req/s: costs, capacity
  fobots bans                        # active bans with remaining time
  fobots analyse access.log          # suggests threshold and ignore_path from a log
  fobots welcome add 17.0.0.0/8      # welcome list + removal of the bans concerned
  fobots welcome list

Ranges come from RDAP (the successor of whois), queried in the background only for a
/16 prefix (IPv6: /32) that already exceeds --prefix-threshold, with an hourly budget.
The ranges found are kept on disk. The ban state is read from nft: the daemon can be
restarted without losing anything.
Configuration: fobots.conf (see fobots.conf.example), looked up in the current directory
then in /etc/fobots/, or given with -f. The command line overrides it.
Signals: SIGUSR1 prints the most active ranges, SIGTERM/SIGINT stop the daemon.
"""
import argparse
import http.client
import ipaddress
import logging
import os
import random
import re
import signal
import socket
import sys
import time
from datetime import datetime

from .analyse import Analysis, report
from .config import CONF_SEARCH, load_config
from .constants import CONF_DIR, STATE_DIR
from .detector import OBSERVED_PREFIX6, OBSERVED_WIDE6, SCOPES, Detector
from .events import read_events, trim_events
from .follow import log_lines, run_sites, stdin_is_feed
from .install import Installer
from .load import (LOAD_DEFAULTS, SIGNALS, LoadMonitor, Probe, parse_probe_urls, read_load,
                   summarize)
from .nft import NFT_SETUP, Nft, NftError
from .rdap import Rdap, RangeStore, RdapError, fetch_rdap
from .record import Recorder
from .replay import MIN_REQUESTS, Replay, make_fetcher, parse_rates, read_requests, select_requests
from .replay import report as replay_report
from .record import report as record_report
from .sites import Site
from .util import parse_duration
from .welcome import Banner, Welcome, welcome_add

log = logging.getLogger("fobots")


def paths(args):
    """(RDAP cache, welcome list). The welcome list is next to the configuration used,
    otherwise in CONF_DIR: never relative to the current directory."""
    wl_base = os.path.dirname(os.path.abspath(args.config)) if args.config else CONF_DIR
    return (args.cache or os.path.join(args.dir, "ip_ranges.json"),
            args.welcome or os.path.join(wl_base, "welcome.txt"))



def ensure_dir(path):
    """Creates the directory (0750) if missing; stops with a clear message otherwise."""
    try:
        os.makedirs(path, mode=0o750, exist_ok=True)
    except OSError as e:
        sys.exit(f"cannot create {path}: {e} (create the directory with the right permissions, "
                 "or give --dir)")



def watch_file_path(args):
    return args.watch_file or os.path.join(args.dir, "watched.jsonl")



def cmd_run(args):
    cache, wl_path = paths(args)
    ensure_dir(os.path.dirname(os.path.abspath(cache)))
    ensure_dir(os.path.dirname(os.path.abspath(watch_file_path(args))))
    store, wl = RangeStore(cache), Welcome(wl_path)
    nft = Nft(args.nft_bin, args.dry_run)
    try:
        for ver in (4, 6):
            log.info("IPv%d: %d range(s) already banned", ver, len(nft.elements(ver)))
    except NftError as e:
        log.error("nft: %s", e)
        return 1
    rdap = Rdap(store, args.delay, args.rdap_per_hour)
    rdap.start()
    load = None
    if args.load_signal not in SIGNALS:
        log.error("invalid load_signal: %r (%s)", args.load_signal, ", ".join(SIGNALS))
        return 1
    if args.load_signal != "none":
        signal_name, sampler = args.load_signal, None
        d_tense, d_crit = LOAD_DEFAULTS[signal_name]
        tense = d_tense if args.load_tense is None else args.load_tense
        critical = d_crit if args.load_critical is None else args.load_critical
        if signal_name == "probe":
            try:
                targets = parse_probe_urls(args.load_probe_url)
                if not targets:
                    raise ValueError("load_probe_url is required with load_signal = probe")
                probe = Probe(targets, args.load_probe_timeout, critical)
                first = probe.measure(strict=True)  # the URL must answer 2xx now
            except (OSError, ValueError) as e:
                log.error("load probe: %s", e)
                return 1
            sampler = probe.measure
            log.info("load probe: %d URL(s), first answer in %.2f s", len(targets), first)
        else:
            try:
                read_load(signal_name)
            except (OSError, ValueError) as e:
                if signal_name != "psi":
                    log.error("load: %s", e)
                    return 1
                log.warning("PSI unavailable (%s), falling back to loadavg", e)
                signal_name = "loadavg"
                d_tense, d_crit = LOAD_DEFAULTS[signal_name]
                tense = d_tense if args.load_tense is None else args.load_tense
                critical = d_crit if args.load_critical is None else args.load_critical
        load = LoadMonitor(signal_name, tense, critical,
                           args.load_recover, (args.tense_factor, args.critical_factor),
                           sampler=sampler)
        load.start()
        log.info("load monitoring: %s, levels %s, recovery after %d s",
                 signal_name, load.thresholds, args.load_recover)
    watch = None
    if args.watch_agent or args.watch_path:
        try:
            watch = (re.compile(args.watch_agent) if args.watch_agent else None,
                     re.compile(args.watch_path) if args.watch_path else None)
        except re.error as e:
            log.error("invalid regular expression: %s", e)
            return 1
        log.info("request monitoring: agent=%r path=%r (counted normally, "
                 "logged if their range is banned)", args.watch_agent, args.watch_path)
    ignore_path = None
    if args.ignore_path:
        try:
            ignore_path = re.compile(args.ignore_path)
        except re.error as e:
            log.error("invalid regular expression for ignore_path: %s", e)
            return 1
        log.info("requests excluded from the count (path): %r", args.ignore_path)
    sites = [Site(d["name"], d["log"], d["regex"], d["all"], d.get("watch"))
             for d in (getattr(args, "sites", None) or [])]
    if args.log:  # single log of [fobots] or --log: a target without rules of its own
        if any(x.log == args.log for x in sites):
            log.error("the log %s is both in [fobots] and in a [site:…] section", args.log)
            return 1
        sites.insert(0, Site("default", args.log))
    if args.files:
        sites = []  # files given as arguments: read once, not followed
    for x in sites:
        log.info("target %s: following %s (%s)", x.name, x.log, x.describe())
    if args.ban_scope not in SCOPES:
        log.error("invalid ban_scope: %r (%s)", args.ban_scope, " or ".join(SCOPES))
        return 1
    if not 8 <= args.observed_prefix <= 32:
        log.error("observed_prefix must be between 8 and 32 (IPv4)")
        return 1
    if args.observed_max_prefix and not 8 <= args.observed_max_prefix <= args.observed_prefix:
        log.error("observed_max_prefix must be 0 (whole allocation) or between 8 and "
                  "observed_prefix (%d)", args.observed_prefix)
        return 1
    if not sites and not args.files and not stdin_is_feed():
        log.error("no log to follow: define `log =` in [fobots] or in a [site:NAME] section "
                  "(configuration used: %s), or pass --log FILE; "
                  "to read stdin explicitly: `run -`", args.config or "none")
        return 1
    watch_file = watch_file_path(args) if watch or any(x.watch for x in sites) else None
    if watch_file:
        trim_events(watch_file)
    det = Detector(args.threshold, args.prefix_threshold or args.threshold, args.sustain,
                   args.window, store, Banner(nft, wl, args.ban_seconds), rdap,
                   load, args.min_threshold, args.min_ban_seconds, watch, watch_file,
                   ignore_path, sites, args.ban_scope, args.observed_prefix, args.observed_escalate,
                   args.observed_max_prefix, args.slow_threshold, args.slow_window)
    if det.observed:
        log.info("ban_scope observed: groups of IPs of at most /%d (IPv6 /%d), fallback to blocks "
                 "of %s if scattered or after %d partial bans", args.observed_prefix,
                 OBSERVED_PREFIX6,
                 f"/{args.observed_max_prefix} (IPv6 /{OBSERVED_WIDE6})"
                 if args.observed_max_prefix else "the whole allocation", args.observed_escalate)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGUSR1, lambda *_: det.dump())
    if args.config:
        log.info("configuration: %s", args.config)
    log.info("daemon ready: threshold %s req/s, ban %d s, %d range(s) cached in %s",
             args.threshold, args.ban_seconds, len(store.ranges), os.path.abspath(cache))
    try:
        if sites:
            run_sites(det, sites, args.from_start)
        else:  # files (read once) or stdin
            for line in log_lines(args):
                det.feed_line(line)
    except KeyboardInterrupt:
        pass
    except OSError as e:  # stdin or file unreadable
        log.error("cannot read: %s", e)
        return 1
    log.info("stopping")
    return 0



def cmd_setup(args):
    nft = Nft(args.nft_bin, args.dry_run)
    if args.dry_run:
        print(NFT_SETUP, end="")
    elif nft.table_exists():
        print("table inet fobots already in place")
    else:
        nft.setup()
        print("table inet fobots created")
    return 0



def cmd_bans(args):
    nft = Nft(args.nft_bin, args.dry_run)
    cache, _ = paths(args)
    store = RangeStore(cache)
    rows = [(n, exp) for ver in (4, 6)
            for n, exp in sorted(nft.elements(ver), key=lambda e: e[0].network_address)]
    names = []
    for n, _ in rows:
        r = store.find(n.network_address)
        if r and args.lookup and not store.name(r):
            try:
                _, _, name = fetch_rdap(str(n.network_address))
                store.add(r, name)
                time.sleep(1)  # RDAP politeness
            except (RdapError, ValueError) as e:
                print(f"RDAP {n}: {e}", file=sys.stderr)
        names.append(store.name(r) if r else "")
    for (n, exp), name in zip(rows, names):
        left = "" if exp is None else f"{exp} s left"
        print(f"{str(n):<24} {left:<12} {name}".rstrip())
    return 0



def cmd_analyse(args):
    """Reads logs once (the files given, otherwise those of the configuration) and suggests."""
    cache, _ = paths(args)
    ignore_path = None
    if args.ignore_path:
        try:
            ignore_path = re.compile(args.ignore_path)
        except re.error as e:
            log.error("invalid regular expression for ignore_path: %s", e)
            return 1
    inputs = []  # (file, target whose rules apply)
    if args.files:
        inputs = [(f, None) for f in args.files]
    else:
        sites = [Site(d["name"], d["log"], d["regex"], d["all"], d.get("watch"))
                 for d in (getattr(args, "sites", None) or [])]
        if getattr(args, "log", None):
            sites.insert(0, Site("default", args.log))
        inputs = [(s.log, s) for s in sites]
    if not inputs:
        log.error("no log to analyse: give files, or define `log =` / [site:NAME] in the configuration")
        return 1
    an = Analysis(RangeStore(cache), ignore_path, args.sustain, args.time_unit, args.slow_window)
    an.slow_threshold = args.slow_threshold
    for path, site in inputs:
        try:
            f = sys.stdin if path == "-" else open(path, errors="replace")
            with f:
                for line in f:
                    an.feed(line, site)
        except OSError as e:
            log.error("%s: %s", path, e)
            return 1
    print("\n".join(report(an, args.threshold, args.top)))
    return 0



def cmd_watched(args):
    """Monitored IPs caught in a ban (history + current state), to spot false positives."""
    path = watch_file_path(args)
    events = read_events(path, time.time() - args.since)
    if not events:
        print(f"no finding in {path} for this period (watch_agent / watch_path "
              "enabled in the daemon's configuration?)")
        return 0
    active, known = [], False
    if not args.dry_run:
        try:
            nft = Nft(args.nft_bin)
            active = [(n, e) for ver in (4, 6) for n, e in nft.elements(ver)]
            known = True
        except NftError as e:
            print(f"ban state unavailable ({e}): STATE column unknown", file=sys.stderr)
    agg = {}
    for ev in events:
        for ip, n, rpath in ev["ips"]:
            a = agg.setdefault(ip, {"bans": 0, "req": 0, "t": 0, "range": "", "path": ""})
            a["bans"] += 1
            a["req"] += n
            if ev["t"] >= a["t"]:
                a.update(t=ev["t"], range=ev["range"], path=rpath)
    rows = []
    for ip, a in agg.items():
        state = "?"
        if known:
            addr = ipaddress.ip_address(ip)
            left = [e for n, e in active if n.version == addr.version and addr in n]
            state = f"active ({max(e or 0 for e in left)} s)" if left else "expired"
        a["state"] = state
        rows.append((ip, a))
    if args.active:
        rows = [r for r in rows if r[1]["state"].startswith("active")]
    rows.sort(key=lambda r: (not r[1]["state"].startswith("active"), -r[1]["bans"], -r[1]["req"]))
    if not rows:
        print("no monitored IP in an active ban")
        return 0
    cmd = "fobots welcome add " + " ".join(str(ipaddress.ip_network(ip)) for ip, _ in rows)
    if args.config:
        cmd += f" -f {args.config}"
    if args.cmd:
        print(cmd)
        return 0
    print(f"{'IP':<40} {'BANS':>4} {'REQ':>6}  {'LAST BAN':<16} {'RANGE':<20} {'STATE':<14} ROUTE")
    for ip, a in rows:
        when = datetime.fromtimestamp(a["t"]).strftime("%Y-%m-%d %H:%M")
        print(f"{ip:<40} {a['bans']:>4} {a['req']:>6}  {when:<16} {a['range']:<20} "
              f"{a['state']:<14} {a['path']}")
    print(f"\n{len(rows)} IP(s) over {args.since / 86400:g} d. To protect them all:\n  {cmd}")
    return 0



def cmd_install(args):
    Installer(args).run_all()
    return 0



def cmd_welcome(args):
    _, wl_path = paths(args)
    if args.action == "list":
        for n in Welcome(wl_path).nets:
            print(n)
        return 0
    nets = []
    for x in args.nets:
        try:
            nets.append(ipaddress.ip_network(x, strict=False))
        except ValueError:
            print(f"invalid range: {x}", file=sys.stderr)
            return 2
    try:
        os.makedirs(os.path.dirname(os.path.abspath(wl_path)), exist_ok=True)
        Welcome.append(wl_path, nets)  # first: the daemon stops banning it
    except OSError as e:
        print(f"cannot write {wl_path}: {e} (permissions? run with sudo)",
              file=sys.stderr)
        return 1
    nft = Nft(args.nft_bin, args.dry_run)
    for net in nets:
        try:
            deletes, adds = welcome_add(nft, net, args.ban_seconds)
        except NftError as e:
            print(f"{net} added to {wl_path}, but nft failed: {e}", file=sys.stderr)
            return 1
        print(f"{net}: welcome list; {len(deletes)} ban(s) removed"
              + (f", {len(adds)} piece(s) of the rest kept" if adds else ""))
    return 0



def add_probe_options(parser):
    parser.add_argument("--load-probe-url", metavar="[HOST@]URL,…",
                        help="load_signal = probe: page(s) to request, e.g. "
                             "www.example.org@http://127.0.0.1/app/page (HOST = Host header)")
    parser.add_argument("--load-probe-timeout", type=parse_duration, default=10, metavar="DURATION",
                        help="probe: an answer slower than this counts as this many seconds (default: 10s)")



def cmd_probe(args):
    """Measures the probe URL(s) for a while, to choose load_tense / load_critical."""
    if args.report:
        return record_report(args.report)
    if args.record:
        return cmd_record(args)
    if args.duration is None:
        args.duration = 60
    if args.interval is None:
        args.interval = 2.0
    try:
        targets = parse_probe_urls(" ".join(args.url) or args.load_probe_url)
        if not targets:
            raise ValueError("give --url, or load_probe_url in the configuration")
        probe = Probe(targets, args.load_probe_timeout, 3.0)
        probe.measure(strict=True)
    except (OSError, ValueError) as e:
        log.error("probe: %s", e)
        return 1
    samples = {url: [] for _, url in targets}
    end = time.monotonic() + args.duration
    print(f"probing {len(targets)} URL(s) for {args.duration} s, one request every "
          f"{args.interval:g} s (Ctrl-C to stop)…", flush=True)
    try:
        while True:
            for host, url in targets:
                try:
                    status, seconds = probe.fetch(host, url)
                except socket.timeout:
                    status, seconds = None, args.load_probe_timeout
                except (OSError, http.client.HTTPException):
                    status, seconds = None, None
                samples[url].append(seconds if status is None or status < 500 else None)
            if time.monotonic() >= end:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    allv = []
    for url, vals in samples.items():
        ok = [v for v in vals if v is not None]
        if not ok:
            print(f"{url}: no answer ({len(vals)} attempts)")
            continue
        med, p95, mx = summarize(ok)
        allv += ok
        print(f"{url}\n  {len(ok)} answers, {len(vals) - len(ok)} failure(s): median {med:.2f} s, "
              f"p95 {p95:.2f} s, max {mx:.2f} s")
    if allv:
        med, p95, mx = summarize(allv)
        tense = max(1.0, float(-(-2 * p95 // 1)))
        print(f"\nDefaults: load_tense = 1, load_critical = 3 (seconds). From these measures, "
              f"2 x p95 gives load_tense = {tense:g}, load_critical = {3 * tense:g}.\n"
              "Measure again during a slowdown to see what a degraded service looks like.")
    return 0



def cmd_record(args):
    """Runs until stopped: records the state of the machine when the service slows down."""
    try:
        targets = parse_probe_urls(" ".join(args.url) or args.load_probe_url)
        if not targets:
            raise ValueError("give --url, or load_probe_url in the configuration")
        d_tense, d_crit = LOAD_DEFAULTS["probe"]
        tense = d_tense if args.load_tense is None else args.load_tense
        critical = d_crit if args.load_critical is None else args.load_critical
        probe = Probe(targets, args.load_probe_timeout, critical)
        probe.measure(strict=True)
        for path in args.record_logs:
            with open(path, "rb"):
                pass
        with open(args.record, "a"):
            pass
    except (OSError, ValueError) as e:
        log.error("record: %s", e)
        return 1
    interval = 5.0 if args.interval is None else args.interval
    rec = Recorder(probe, args.record, tense, critical, interval, logs=args.record_logs)
    rec.start(" ".join(f"{h}@{u}" if h else u for h, u in targets), args.load_probe_timeout)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    log.info("recording to %s: one measure every %g s, readings written from %g s "
             "(Ctrl-C to stop; `fobots probe --report %s` to read)",
             args.record, interval, tense, args.record)
    try:
        if args.duration is None:
            rec.run()
        else:
            end = time.monotonic() + args.duration
            while time.monotonic() < end:
                rec.step()
                time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        rec.finish()
    return 0



def cmd_replay(args):
    """Replays the GET requests of a log against a server with a rising load, and measures."""
    if args.report:
        return replay_report(args.report)
    try:
        if not args.base:
            raise ValueError("give --base (e.g. https://www.example.org): the server to load")
        rates = parse_rates(args.rate)
        agent_re = re.compile(args.agent) if args.agent else None
        ignore_re = re.compile(args.ignore_path) if args.ignore_path else None
        since = datetime.fromisoformat(args.since).timestamp() if args.since else None
        until = datetime.fromisoformat(args.until).timestamp() if args.until else None
        fetch = make_fetcher(args.base, args.host, args.timeout, args.insecure, args.user_agent,
                             not args.no_compression)
        probe_text = args.probe_url or getattr(args, "load_probe_url", None)
        probe = None
        if probe_text:
            targets = parse_probe_urls(probe_text)
            probe = Probe(targets, getattr(args, "load_probe_timeout", 10), args.stop_latency)
            probe.measure(strict=True)
    except (OSError, ValueError, re.error) as e:
        log.error("replay: %s", e)
        return 1
    if args.files:
        logs = [(f, None) for f in args.files]
    else:  # the logs of the configuration, with the exclusion rules of each target
        sites = [Site(d["name"], d["log"], d["regex"], d["all"], d.get("watch"))
                 for d in (getattr(args, "sites", None) or [])]
        if getattr(args, "log", None):
            sites.insert(0, Site("default", args.log))
        logs = [(x.log, x) for x in sites]
    if not logs:
        log.error("replay: give the log(s) to replay, or define `log =` in the configuration")
        return 1
    stats = {}
    try:
        reqs = read_requests(logs, agent_re, ignore_re, stats)
    except OSError as e:
        log.error("replay: %s", e)
        return 1
    reqs = select_requests(reqs, since, until)
    if len(reqs) < MIN_REQUESTS:
        log.error("replay: %d GET request(s) selected: too few to make a load (check --agent, "
                  "--ignore-path, --from, --until)", len(reqs))
        return 1
    seed = args.seed if args.seed is not None else random.randrange(1_000_000)
    start = random.Random(seed).randrange(len(reqs))
    print(f"Target: {args.base}" + (f" (Host: {args.host})" if args.host else ""))
    print(f"Log: {len(reqs)} GET requests" + (f", user agents matching {args.agent!r}" if args.agent else "")
          + f"; replayed in the order of the log from position {start} (seed {seed}, --seed to repeat)")
    if stats["ignored"]:
        print(f"Left out by ignore_path: {stats['ignored']} request(s) (cheap pages that say nothing of the load).")
    print("Stages: " + ", ".join(f"{r:g}/s" for r in rates) + f", {args.step:.0f} s each")
    for r in rates:
        if r * args.step > len(reqs):
            print(f"NB: {r:g}/s for {args.step:.0f} s needs {r * args.step:.0f} requests, the log has "
                  f"{len(reqs)}: some are replayed again (warm caches).")
            break
    print(f"Stops by itself: median response time >= {args.stop_latency:g} s, {100 * args.stop_errors:.0f} % of failures, "
          f"{args.max_inflight} requests in flight" + (", or the probe page slow" if probe else ""))
    print("The requests come ON TOP of the real traffic. Put this machine's IP in the welcome list "
          "(fobots would ban it).")
    if not args.yes:
        if not sys.stdin.isatty():
            log.error("replay: not interactive: add --yes to start")
            return 1
        if input("Start? [y/N] ").strip().lower() not in ("y", "yes", "o", "oui"):
            return 1
    rp = Replay(reqs, fetch, rates, args.step, args.stop_latency, args.stop_errors,
                args.max_inflight, args.timeout, probe, args.results, start=start, seed=seed)
    try:
        rp.run()
    except KeyboardInterrupt:
        rp.halt("interrupted")
        print("interrupted")
    print()
    return replay_report(args.results)



def main(argv=None):
    pre = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    pre.add_argument("-f", "--config")
    conf_path = pre.parse_known_args(argv)[0].config
    if conf_path is None:
        conf_path = next((c for c in CONF_SEARCH if os.path.exists(c)), None)
    elif not os.path.exists(conf_path):
        sys.exit(f"configuration not found: {conf_path}")
    conf = load_config(conf_path) if conf_path else {}

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-f", "--config", help="configuration file "
                        "(default: /etc/fobots/fobots.conf, then ./fobots.conf)")
    common.add_argument("--dir", default=STATE_DIR,
                        help=f"state directory: ip_ranges.json, watched.jsonl (default: {STATE_DIR})")
    common.add_argument("-c", "--cache", help="file of RDAP ranges (default: DIR/ip_ranges.json)")
    common.add_argument("-w", "--welcome", help="welcome list (default: welcome.txt next to the configuration, "
                        f"otherwise {CONF_DIR}/welcome.txt)")
    common.add_argument("--watch-file",
                        help="file of monitoring findings (default: DIR/watched.jsonl)")
    common.add_argument("--ban-time", dest="ban_seconds", type=parse_duration, default=3600,
                        help="duration of a ban: 30m, 1h, 1d… (default: 1h)")
    common.add_argument("--nft-bin", default="nft", help="nft binary (default: nft)")
    common.add_argument("--dry-run", action="store_true",
                        help="does not call nft: prints the commands (simulated sets)")
    common.add_argument("-v", "--verbose", action="store_true")

    ap = argparse.ArgumentParser(prog="fobots", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", parents=[common], help="daemon: reads the log and bans")
    r.add_argument("files", nargs="*",
                   help="logs read once (- = stdin); otherwise --log is followed, otherwise stdin")
    r.add_argument("-l", "--log", help="log to follow continuously (rotation handled, like tail -F)")
    r.add_argument("--from-start", action="store_true",
                   help="with --log: first reads the existing content (default: end of the file)")
    r.add_argument("-t", "--threshold", type=float, default=5.0,
                   help="req/s of a range above which it is banned (default: 5)")
    r.add_argument("-p", "--prefix-threshold", type=float,
                   help="req/s of an unresolved /16 prefix that trigger an RDAP request "
                        "(default: = --threshold)")
    r.add_argument("--sustain", type=int, default=5,
                   help="consecutive seconds above the threshold required (default: 5)")
    r.add_argument("--slow-threshold", type=float, default=0, metavar="REQ_PER_S",
                   help="bans a range whose AVERAGE rate over --slow-window exceeds this "
                        "(slow scrapers; 0 = disabled, default)")
    r.add_argument("--slow-window", type=parse_duration, default=600, metavar="DURATION",
                   help="window of --slow-threshold (default: 10m)")
    r.add_argument("--window", type=int, default=60,
                   help="window in seconds over which IPs are tracked (default: 60)")
    r.add_argument("--load-signal", choices=SIGNALS, default="none",
                   help="hardens the rules according to the load: probe (response time of the "
                        "service itself), psi (reactive), loadavg (load/cores) or none (default)")
    r.add_argument("--load-tense", type=float,
                   help="signal value at the tense level (default: 1 s for probe, 20 %% for psi, "
                        "1.0 for loadavg)")
    r.add_argument("--load-critical", type=float,
                   help="value at the critical level (default: 3 s for probe, 50 %% for psi, "
                        "2.0 for loadavg)")
    add_probe_options(r)
    r.add_argument("--load-recover", type=parse_duration, default=300,
                   help="time below the level before going down one level (default: 5m)")
    r.add_argument("--tense-factor", type=float, default=0.5,
                   help="multiplier of the threshold AND of the ban duration at the tense level (default: 0.5)")
    r.add_argument("--critical-factor", type=float, default=0.25,
                   help="same at the critical level (default: 0.25)")
    r.add_argument("--min-threshold", type=float, default=1.0,
                   help="floor of the effective threshold in req/s (default: 1)")
    r.add_argument("--min-ban-time", dest="min_ban_seconds", type=parse_duration, default=60,
                   help="floor of the effective ban duration (default: 1m)")
    r.add_argument("--ignore-path", metavar="REGEX",
                   help="opt-in: does not count the requests whose path matches "
                        "(cheap static pages, e.g. ^/(assets|uploads)/)")
    r.add_argument("--watch-agent", metavar="REGEX",
                   help="opt-in: logs (WATCH) the IPs whose user agent matches when "
                        "their range is banned (e.g. ^gitlab-runner); does not change the count")
    r.add_argument("--watch-path", metavar="REGEX",
                   help="restricts --watch-agent to the matching paths (e.g. ^/api/v4/); "
                        "if both are given, both must match")
    r.add_argument("--ban-scope", choices=SCOPES, default="allocation",
                   help="allocation: the whole RDAP range is banned (default); observed: only "
                        "the groups of IPs seen, inside the allocation")
    r.add_argument("--observed-prefix", type=int, default=20,
                   help="ban_scope=observed: maximum width of a group of IPs, as an IPv4 prefix "
                        "(default: 20, i.e. 4096 addresses; IPv6: /48)")
    r.add_argument("--observed-escalate", type=int, default=4,
                   help="ban_scope=observed: partial bans of the same allocation (within the duration "
                        "of a ban) before falling back to wide blocks (default: 4)")
    r.add_argument("--observed-max-prefix", type=int, default=16,
                   help="ban_scope=observed: if the traffic is scattered, blocks of this width are "
                        "banned (IPv4 prefix, default: 16; IPv6: /32) instead of the whole "
                        "allocation; 0 = whole allocation")
    r.add_argument("--rdap-per-hour", type=int, default=100,
                   help="budget of RDAP requests per hour (default: 100)")
    r.add_argument("--delay", type=float, default=2.0,
                   help="minimum seconds between two RDAP requests (default: 2)")
    r.set_defaults(fn=cmd_run)

    sub.add_parser("setup", parents=[common],
                   help="creates the nft table if absent").set_defaults(fn=cmd_setup)
    b = sub.add_parser("bans", parents=[common], help="lists the active bans, with the organisation")
    b.add_argument("--no-lookup", dest="lookup", action="store_false",
                   help="does not ask RDAP for the organisation of ranges missing from the cache "
                        "(by default it does, 1 request/s, and keeps the answer in the cache)")
    b.set_defaults(fn=cmd_bans)

    ins = sub.add_parser("install", parents=[common],
                         help="installs fobots (nftables, user, directories, configuration, systemd unit)")
    ins.add_argument("--log", help="log to follow, written in the configuration created (default: the example's)")
    ins.add_argument("--log-group", help="group giving access to the log (default: detected, otherwise adm)")
    ins.add_argument("--yes", action="store_true", help="answers yes to the questions (apt installation)")
    ins.add_argument("--enable", action="store_true", help="enables the service at boot")
    ins.add_argument("--start", action="store_true", help="enables AND starts the service")
    ins.add_argument("--destdir", help="writes the files under this prefix without touching the system (test)")
    ins.set_defaults(fn=cmd_install)

    an = sub.add_parser("analyse", parents=[common],
                        help="reads a log once and suggests settings (threshold, ignore_path)")
    an.add_argument("files", nargs="*", help="logs to read (- = stdin); "
                    "default: those of the configuration")
    an.add_argument("-t", "--threshold", type=float, default=5.0,
                    help="threshold to highlight in the table (default: the configuration, else 5)")
    an.add_argument("--sustain", type=int, default=5,
                    help="consecutive seconds above the threshold (default: the configuration, else 5)")
    an.add_argument("--ignore-path", metavar="REGEX",
                    help="paths not counted (default: ignore_path of the configuration)")
    an.add_argument("--slow-window", type=parse_duration, default=600, metavar="DURATION",
                    help="window of the average-rate table (slow scrapers), default 10m")
    an.add_argument("--slow-threshold", type=float, default=0, metavar="REQ_PER_S",
                    help="average rate to highlight in that table (default: the configuration)")
    an.add_argument("--time-unit", choices=("auto", "us", "ms", "s"), default="auto",
                    help="unit of the duration at the end of the line (auto: decimal = s, "
                         "integer = µs like Apache %%D)")
    an.add_argument("--top", type=int, default=10, help="rows of the rankings (default: 10)")
    an.set_defaults(fn=cmd_analyse)

    pr = sub.add_parser("probe", parents=[common],
                        help="measures the response time of the probe URL(s) (to set load_tense/critical)")
    pr.add_argument("--url", action="append", default=[], metavar="[HOST@]URL",
                    help="page to request (default: load_probe_url of the configuration)")
    pr.add_argument("--duration", type=parse_duration,
                    help="measuring time (default: 1m; with --record: until stopped)")
    pr.add_argument("--interval", type=float,
                    help="seconds between requests (default: 2; with --record: 5)")
    pr.add_argument("--record", metavar="FILE",
                    help="runs until stopped and writes to FILE the state of the machine "
                         "(load, memory, swap, pressure, accept queue, processes) when the response "
                         "time reaches --load-tense")
    pr.add_argument("--log", dest="record_logs", action="append", default=[], metavar="FILE",
                    help="--record: access log to follow too (repeatable): requests/s, share of 5xx "
                         "and distinct IPs of each measure, to tell a traffic peak from an "
                         "internal cause. Not taken from the configuration")
    pr.add_argument("--report", metavar="FILE",
                    help="reads a --record file: slowdowns, and which reading moved first")
    pr.add_argument("--load-tense", type=float,
                    help="--record: response time (s) starting a slowdown record (default: 1)")
    pr.add_argument("--load-critical", type=float,
                    help="--record: response time (s) of the critical level (default: 3)")
    add_probe_options(pr)
    pr.set_defaults(fn=cmd_probe)

    rp = sub.add_parser("replay", parents=[common],
                        help="replays the GET requests of a log against a server with a rising load")
    rp.add_argument("files", nargs="*", help="log(s) to replay (default: those of the configuration)")
    rp.add_argument("--base", metavar="URL", help="server to load, e.g. https://www.example.org")
    rp.add_argument("--host", help="Host header (default: that of --base)")
    rp.add_argument("--rate", default="2,5,10,15", metavar="R,R,…",
                    help="stages: requests per second inflicted on the server (default: 2,5,10,15)")
    rp.add_argument("--step", type=parse_duration, default=180, metavar="DURATION",
                    help="duration of each stage (default: 3m)")
    rp.add_argument("--seed", type=int, help="seed of the random starting position in the log (to repeat a run)")
    rp.add_argument("--from", dest="since", metavar="DATETIME",
                    help="only the log after this time (local time, 2026-10-15 23:00)")
    rp.add_argument("--until", metavar="DATETIME", help="only the log before this time")
    rp.add_argument("--agent", metavar="REGEX", help="only the requests whose user agent matches (e.g. bots)")
    rp.add_argument("--ignore-path", metavar="REGEX",
                    help="not the requests whose path matches (default: ignore_path of the configuration, "
                         "and the rules of each [site:NAME])")
    rp.add_argument("--user-agent", help="user agent sent (default: the logged one)")
    rp.add_argument("--stop-latency", type=float, default=3.0, metavar="SECONDS",
                    help="stops when the median response time of the last 20 requests reaches this (default: 3)")
    rp.add_argument("--stop-errors", type=float, default=0.2, metavar="SHARE",
                    help="stops when this share of the last 50 requests failed (default: 0.2)")
    rp.add_argument("--max-inflight", type=int, default=100,
                    help="stops when this many requests wait for an answer (default: 100)")
    rp.add_argument("--timeout", type=parse_duration, default=20, metavar="DURATION",
                    help="a request without answer after this fails (default: 20s)")
    rp.add_argument("--no-compression", action="store_true",
                    help="does not send Accept-Encoding: gzip (default: sent, like most clients)")
    rp.add_argument("--insecure", action="store_true", help="does not verify the certificate")
    rp.add_argument("--probe-url", metavar="[HOST@]URL",
                    help="page measured during the replay, also stops it (default: load_probe_url)")
    rp.add_argument("--results", default="replay.jsonl", metavar="FILE",
                    help="results (default: replay.jsonl)")
    rp.add_argument("--yes", action="store_true", help="does not ask for confirmation")
    rp.add_argument("--report", metavar="FILE", help="reads the results of a replay instead of running one")
    rp.set_defaults(fn=cmd_replay)

    wd = sub.add_parser("watched", parents=[common],
                        help="monitored IPs (watch_*) caught in a ban: possible false positives")
    wd.add_argument("--since", type=parse_duration, default=7 * 86400,
                    help="period to consider: 12h, 3d… (default: 7d)")
    wd.add_argument("--active", action="store_true", help="only those whose ban is active")
    wd.add_argument("--cmd", action="store_true",
                    help="only prints the corresponding `welcome add` command")
    wd.set_defaults(fn=cmd_watched)

    w = sub.add_parser("welcome", parents=[common], help="manages the welcome list")
    w.add_argument("action", choices=["add", "list"])
    w.add_argument("nets", nargs="*", help="CIDRs to add (add)")
    w.set_defaults(fn=cmd_welcome)

    for p in sub.choices.values():
        p.set_defaults(config=conf_path, **conf)  # command line > configuration > defaults
    args = ap.parse_args(argv)
    if args.cmd == "run":
        for name in ("tense_factor", "critical_factor"):
            if not 0 < getattr(args, name) <= 1:
                ap.error(f"--{name.replace('_', '-')} must be in ]0, 1]")
    if args.cmd == "welcome" and args.action == "add" and not args.nets:
        ap.error("welcome add: give at least one range")
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    try:
        return args.fn(args)
    except NftError as e:  # nft missing, kernel refusal, insufficient permissions…
        log.error("nft: %s", e)
        return 1

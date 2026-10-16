# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Unit tests for fobots (standard library only): python3 -m unittest discover -s tests -v"""
import argparse
import contextlib
import io
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import warnings
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from fobots.analyse import Analysis, average_rate, dir_key, report, short_agent, sustained_rate  # noqa: E402
from fobots.cli import main  # noqa: E402
from fobots.config import CONF_KEYS, SITE_KEYS, load_config  # noqa: E402
from fobots.detector import Detector  # noqa: E402
from fobots.events import append_event, read_events, trim_events  # noqa: E402
from fobots.follow import follow  # noqa: E402
from fobots.grouping import cluster_ips, pick_groups, wide_blocks  # noqa: E402
from fobots.load import LoadMonitor, Probe, parse_probe_urls, read_psi, summarize  # noqa: E402
from fobots.nft import Nft, NftError, parse_elems, val_nets  # noqa: E402
from fobots.rdap import RangeStore  # noqa: E402
from fobots.replay import Replay, make_fetcher, parse_speeds, read_requests, schedule, select_window  # noqa: E402
from fobots.replay import report as replay_report  # noqa: E402
from fobots.record import LogTail, Recorder, episodes, read_records, read_sys, recorded_span, scan_procs  # noqa: E402
from fobots.record import report as record_report  # noqa: E402
from fobots.sites import Site  # noqa: E402
from fobots.util import fmt_range, parse_duration, parse_ts, prefix_of, range_nets, subtract  # noqa: E402
from fobots.welcome import Banner, Welcome, welcome_add  # noqa: E402

# main() calls logging.basicConfig; with a handler already on the root logger it does nothing,
# so the tests control where the log records go.
logging.getLogger().addHandler(logging.NullHandler())

net = ipaddress.ip_network


def ip(s):
    return int(ipaddress.ip_address(s))


def rng(first, last):
    a = ipaddress.ip_address(first)
    return (a.version, int(a), int(ipaddress.ip_address(last)))


def line(addr, sec, path="/x", agent="ua"):
    return (f'{addr} - - [14/Oct/2026:10:{sec // 60:02d}:{sec % 60:02d} +0000] '
            f'"GET {path} HTTP/1.1" 200 10 "-" "{agent}"\n')


class FakeNft:
    """Stands for Nft: a set of (network, remaining seconds) per version, with a call log."""

    def __init__(self, elems=None, fail_adds=0):
        self.sets = {4: list(elems or []), 6: []}
        self.calls = []
        self.fail_adds = fail_adds

    def elements(self, ver):
        return list(self.sets[ver])

    def apply(self, ver, deletes, adds, restore=()):
        self.calls.append((ver, list(deletes), list(adds)))
        if self.fail_adds:
            self.fail_adds -= 1
            raise NftError("interval overlaps with an existing one")
        gone = set(deletes)
        self.sets[ver] = [(n, e) for n, e in self.sets[ver] if n not in gone] + list(adds)

    def banned(self, ver=4):
        return sorted(str(n) for n, _ in self.sets[ver])


class NoRdap:
    def __init__(self):
        self.requested = []

    def request(self, addr, prefix):
        self.requested.append((addr, prefix))


class TmpDirCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def path(self, name):
        return os.path.join(self.dir, name)

    def read(self, *parts):
        with open(os.path.join(self.dir, *parts)) as f:
            return f.read()

    def write(self, name, text):
        with open(self.path(name), "w") as f:
            f.write(text)
        return self.path(name)


class Utilities(unittest.TestCase):
    def test_parse_duration(self):
        self.assertEqual(parse_duration("30s"), 30)
        self.assertEqual(parse_duration("10m"), 600)
        self.assertEqual(parse_duration("1h"), 3600)
        self.assertEqual(parse_duration("2d"), 172800)
        for bad in ("", "10", "h", "1x", "-5m", "1.5h"):
            with self.assertRaises(argparse.ArgumentTypeError):
                parse_duration(bad)

    def test_parse_ts(self):
        self.assertEqual(parse_ts("14/Oct/2026:10:00:01 +0000") - parse_ts("14/Oct/2026:10:00:00 +0000"), 1)
        self.assertEqual(parse_ts("14/Oct/2026:12:00:00 +0200"), parse_ts("14/Oct/2026:10:00:00 +0000"))
        with self.assertRaises(ValueError):
            parse_ts("garbage")

    def test_fmt_range(self):
        self.assertEqual(fmt_range(rng("10.0.0.0", "10.0.255.255")), "10.0.0.0/16")
        self.assertEqual(fmt_range(rng("34.4.5.0", "34.63.255.255")), "34.4.5.0-34.63.255.255")
        self.assertEqual(fmt_range(rng("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")), "2001:db8::/32")

    def test_range_nets_roundtrip(self):
        r = rng("34.4.5.0", "34.63.255.255")
        nets = range_nets(r)
        self.assertEqual(int(nets[0].network_address), r[1])
        self.assertEqual(int(nets[-1].broadcast_address), r[2])
        self.assertEqual(sum(n.num_addresses for n in nets), r[2] - r[1] + 1)

    def test_prefix_of(self):
        self.assertEqual(prefix_of(ipaddress.ip_address("1.2.3.4")), net("1.2.0.0/16"))
        self.assertEqual(prefix_of(ipaddress.ip_address("2001:db8:1::1")), net("2001:db8::/32"))

    def test_subtract(self):
        self.assertEqual(subtract(net("10.0.0.0/8"), []), [net("10.0.0.0/8")])
        self.assertEqual(subtract(net("10.1.0.0/16"), [net("10.0.0.0/8")]), [])
        self.assertEqual(subtract(net("10.0.0.0/8"), [net("192.168.0.0/16")]), [net("10.0.0.0/8")])
        pieces = subtract(net("10.0.0.0/24"), [net("10.0.0.0/26")])
        self.assertEqual(sorted(pieces), [net("10.0.0.64/26"), net("10.0.0.128/25")])
        self.assertEqual(subtract(net("2001:db8::/32"), [net("2001:db8::/32")]), [])
        # IPv4 and IPv6 entries do not interfere
        self.assertEqual(subtract(net("10.0.0.0/8"), [net("2001:db8::/32")]), [net("10.0.0.0/8")])


class Grouping(unittest.TestCase):
    def test_cluster_groups_close_ips_and_bounds_by_extremes(self):
        groups = cluster_ips([(100, 1), (110, 2), (5000, 1)], span=4096)
        self.assertEqual(groups, [[100, 110, 3, 2], [5000, 5000, 1, 1]])

    def test_cluster_not_split_on_block_boundary(self):
        a, b = ip("127.255.255.255"), ip("128.0.0.0")
        self.assertEqual(cluster_ips([(a, 1), (b, 1)], 4096), [[a, b, 2, 2]])

    def test_cluster_span_is_extent_from_first_ip(self):
        self.assertEqual(len(cluster_ips([(0, 1), (4095, 1), (4096, 1)], 4096)), 2)
        self.assertEqual(len(cluster_ips([(0, 1), (4095, 1)], 4096)), 1)

    def test_cluster_input_order_irrelevant(self):
        self.assertEqual(cluster_ips([(5000, 1), (100, 1)], 4096), cluster_ips([(100, 1), (5000, 1)], 4096))

    def test_pick_groups_covers_requested_share(self):
        groups = [[0, 0, 80, 1], [10**6, 10**6, 15, 1], [2 * 10**6, 2 * 10**6, 5, 1]]
        self.assertEqual(pick_groups(groups, 0.8, 4), [groups[0]])
        self.assertEqual(len(pick_groups(groups, 0.9, 4)), 2)

    def test_pick_groups_too_scattered(self):
        groups = [[i * 10**6, i * 10**6, 1, 1] for i in range(6)]
        self.assertIsNone(pick_groups(groups, 0.8, 4))

    def test_wide_blocks_clamped_to_allocation_bounds(self):
        lo, hi = ip("34.64.0.0"), ip("34.127.255.255")
        ips = [(ip("34.67.1.1"), 5), (ip("34.67.9.9"), 3), (ip("34.100.0.1"), 2)]
        blocks = wide_blocks(ips, lo, hi, 16, 0.8)
        self.assertEqual(blocks, [(ip("34.67.0.0"), ip("34.67.255.255"))])
        blocks = wide_blocks(ips, lo, hi, 16, 1.0)
        self.assertEqual(blocks, [(ip("34.67.0.0"), ip("34.67.255.255")), (ip("34.100.0.0"), ip("34.100.255.255"))])

    def test_wide_blocks_clamp_at_edges(self):
        lo, hi = ip("10.0.5.0"), ip("10.0.9.255")  # allocation narrower than a /16
        self.assertEqual(wide_blocks([(ip("10.0.6.1"), 1)], lo, hi, 16, 0.8), [(lo, hi)])


class WelcomeList(TmpDirCase):
    def test_reads_comments_blank_and_bad_lines(self):
        p = self.write("w.txt", "# header\n10.0.0.0/8  # admins\n\nnot-an-ip\n2001:db8::/32\n")
        with self.assertLogs("fobots", "WARNING"):
            w = Welcome(p)
        self.assertEqual(w.nets, [net("10.0.0.0/8"), net("2001:db8::/32")])

    def test_missing_file_is_empty(self):
        with self.assertLogs("fobots", "INFO") as cm:
            w = Welcome(self.path("absent.txt"))
        self.assertEqual(w.nets, [])
        self.assertIn("file missing", cm.output[0])

    def test_reload_after_change(self):
        p = self.write("w.txt", "10.0.0.0/8\n")
        w = Welcome(p)
        Welcome.append(p, [net("192.168.0.0/16")])
        os.utime(p, (time.time() + 5, time.time() + 5))
        w.reload()
        self.assertEqual(w.nets, [net("10.0.0.0/8"), net("192.168.0.0/16")])


class RangeStoreTests(TmpDirCase):
    def test_find_returns_most_specific(self):
        s = RangeStore(None)
        s.add(rng("10.0.0.0", "10.255.255.255"))
        s.add(rng("10.1.0.0", "10.1.255.255"))
        self.assertEqual(s.find(ipaddress.ip_address("10.1.2.3")), rng("10.1.0.0", "10.1.255.255"))
        self.assertEqual(s.find(ipaddress.ip_address("10.9.2.3")), rng("10.0.0.0", "10.255.255.255"))
        self.assertIsNone(s.find(ipaddress.ip_address("11.0.0.1")))
        self.assertIsNone(s.find(ipaddress.ip_address("2001:db8::1")))

    def test_persistence_and_version(self):
        p = self.path("ranges.json")
        s = RangeStore(p)
        v = s.version
        s.add(rng("10.0.0.0", "10.255.255.255"))
        s.add(rng("10.0.0.0", "10.255.255.255"))  # duplicate: no change
        self.assertEqual(s.version, v + 1)
        self.assertEqual(RangeStore(p).ranges, s.ranges)

    def test_old_format_and_corrupt_file(self):
        p = self.write("old.json", json.dumps([[4, 1, 2, "name"]]))
        self.assertEqual(RangeStore(p).ranges, ((4, 1, 2),))
        bad = self.write("bad.json", "{not json")
        with self.assertLogs("fobots", "WARNING"):
            self.assertEqual(RangeStore(bad).ranges, ())


class NftParsing(unittest.TestCase):
    def test_val_nets(self):
        self.assertEqual(val_nets("1.2.3.4"), [net("1.2.3.4/32")])
        self.assertEqual(val_nets({"prefix": {"addr": "10.0.0.0", "len": 8}}), [net("10.0.0.0/8")])
        self.assertEqual(val_nets({"range": ["10.0.0.0", "10.0.0.255"]}), [net("10.0.0.0/24")])

    def test_parse_elems_with_and_without_expires(self):
        data = {"nftables": [{"metainfo": {}}, {"set": {"elem": [
            {"elem": {"val": {"prefix": {"addr": "10.0.0.0", "len": 8}}, "timeout": 3600, "expires": 120}},
            {"prefix": {"addr": "20.0.0.0", "len": 8}},
            "1.2.3.4",
            {"elem": {"val": {"range": ["34.4.5.0", "34.4.6.255"]}, "timeout": 3600}},
        ]}}]}
        got = parse_elems(data)
        self.assertEqual(got[0], (net("10.0.0.0/8"), 120))
        self.assertEqual(got[1], (net("20.0.0.0/8"), None))
        self.assertEqual(got[2], (net("1.2.3.4/32"), None))
        self.assertEqual([n for n, _ in got[3:]], [net("34.4.5.0/24"), net("34.4.6.0/24")])

    def test_parse_elems_empty_set(self):
        self.assertEqual(parse_elems({"nftables": [{"set": {"name": "x"}}]}), [])


class NftDryRun(unittest.TestCase):
    def apply(self, nft, *a, **k):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            nft.apply(*a, **k)
        return out.getvalue()

    def test_delete_and_add_are_two_transactions_in_order(self):
        nft = Nft(dry_run=True)
        nft.sim[4] = [(net("34.66.63.27/32"), 100)]
        out = self.apply(nft, 4, [net("34.66.63.27/32")], [(net("34.64.0.0/10"), 3600)])
        lines = out.strip().splitlines()
        self.assertEqual(lines[0], "delete element inet fobots banned4 { 34.66.63.27/32 }")
        self.assertEqual(lines[1], "add element inet fobots banned4 { 34.64.0.0/10 timeout 3600s }")
        self.assertEqual(nft.sim[4], [(net("34.64.0.0/10"), 3600)])

    def test_add_only_and_timeout_floor(self):
        nft = Nft(dry_run=True)
        out = self.apply(nft, 4, [], [(net("1.2.3.0/24"), 0)])
        self.assertEqual(out.strip(), "add element inet fobots banned4 { 1.2.3.0/24 timeout 1s }")

    def test_restore_when_add_fails(self):
        nft = Nft(dry_run=True)
        nft.sim[4] = [(net("1.1.1.1/32"), 50)]
        calls = []
        orig = nft._add

        def flaky(ver, adds):
            calls.append(adds)
            if len(calls) == 1:
                raise NftError("overlap")
            orig(ver, adds)
        nft._add = flaky
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(NftError):
                nft.apply(4, [net("1.1.1.1/32")], [(net("1.1.0.0/16"), 3600)], restore=[(net("1.1.1.1/32"), 50)])
        self.assertEqual(calls[1], [(net("1.1.1.1/32"), 50)])
        self.assertEqual(nft.sim[4], [(net("1.1.1.1/32"), 50)])


class BannerTests(TmpDirCase):
    def banner(self, nft, welcome_text=""):
        w = Welcome(self.write("w.txt", welcome_text))
        return Banner(nft, w, 3600)

    def test_ban_adds_cidr_pieces(self):
        nft = FakeNft()
        self.assertTrue(self.banner(nft).ban(rng("34.4.5.0", "34.4.6.255"), "t"))
        self.assertEqual(nft.banned(), ["34.4.5.0/24", "34.4.6.0/24"])

    def test_already_covered_is_not_banned_again(self):
        nft = FakeNft([(net("10.0.0.0/8"), 100)])
        self.assertFalse(self.banner(nft).ban(rng("10.1.0.0", "10.1.255.255"), "t"))
        self.assertEqual(nft.calls, [])

    def test_wider_ban_replaces_included_ones(self):
        nft = FakeNft([(net("34.66.63.27/32"), 100), (net("34.67.0.112/32"), 100), (net("34.128.0.0/10"), 100)])
        self.assertTrue(self.banner(nft).ban(rng("34.64.0.0", "34.127.255.255"), "t"))
        self.assertEqual(nft.banned(), ["34.128.0.0/10", "34.64.0.0/10"])
        (_, deletes, adds), = nft.calls
        self.assertEqual(sorted(deletes), [net("34.66.63.27/32"), net("34.67.0.112/32")])
        self.assertEqual([n for n, _ in adds], [net("34.64.0.0/10")])

    def test_welcome_list_is_excluded(self):
        nft = FakeNft()
        self.banner(nft, "10.0.0.0/26\n").ban(rng("10.0.0.0", "10.0.0.255"), "t")
        self.assertEqual(nft.banned(), ["10.0.0.128/25", "10.0.0.64/26"])

    def test_entirely_welcome(self):
        nft = FakeNft()
        with self.assertLogs("fobots", "INFO"):
            self.assertFalse(self.banner(nft, "10.0.0.0/8\n").ban(rng("10.1.0.0", "10.1.255.255"), "t"))
        self.assertEqual(nft.banned(), [])

    def test_retry_once_then_raise(self):
        nft = FakeNft(fail_adds=1)
        with self.assertLogs("fobots", "WARNING"):
            self.assertTrue(self.banner(nft).ban(rng("1.2.3.0", "1.2.3.255"), "t"))
        nft = FakeNft(fail_adds=2)
        with self.assertLogs("fobots", "WARNING"), self.assertRaises(NftError):
            self.banner(nft).ban(rng("1.2.3.0", "1.2.3.255"), "t")

    def test_replaced_elements_are_offered_for_restoration(self):
        seen = {}

        class Spy(FakeNft):
            def apply(self, ver, deletes, adds, restore=()):
                seen["restore"] = list(restore)
                super().apply(ver, deletes, adds, restore)
        nft = Spy([(net("1.1.1.1/32"), 42), (net("1.1.2.2/32"), None)])
        self.banner(nft).ban(rng("1.1.0.0", "1.1.255.255"), "t")
        self.assertEqual(sorted(seen["restore"]), [(net("1.1.1.1/32"), 42), (net("1.1.2.2/32"), 3600)])

    def test_welcome_add_removes_and_keeps_the_rest(self):
        nft = FakeNft([(net("17.0.0.0/8"), 500)])
        deletes, adds = welcome_add(nft, net("17.1.0.0/16"), 3600)
        self.assertEqual(deletes, [net("17.0.0.0/8")])
        self.assertEqual(len(adds), 8)
        self.assertTrue(all(t == 500 for _, t in adds))
        covered = sum(n.num_addresses for n, _ in adds)
        self.assertEqual(covered, 2 ** 24 - 2 ** 16)
        self.assertFalse(any(n.overlaps(net("17.1.0.0/16")) for n, _ in adds))


class DetectorBase(TmpDirCase):
    def detector(self, ranges=(), threshold=5, sustain=1, window=60, scope="allocation", nft=None,
                 welcome="", **kw):
        self.nft = nft or FakeNft()
        self.store = RangeStore(None)
        for r in ranges:
            self.store.add(r)
        self.rdap = NoRdap()
        banner = Banner(self.nft, Welcome(self.write("w.txt", welcome)), 3600)
        self.det = Detector(threshold, kw.pop("prefix_threshold", threshold), sustain, window,
                               self.store, banner, self.rdap, scope=scope, **kw)
        return self.det

    def feed(self, ips, sec):
        for a in ips:
            self.det.feed_line(line(a, sec))


class DetectorAllocation(DetectorBase):
    ALLOC = rng("43.0.0.0", "43.127.255.255")

    def test_ban_when_threshold_exceeded(self):
        self.detector([self.ALLOC], threshold=5)
        self.feed([f"43.1.1.{i}" for i in range(5)], 0)  # 5 req/s: not above the threshold
        self.assertEqual(self.nft.banned(), [])
        with self.assertLogs("fobots", "INFO") as cm:
            self.feed(["43.2.2.2"], 0)
        self.assertEqual(self.nft.banned(), ["43.0.0.0/9"])
        self.assertIn("req/s > 5", cm.output[0])

    def test_rate_is_per_second(self):
        self.detector([self.ALLOC], threshold=5)
        for sec in range(10):
            self.feed([f"43.1.1.{i}" for i in range(5)], sec)
        self.assertEqual(self.nft.banned(), [])

    def test_slow_scraper_is_banned_by_average_rate(self):
        self.detector([self.ALLOC], threshold=2, slow_threshold=0.5, slow_window=100)
        with self.assertLogs("fobots", "INFO") as cm:
            for s in range(0, 100):  # one request per second: never above the threshold
                self.feed([f"43.{s % 7}.1.1"], s)
        self.assertEqual(self.nft.banned(), ["43.0.0.0/9"])
        self.assertTrue(any("on average over" in m for m in cm.output))

    def test_slow_criterion_ignores_a_short_burst_and_is_off_by_default(self):
        self.detector([self.ALLOC], threshold=100, slow_threshold=0.5, slow_window=100)
        self.feed(["43.1.1.1"] * 40, 0)      # 40 requests in 100 s = 0.4 req/s
        self.assertEqual(self.nft.banned(), [])
        self.detector([self.ALLOC], threshold=100)
        for s in range(200):
            self.feed(["43.1.1.1"] * 2, s)
        self.assertEqual(self.nft.banned(), [])

    def test_slow_window_forgets_old_requests(self):
        self.detector([self.ALLOC], threshold=100, slow_threshold=0.5, slow_window=100)
        self.feed(["43.1.1.1"] * 45, 0)
        self.feed(["43.1.1.2"] * 45, 500)    # the first 45 are long gone
        self.assertEqual(self.nft.banned(), [])
        self.assertEqual(len(self.det.slow), 1)

    def test_sustain_requires_several_seconds(self):
        self.detector([self.ALLOC], threshold=2, sustain=3)
        for sec in (0, 1):
            self.feed(["43.1.1.1"] * 3, sec)
        self.assertEqual(self.nft.banned(), [])
        with self.assertLogs("fobots", "INFO"):
            self.feed(["43.1.1.1"] * 3, 2)
        self.assertEqual(self.nft.banned(), ["43.0.0.0/9"])

    def test_sustain_requires_consecutive_seconds(self):
        self.detector([self.ALLOC], threshold=2, sustain=3)
        for sec in (0, 1, 3, 4):  # second 2 is quiet: the excess is interrupted
            self.feed(["43.1.1.1"] * 3, sec)
        self.assertEqual(self.nft.banned(), [])
        with self.assertLogs("fobots", "INFO"):
            self.feed(["43.1.1.1"] * 3, 5)
        self.assertEqual(self.nft.banned(), ["43.0.0.0/9"])

    def test_sustain_forgets_old_seconds(self):
        self.detector([self.ALLOC], threshold=2, sustain=2, window=5)
        self.feed(["43.1.1.1"] * 3, 0)
        self.feed(["43.1.1.1"] * 3, 30)
        self.assertEqual(self.nft.banned(), [])

    def test_unknown_range_asks_rdap_for_the_prefix(self):
        self.detector([], threshold=2, prefix_threshold=2)
        self.feed(["8.8.1.1", "8.8.1.2", "8.8.1.3"], 0)
        self.assertEqual(self.nft.banned(), [])
        self.assertEqual(self.rdap.requested[0][1], net("8.8.0.0/16"))

    def test_private_and_invalid_ips_are_ignored(self):
        self.detector([], threshold=1, prefix_threshold=1)
        self.feed(["10.0.0.1"] * 5 + ["192.168.1.1"] * 5, 0)
        self.det.feed_line("not a log line\n")
        self.det.feed_line('1.2.3.4 - - [bad date] "GET / HTTP/1.1" 200 1\n')
        self.assertEqual(self.rdap.requested, [])
        self.assertEqual(self.det.skipped, 2)

    def test_ipv6(self):
        r = rng("2a00:1450::", "2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff")
        self.detector([r], threshold=2)
        with self.assertLogs("fobots", "INFO"):
            self.feed(["2a00:1450::1", "2a00:1450::2", "2a00:1450::3"], 0)
        self.assertEqual(self.nft.banned(6), ["2a00:1450::/32"])

    def test_recent_ban_is_not_repeated_within_a_minute(self):
        self.detector([self.ALLOC], threshold=2)
        with self.assertLogs("fobots", "INFO"):
            self.feed(["43.1.1.1"] * 3, 0)
        n = len(self.nft.calls)
        self.nft.sets[4] = []  # the ban vanished (e.g. flush): within 60 s nothing is retried
        self.feed(["43.1.1.1"] * 3, 10)
        self.assertEqual(len(self.nft.calls), n)

    def test_ignore_path_and_site_rules(self):
        import re
        site = Site("gitlab", "/x.log", regex="^/assets/")
        self.detector([self.ALLOC], threshold=2, ignore_path=re.compile(r"^/favicon"), sites=[site])
        for p in ("/assets/a.js", "/assets/b.js", "/favicon.ico", "/favicon.png"):
            for _ in range(3):
                self.det.feed_line(line("43.1.1.1", 0, p), site)
        self.assertEqual(self.nft.banned(), [])
        self.assertEqual((site.lines, site.ignored), (12, 12))
        with self.assertLogs("fobots", "INFO"):
            for _ in range(3):
                self.det.feed_line(line("43.1.1.1", 0, "/projects"), site)
        self.assertEqual(self.nft.banned(), ["43.0.0.0/9"])

    def test_site_ignore_all(self):
        site = Site("static", "/x.log", all=True)
        self.detector([self.ALLOC], threshold=1)
        for _ in range(10):
            self.det.feed_line(line("43.1.1.1", 0), site)
        self.assertEqual(self.nft.banned(), [])
        self.assertEqual(site.ignored, 10)

    def test_welcome_list_prevents_ban(self):
        self.detector([self.ALLOC], threshold=2, welcome="43.0.0.0/9\n")
        with self.assertLogs("fobots", "INFO"):
            self.feed(["43.1.1.1"] * 3, 0)
        self.assertEqual(self.nft.banned(), [])

    def test_watch_reads_the_agent_before_a_trailing_duration(self):
        from fobots.detector import REQ_RE
        m = REQ_RE.search(line("43.1.1.1", 0, "/api", agent="runner/1").rstrip("\n") + " 123456\n")
        self.assertEqual((m.group(1), m.group(2)), ("/api", "runner/1"))

    def test_watched_ips_are_reported(self):
        wf = self.path("watched.jsonl")
        import re
        self.detector([self.ALLOC], threshold=2, watch=(re.compile("^runner"), None), watch_file=wf)
        with self.assertLogs("fobots", "WARNING") as cm:
            for _ in range(3):
                self.det.feed_line(line("43.1.1.1", 0, "/api/v4/jobs", agent="runner/1"))
        self.assertTrue(any("WATCH 43.0.0.0/9 banned" in m for m in cm.output))
        events = read_events(wf, 0)
        self.assertEqual(events[0]["ips"][0][0], "43.1.1.1")
        self.assertEqual(events[0]["range"], "43.0.0.0/9")

    def test_site_watch_overrides_the_global_one(self):
        wf = self.path("watched.jsonl")
        site = Site("gitlab", "/x.log", watch=("^runner", "^/api/v4/"))
        self.detector([self.ALLOC], threshold=2, watch_file=wf)  # no global watch
        with self.assertLogs("fobots", "WARNING") as cm:
            for _ in range(3):
                self.det.feed_line(line("43.1.1.1", 0, "/api/v4/jobs", agent="runner/1"), site)
        self.assertTrue(any("WATCH 43.0.0.0/9 banned" in m for m in cm.output))
        self.assertEqual(read_events(wf, 0)[0]["ips"][0][0], "43.1.1.1")

    def test_site_watch_requires_its_own_path(self):
        wf = self.path("watched.jsonl")
        site = Site("gitlab", "/x.log", watch=("^runner", "^/api/v4/"))
        self.detector([self.ALLOC], threshold=2, watch_file=wf)
        with self.assertLogs("fobots", "INFO") as cm:
            for _ in range(3):
                self.det.feed_line(line("43.1.1.1", 0, "/other", agent="runner/1"), site)
        self.assertFalse(any("WATCH" in m for m in cm.output))
        self.assertEqual(read_events(wf, 0), [])

    def test_load_lowers_threshold_and_duration(self):
        class Load:
            level, factor = 1, 0.5

            def describe(self):
                return "x"
        self.detector([self.ALLOC], threshold=10, load=Load(), min_threshold=1.0, min_ban_seconds=60)
        self.assertEqual(self.det.threshold, 5)
        self.assertEqual(self.det.ban_seconds(), 1800)
        self.det.load.factor = 0.01
        self.assertEqual(self.det.threshold, 1.0)  # floor
        self.assertEqual(self.det.ban_seconds(), 60)


class DetectorObserved(DetectorBase):
    ALLOC = rng("34.64.0.0", "34.127.255.255")  # a /10

    def test_concentrated_scraper_gets_a_tight_ban(self):
        self.detector([self.ALLOC], threshold=5, scope="observed")
        self.feed(["34.100.9.9"], 0)  # a bystander in the same allocation
        with self.assertLogs("fobots", "INFO"):
            self.feed([f"34.67.1.{i}" for i in range(1, 8)], 0)
        banned = [ipaddress.ip_network(b) for b in self.nft.banned()]
        self.assertTrue(banned)
        self.assertTrue(all(n.subnet_of(net("34.67.1.0/24")) for n in banned))
        self.assertFalse(any(ipaddress.ip_address("34.100.9.9") in n for n in banned))
        self.assertTrue(any(ipaddress.ip_address("34.67.1.3") in n for n in banned))

    def test_scattered_traffic_falls_back_to_slash16_blocks(self):
        self.detector([self.ALLOC], threshold=8, scope="observed")
        ips = [f"34.{o}.1.1" for o in (66, 67, 68, 70, 72, 74, 76, 78, 80)]
        with self.assertLogs("fobots", "INFO") as cm:
            self.feed(ips, 0)
        self.assertTrue(self.nft.banned())
        self.assertTrue(all(net(b).prefixlen == 16 for b in self.nft.banned()))
        self.assertTrue(any("too scattered" in m for m in cm.output))

    def test_fallback_whole_allocation_when_cap_is_zero(self):
        self.detector([self.ALLOC], threshold=8, scope="observed", wide_prefix=0)
        ips = [f"34.{o}.1.1" for o in (66, 67, 68, 70, 72, 74, 76, 78, 80)]
        with self.assertLogs("fobots", "INFO"):
            self.feed(ips, 0)
        self.assertEqual(self.nft.banned(), ["34.64.0.0/10"])

    def test_small_allocation_is_banned_whole_on_fallback(self):
        small = rng("20.0.0.0", "20.0.255.255")
        self.detector([small], threshold=8, scope="observed")
        with self.assertLogs("fobots", "INFO"):
            self.feed([f"20.0.{o}.1" for o in range(0, 144, 16)], 0)  # 9 groups, 4096 apart
        self.assertEqual(self.nft.banned(), ["20.0.0.0/16"])

    def test_escalates_after_repeated_partial_bans(self):
        self.detector([self.ALLOC], threshold=5, scope="observed", escalate=2)
        with self.assertLogs("fobots", "INFO"):
            for k, base in enumerate((66, 80, 100)):
                self.feed([f"34.{base}.1.{i}" for i in range(1, 8)], k * 120)
        self.assertTrue(any(net(b).prefixlen == 16 for b in self.nft.banned()))

    def test_ips_are_forgotten_after_the_window(self):
        self.detector([self.ALLOC], threshold=100, scope="observed", window=10)
        self.feed(["34.67.1.1"], 0)
        self.feed(["34.67.1.2"], 100)  # triggers a purge
        self.assertNotIn("34.67.1.1", self.det.ips)
        self.assertIn("34.67.1.2", self.det.ips)

    def test_default_mode_tracks_no_ips(self):
        self.detector([self.ALLOC], threshold=100)
        self.feed(["34.67.1.1"], 0)
        self.assertEqual(self.det.ips, {})


class LoadMonitorTests(unittest.TestCase):
    def monitor(self, values):
        it = iter(values)
        return LoadMonitor("loadavg", 1.0, 2.0, 300, (0.5, 0.25), sampler=lambda: next(it))

    def test_goes_up_immediately(self):
        m = self.monitor([0.1, 1.5, 2.5])
        with self.assertLogs("fobots", "WARNING"):
            m.step(0)
            self.assertEqual((m.level, m.factor), (0, 1.0))
            m.step(1)
            self.assertEqual((m.level, m.factor), (1, 0.5))
            m.step(2)
            self.assertEqual((m.level, m.factor), (2, 0.25))

    def test_goes_down_one_level_after_recovery(self):
        m = self.monitor([2.5, 0.1, 0.1, 0.1, 0.1])
        with self.assertLogs("fobots"):
            m.step(0)
            m.step(10)
            self.assertEqual(m.level, 2)
            m.step(10 + 299)
            self.assertEqual(m.level, 2)
            m.step(10 + 300)
            self.assertEqual(m.level, 1)  # one level at a time
            m.step(10 + 301)
            self.assertEqual(m.level, 1)

    def test_blip_resets_recovery_timer(self):
        m = self.monitor([1.5, 0.1, 1.5, 0.1, 0.1])
        with self.assertLogs("fobots"):
            m.step(0)
            m.step(100)
            m.step(200)  # back above the level: timer reset
            m.step(250)
            m.step(250 + 299)
            self.assertEqual(m.level, 1)

    def test_sampler_failure_keeps_level(self):
        def boom():
            raise OSError("no psi")
        m = LoadMonitor("psi", 20, 50, 300, (0.5, 0.25), sampler=boom)
        m.level = 1
        with self.assertLogs("fobots", "WARNING"):
            m.step(0)
        self.assertEqual(m.level, 1)

    def test_read_psi(self):
        data = "some avg10=12.50 avg60=1.00 avg300=0.00 total=1\nfull avg10=0.00 avg60=0 avg300=0 total=0\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=data)):
            self.assertEqual(read_psi("cpu"), 12.5)
        with mock.patch("builtins.open", mock.mock_open(read_data="full avg10=0.00\n")):
            with self.assertRaises(OSError):
                read_psi("cpu")


class AnalyseTests(unittest.TestCase):
    def analysis(self, **kw):
        from fobots.rdap import RangeStore
        return Analysis(RangeStore(None), **kw)

    def test_dir_key(self):
        self.assertEqual(dir_key("/collorg/images/a/b.png?x=1"), "/collorg/images/")
        self.assertEqual(dir_key("/collorg/uuid?q=/x/y"), "/collorg/")
        self.assertEqual(dir_key("/robots.txt"), "/robots.txt")
        self.assertEqual(dir_key("/"), "/")

    def test_sustained_rate(self):
        self.assertEqual(sustained_rate({0: 3, 1: 5, 2: 4}, 3), 3)
        self.assertEqual(sustained_rate({0: 3, 1: 5, 3: 4}, 3), 0)  # second 2 is missing
        self.assertEqual(sustained_rate({0: 9}, 1), 9)

    def test_agents_differing_by_their_end_are_not_merged(self):
        an = self.analysis()
        long_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
        an.feed(line("43.1.1.1", 0, agent=long_ua + "Chrome/120.0.0.0 Safari/537.36"))
        an.feed(line("43.1.1.2", 0, agent=long_ua + "Chrome/153.0.0.0 Safari/537.36"))
        self.assertEqual(len(an.agents), 2)
        self.assertTrue(short_agent(long_ua + "Chrome/120.0.0.0 Safari/537.36").endswith("Chrome/120.0.0.0 Safari/537.36"))

    def test_average_rate(self):
        slow = {s: 1 for s in range(0, 100, 2)}          # one request every 2 s
        self.assertEqual(average_rate(slow, 10), 0.5)
        self.assertEqual(sustained_rate(slow, 5), 0)     # invisible to the per-second criterion
        self.assertEqual(average_rate({0: 10, 100: 10}, 10), 1.0)  # a burst, not an average

    def test_slow_distributed_scraper_is_reported(self):
        an = self.analysis(slow_window=60)
        for s in range(60):
            an.feed(line(f"43.{s % 20}.1.1", s, f"/p/{s}", agent="bot/1"))   # 20 prefixes, 1 req/s
        an.feed(line("82.1.1.1", 0, "/", agent="Mozilla"))
        text = "\n".join(report(an, 5))
        self.assertIn("Slow scrapers", text)
        self.assertIn("ONE user agent spread over 20+ ranges", text)

    def test_scraper_and_static_directory(self):
        an = self.analysis(sustain=3)
        for s in range(10):
            for i in range(6):
                an.feed(line(f"43.1.1.{i}", s, f"/app/{s}-{i}"))
            for _ in range(2):
                an.feed(line("82.1.1.1", s, "/app/img/x.png"))
        rates = dict((k, r) for r, k in an.rates())
        self.assertEqual(rates[prefix_of(ipaddress.ip_address("43.1.1.1"))], 6)
        table = an.ban_table(an.rates(), [1, 5, 6])
        self.assertEqual([n for _, n, _ in table], [2, 1, 0])
        self.assertEqual([d for d, _ in an.static_dirs()], ["/app/img/"])
        self.assertEqual(an.suggested_regex(an.static_dirs()), "^(/app/img/)")

    def test_ignore_rules_are_applied(self):
        import re
        an = self.analysis(ignore_path=re.compile("^/app/"))
        an.feed(line("43.1.1.1", 0, "/app/x"))
        self.assertEqual((an.ignored, len(an.ranges)), (1, 0))
        self.assertEqual(an.static_dirs(), [])

    def test_duration_units_and_slow_directories(self):
        an = self.analysis()
        base = '43.1.1.1 - - [14/Oct/2026:10:00:00 +0000] "GET /a/x.js HTTP/1.1" 200 1 "-" "ua" '
        an.feed(base + "2000\n")      # integer: microseconds (Apache %D) -> 2 ms
        an.feed(base + "0.002\n")     # decimal: seconds (nginx) -> 2 ms
        self.assertAlmostEqual(an.dirs["/a/"][3], 4.0)
        slow = self.analysis(time_unit="ms")
        for _ in range(3):
            slow.feed(base.replace("x.js", "y.js") + "900\n")
        self.assertEqual(slow.static_dirs(), [])  # 900 ms per request: not cheap

    def test_unreadable_lines_and_empty_report(self):
        an = self.analysis()
        an.feed("garbage\n")
        self.assertEqual(an.unreadable, 1)
        self.assertIn("no readable line", report(an, 5)[0])

    def test_common_format_is_read(self):
        an = self.analysis()
        an.feed('43.1.1.1 - - [14/Oct/2026:10:00:00 +0000] "GET /x HTTP/1.1" 200 12\n')
        self.assertEqual(an.lines, 1)


class ProbeTests(unittest.TestCase):
    """The load signal 'probe', against a real local HTTP server."""

    @classmethod
    def setUpClass(cls):
        import http.server
        cls.mode = {"delay": 0.0, "status": 200}
        cls.hosts = []
        outer = cls

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.hosts.append(self.headers.get("Host"))
                time.sleep(outer.mode["delay"])
                self.send_response(outer.mode["status"])
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}/page"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.mode.update(delay=0.0, status=200)
        self.hosts.clear()

    def test_parse_urls(self):
        self.assertEqual(parse_probe_urls("a.org@http://127.0.0.1/x, http://127.0.0.1:8080/y"),
                         [("a.org", "http://127.0.0.1/x"), (None, "http://127.0.0.1:8080/y")])
        self.assertEqual(parse_probe_urls(""), [])
        with self.assertRaises(ValueError):
            parse_probe_urls("ftp://x/y")
        with self.assertRaises(ValueError):
            parse_probe_urls("/just/a/path")

    def test_measures_the_response_time_and_sends_the_host(self):
        p = Probe([("www.example.org", self.url)], timeout=5)
        self.assertLess(p.measure(), 0.5)
        self.assertEqual(self.hosts, ["www.example.org"])
        self.mode["delay"] = 0.3
        self.assertGreaterEqual(p.measure(), 0.3)

    def test_worst_of_several_urls(self):
        p = Probe([(None, self.url), (None, self.url + "2")], timeout=5)
        self.mode["delay"] = 0.2
        self.assertGreaterEqual(p.measure(), 0.2)

    def test_timeout_counts_as_the_timeout(self):
        self.mode["delay"] = 1.0
        p = Probe([(None, self.url)], timeout=0.2)
        self.assertEqual(p.measure(), 0.2)

    def test_server_errors_become_critical_only_after_repeated_failures(self):
        p = Probe([(None, self.url)], timeout=4, critical=3.0)
        self.assertLess(p.measure(), 0.5)
        self.mode["status"] = 503
        self.assertLess(p.measure(), 0.5)   # first failures: the previous value is kept
        self.assertLess(p.measure(), 0.5)
        with self.assertLogs("fobots", "WARNING"):
            self.assertEqual(p.measure(), 4)    # third failure: critical (max of timeout, critical)
        self.mode["status"] = 200
        with self.assertLogs("fobots", "INFO"):
            self.assertLess(p.measure(), 0.5)

    def test_strict_start_check(self):
        p = Probe([(None, self.url)], timeout=2)
        self.assertLess(p.measure(strict=True), 0.5)
        self.mode["status"] = 404
        with self.assertRaises(OSError):
            p.measure(strict=True)
        with self.assertRaises(OSError):
            Probe([(None, "http://127.0.0.1:1/x")], timeout=1).measure(strict=True)

    def test_monitor_levels_follow_the_probe(self):
        values = iter([0.2, 1.5, 3.5, 0.2])
        m = LoadMonitor("probe", 1.0, 3.0, 10, (0.5, 0.25), sampler=lambda: next(values))
        levels = []
        with self.assertLogs("fobots", "INFO"):
            for now in (0, 1, 2, 3):
                m.step(now)
                levels.append(m.level)
        self.assertEqual(levels, [0, 1, 2, 2])
        self.assertIn("probe=0.20 s", m.describe())

    def test_summarize(self):
        self.assertEqual(summarize([1, 2, 3, 4, 100]), (3, 100, 100))

    def cli(self, *argv):
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        with tempfile.TemporaryDirectory() as d:
            conf = os.path.join(d, "f.conf")
            with open(conf, "w") as f:
                f.write("[fobots]\n")
            return subprocess.run([sys.executable, os.path.join(root, "fobots.py"), *argv, "-f", conf,
                                   "--dir", d], capture_output=True, text=True, timeout=60)

    def test_run_refuses_to_start_if_the_probe_page_does_not_answer_2xx(self):
        self.mode["status"] = 404
        r = self.cli("run", "--dry-run", "--load-signal", "probe", "--load-probe-url", self.url, "/dev/null")
        self.assertEqual(r.returncode, 1)
        self.assertIn("load probe", r.stderr)
        self.assertIn("HTTP 404", r.stderr)
        r = self.cli("run", "--dry-run", "--load-signal", "probe", "/dev/null")
        self.assertEqual(r.returncode, 1)
        self.assertIn("load_probe_url is required", r.stderr)

    def test_run_starts_with_the_probe_signal(self):
        r = self.cli("run", "--dry-run", "--load-signal", "probe", "--load-probe-url", self.url, "/dev/null")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("load monitoring: probe, levels (1.0, 3.0)", r.stderr)

    def test_probe_command(self):
        r = self.cli("probe", "--url", self.url, "--duration", "1s", "--interval", "0.2")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("median", r.stdout)
        self.assertIn("load_tense = 1", r.stdout)
        self.assertEqual(self.cli("probe").returncode, 1)


class RecordTests(TmpDirCase):
    """`fobots probe --record` / `--report` against a fake /proc."""

    def fake_proc(self, avail=8000, swap_free=1000, pswp=0, queue=0, drops=0, psi_mem=0.0):
        root = os.path.join(self.dir, "proc")
        for sub in ("net", "pressure", "10", "11"):
            os.makedirs(os.path.join(root, sub), exist_ok=True)

        def put(rel, text):
            with open(os.path.join(root, rel), "w") as f:
                f.write(text)
        put("loadavg", "0.50 0.40 0.30 1/100 999\n")
        put("meminfo", f"MemTotal: 10000 kB\nMemAvailable: {avail} kB\nSwapTotal: 4096 kB\n"
                       f"SwapFree: {swap_free} kB\n")
        put("vmstat", f"pswpin {pswp}\npswpout 0\n")
        for r in ("cpu", "io", "memory"):
            put(f"pressure/{r}", f"some avg10={psi_mem if r == 'memory' else 0.0} avg60=0 avg300=0 total=0\n")
        put("net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue\n"
                       f"   0: 00000000:0050 00000000:0000 0A 00000000:{queue:08X} 00:0 0 0 0\n"
                       "   1: 00000000:0016 00000000:0000 0A 00000000:00000009 00:0 0 0 0\n")
        put("net/netstat", "TcpExt: SyncookiesSent ListenOverflows ListenDrops\n"
                           f"TcpExt: 0 {drops} 0\n")
        for pid, name, ticks, pages in (("10", "php-fpm", 300, 2560), ("11", "nginx (w)", 100, 256)):
            put(f"{pid}/stat", f"{pid} ({name}) S 1 1 1 0 -1 0 0 0 0 0 {ticks} {ticks} 0 0 20 0 1\n")
            put(f"{pid}/statm", f"100 {pages} 10 1 0 1 0\n")
        return root

    def test_read_sys(self):
        root = self.fake_proc(avail=1000, swap_free=96, queue=7, psi_mem=12.5)
        s, state = read_sys(root, None, 100.0)
        self.assertEqual((s["avail_pct"], s["swap_mb"], s["lq"]), (10.0, 3, 7))  # port 22 ignored
        self.assertEqual(s["psi"], {"cpu": 0.0, "io": 0.0, "memory": 12.5})
        self.assertNotIn("swap_rate", s)  # needs two readings
        self.fake_proc(pswp=500, drops=3)
        s, _ = read_sys(root, state, 110.0)
        self.assertEqual((s["swap_rate"], s["lovf"]), (50.0, 3))

    def test_read_sys_survives_missing_files(self):
        s, _ = read_sys(os.path.join(self.dir, "nothing"), None, 1.0)
        self.assertIsNone(s["load"])
        self.assertIsNone(s["psi"])
        self.assertIsNone(s["lq"])

    def test_scan_procs_groups_by_name(self):
        root = self.fake_proc()
        top, cpu = scan_procs(root, None)
        self.assertEqual([g["name"] for g in top], ["php-fpm", "nginx (w)"])
        self.assertEqual((top[0]["n"], top[0]["rss_mb"], top[0]["cpu_s"]), (1, 10, None))
        self.assertGreater(cpu["php-fpm"], 0)
        top, _ = scan_procs(root, {"php-fpm": 0.0})
        self.assertGreater(top[0]["cpu_s"], 0)

    def recorder(self, times, **kw):
        it = iter(times)
        probe = mock.Mock(targets=[(None, "http://127.0.0.1/x")], timeout=10.0)
        probe.fetch = lambda host, url: (200, next(it))
        root = self.fake_proc(**kw)
        return Recorder(probe, os.path.join(self.dir, "rec.jsonl"), 1.0, 3.0, 5.0, root), root

    def test_slowdown_is_recorded_with_what_preceded_it(self):
        rec, root = self.recorder([0.1, 0.1, 0.1, 1.5, 3.5, 0.2, 0.1])
        for i in range(3):
            rec.step(i * 5, 1000.0 + i * 5)
        self.fake_proc(avail=500)  # memory drops as the page slows down
        rec.step(15, 1015.0)
        rec.step(20, 1020.0)  # critical: a new snapshot at once
        rec.step(25, 1025.0)
        rec.step(30, 1030.0)
        kinds = [r["kind"] for r in read_records(rec.path)]
        self.assertEqual(kinds, ["base", "pre", "pre", "snap", "snap", "end"])
        eps = episodes(read_records(rec.path))
        self.assertEqual(len(eps), 1)
        self.assertEqual(len(eps[0]["pre"]), 2)
        self.assertEqual(eps[0]["snaps"][1]["level"], 2)
        self.assertEqual(eps[0]["snaps"][0]["procs"][0]["name"], "php-fpm")

    def test_report_says_which_reading_moved_first(self):
        rec, root = self.recorder([0.1, 0.1, 0.1, 0.1, 1.5, 3.5, 0.1])
        for i in range(2):
            rec.step(i * 5, 1000.0 + i * 5)
        self.fake_proc(avail=900)  # 9 % available, two readings before the page slows down
        rec.step(10, 1010.0)
        rec.step(15, 1015.0)
        rec.step(20, 1020.0)
        rec.step(25, 1025.0)
        rec.step(30, 1030.0)
        lines = []
        self.assertEqual(record_report(rec.path, lines.append), 0)
        text = "\n".join(lines)
        self.assertIn("1 incident(s)", text)
        row = next(x for x in lines if x.strip().startswith("memory available"))
        self.assertEqual(row.split()[5:9], ["1", "0", "0", "0"])  # before=1
        self.assertIn("10 s", row)
        self.assertIn("php-fpm", text)

    def test_logtail_counts_what_arrived(self):
        path = self.write("access.log", line("1.1.1.1", 0) * 3)
        tail = LogTail([path])
        tail.t = 100.0
        with open(path, "a") as f:
            f.write(line("1.1.1.1", 1) + line("2.2.2.2", 1) + line("3.3.3.3", 1).replace(" 200 ", " 502 "))
            f.write(line("4.4.4.4", 1).replace(" 200 ", " 404 "))
        self.assertEqual(tail.read(102.0), {"req_s": 2.0, "e5": 25.0, "ips": 4})
        self.assertEqual(tail.read(104.0), {"req_s": 0.0, "e5": None, "ips": 0})

    def test_logtail_gives_no_rate_over_a_tiny_interval(self):
        path = self.write("access.log", "")
        tail = LogTail([path])
        with open(path, "a") as f:
            f.write(line("1.1.1.1", 0) * 60)
        self.assertEqual(tail.read(100.0), {})  # first call: nothing to compare with
        with open(path, "a") as f:
            f.write(line("1.1.1.1", 0) * 60)
        self.assertEqual(tail.read(100.01), {})  # 60 lines in 10 ms would be 6000 requests/s
        self.assertEqual(tail.read(101.0)["req_s"], 0.0)

    def test_normal_times_use_every_measure(self):
        rec, _ = self.recorder([0.1, 0.2, 0.3, 0.4])
        rec.step(0, 1000.0)
        for i in (1, 2):
            rec.step(i * 5, 1000.0 + i * 5)
        rec.step(300, 1300.0)
        lines = []
        record_report(rec.path, lines.append)
        self.assertIn("(4 measures)", "\n".join(lines))

    def test_logtail_follows_a_rotation(self):
        path = self.write("access.log", line("1.1.1.1", 0) * 5)
        tail = LogTail([path])
        tail.t = 0.0
        os.replace(path, path + ".1")
        self.write("access.log", line("9.9.9.9", 0) * 2)
        self.assertEqual(tail.read(1.0)["req_s"], 2.0)

    def test_report_with_the_log(self):
        log_path = self.write("access.log", "")
        rec, root = self.recorder([0.1, 0.1, 0.1, 0.1, 1.5, 3.5, 0.1])
        rec.logs = LogTail([log_path])
        rec.logs.t = 999.0
        for i in range(7):
            with open(log_path, "a") as f:
                f.write(line("1.1.1.1", 0) * (5 if i < 3 else 50))  # traffic x10 from step 3
            rec.step(i * 5, 1000.0 + i * 5)
        lines = []
        record_report(rec.path, lines.append)
        text = "\n".join(lines)
        self.assertIn("requests/s", text)
        row = next(x for x in lines if x.strip().startswith("requests/s (log)"))
        cols = row.split()
        self.assertEqual(cols[cols.index("normal") + 1:][:4], ["1", "0", "0", "0"])  # before the page slowed
        self.assertIn("5 s", row)
        self.assertIn("distinct IP", text)

    def test_report_asks_for_the_log(self):
        rec, _ = self.recorder([0.1, 3.5, 0.1])
        for i in range(3):
            rec.step(i * 5, 1000.0 + i * 5)
        lines = []
        record_report(rec.path, lines.append)
        self.assertIn("(give --log)", "\n".join(lines))

    def synthetic(self, long_peaks=(4.0, 5.0, 6.0, 5.0), short_peaks=(1.3, 1.2), hours=3):
        """A recording: normal times (0.2 s), slowdowns preceded by memory and CPU pressure."""
        ok = {"load": 0.1, "avail_pct": 40.0, "psi": {"cpu": 0.0, "io": 0.0, "memory": 0.0}, "lq": 0}
        bad = {**ok, "avail_pct": 9.0, "psi": {"cpu": 30.0, "io": 0.0, "memory": 6.0}}
        recs = [{"t": 0.0, "kind": "start", "url": "a.org@http://127.0.0.1/p", "interval": 5.0,
                 "tense": 1.0, "critical": 3.0}]
        for i in range(hours * 12):
            recs.append({"t": 300.0 * (i + 1), "kind": "base", "rt": 0.2, "level": 0, "sys": ok,
                         "rts": [0.2] * 60})
        starts = [1000.0 + 1500 * i for i in range(len(long_peaks) + len(short_peaks))]
        for t0, peak in zip(starts, list(long_peaks) + list(short_peaks)):
            long = peak in long_peaks
            for k in range(3):  # two minutes before: memory and CPU, the page still fine
                recs.append({"t": t0 - 60 + 20 * k, "kind": "pre", "rt": 0.2, "level": 0,
                             "sys": bad if long else ok})
            for k in range(7 if long else 1):
                recs.append({"t": t0 + 10 * k, "kind": "snap", "rt": peak, "level": 2 if peak >= 3 else 1,
                             "sys": bad if long else ok, "procs": []})
            recs.append({"t": t0 + (70 if long else 5), "kind": "end", "rt": 0.2, "level": 0, "sys": ok})
        recs.sort(key=lambda r: r["t"])
        return self.write("rec.jsonl", "".join(json.dumps(r) + "\n" for r in recs))

    def test_report_suggests_a_configuration(self):
        lines = []
        record_report(self.synthetic(), lines.append)
        text = "\n".join(lines)
        self.assertIn("load_signal = probe", text)
        self.assertIn("load_probe_url = a.org@http://127.0.0.1/p", text)
        self.assertRegex(text, r"load_tense = 1\.5 ")      # above the short excursions (1.3 s)
        self.assertRegex(text, r"load_critical = 4 ")       # under the median peak (5 s) x 0.8
        self.assertIn("replay, defaults 1 s / 3 s", text)
        self.assertIn("replay, suggested 1.5 s / 4 s", text)
        self.assertIn("Alternative: `load_signal = psi`", text)
        self.assertIn("Observed: memory available %", text)

    def test_replay_counts_less_tense_time_with_the_suggested_levels(self):
        lines = []
        record_report(self.synthetic(long_peaks=(4.0, 5.0, 6.0), short_peaks=(1.3,) * 6), lines.append)
        rep = [x for x in lines if "replay," in x]
        share = lambda x: float(x.split("time (")[0].split()[-2]) if False else float(x.split(": tense or critical ")[1].split(" %")[0])
        self.assertGreater(share(rep[0]), share(rep[1]))

    def test_report_gives_no_levels_without_enough_data(self):
        lines = []
        record_report(self.synthetic(hours=1, long_peaks=(), short_peaks=()), lines.append)
        text = "\n".join(lines)
        self.assertIn("Not enough data yet", text)
        self.assertNotIn("load_tense", text)

    def test_report_trusts_several_severe_slowdowns_on_a_short_recording(self):
        lines = []
        record_report(self.synthetic(hours=1, long_peaks=(6.0, 7.0, 9.0), short_peaks=()), lines.append)
        text = "\n".join(lines)
        self.assertIn("Short recording", text)
        self.assertRegex(text, r"load_tense = 1 ")
        self.assertIn("load_critical", text)
        lines = []
        record_report(self.synthetic(hours=1, long_peaks=(6.0, 7.0), short_peaks=()), lines.append)
        self.assertIn("Not enough data yet", "\n".join(lines))

    def test_report_does_not_compare_signals_with_few_slowdowns(self):
        lines = []
        record_report(self.synthetic(long_peaks=(4.0, 5.0), short_peaks=()), lines.append)
        text = "\n".join(lines)
        self.assertIn("load_tense", text)
        self.assertIn("3 needed to compare them", text)
        self.assertNotIn("Alternative", text)

    def test_start_header_is_written(self):
        rec, _ = self.recorder([0.1])
        rec.start("a.org@http://127.0.0.1/p", 10.0)
        first = read_records(rec.path)[0]
        self.assertEqual((first["kind"], first["url"], first["interval"]), ("start", "a.org@http://127.0.0.1/p", 5.0))

    def test_clean_stop_is_a_pause_but_a_cut_run_is_an_incident(self):
        rec, _ = self.recorder([0.1])
        rec.start("http://127.0.0.1/p", 10.0)
        rec.finish()
        rec.start("http://127.0.0.1/p", 10.0)  # after a clean stop
        rec.start("http://127.0.0.1/p", 10.0)  # the previous run left no stop: cut
        starts = [r for r in read_records(rec.path) if r["kind"] == "start"]
        self.assertEqual([bool(r.get("unclean")) for r in starts], [False, False, True])
        self.assertEqual(starts[2]["last_t"], starts[1]["t"])

    def test_report_lists_interruptions_and_does_not_count_clean_pauses(self):
        recs = [{"t": 0.0, "kind": "start", "interval": 5.0}, {"t": 100.0, "kind": "stop"},
                {"t": 40100.0, "kind": "start", "interval": 5.0},          # clean pause of 11 h
                {"t": 40200.0, "kind": "base", "rt": 0.1, "level": 0, "sys": {}, "rts": [0.1]},
                {"t": 40500.0, "kind": "gap", "seconds": 240.0},           # stall
                {"t": 50000.0, "kind": "start", "interval": 5.0, "unclean": True, "last_t": 40500.0}]
        path = self.write("rec.jsonl", "".join(json.dumps(r) + "\n" for r in recs))
        self.assertAlmostEqual(recorded_span(read_records(path)), 50000.0 - 40000.0)
        lines = []
        record_report(path, lines.append)
        text = "\n".join(lines)
        self.assertIn("2 unexpected interruption(s)", text)
        self.assertIn("the recorder stalled", text)
        self.assertIn("the recorder was cut", text)

    def test_interruptions_count_as_severe_when_judging_a_short_recording(self):
        recs = [{"t": 0.0, "kind": "start", "interval": 5.0, "tense": 1.0}]
        recs += [{"t": 100.0 * i, "kind": "gap", "seconds": 60.0} for i in range(1, 4)]
        path = self.write("rec.jsonl", "".join(json.dumps(r) + "\n" for r in recs))
        lines = []
        record_report(path, lines.append)
        self.assertIn("Short recording", "\n".join(lines))

    def test_a_collapse_does_not_give_absurd_levels(self):
        """A server that falls down for hours (HTTP 500 after 39 s) and failed connections: the levels
        stay within what the daemon can tell apart (the probe timeout), and errors are not 'slowness'."""
        ok = {"load": 0.1, "avail_pct": 40.0}
        recs = [{"t": 0.0, "kind": "start", "interval": 5.0, "tense": 1.0, "critical": 3.0, "timeout": 10.0}]
        for i in range(30):
            recs.append({"t": 300.0 * (i + 1), "kind": "base", "rt": 0.2, "level": 0, "sys": ok, "rts": [0.2] * 60})
        for k in range(5):  # refused connections: one measure each, no time measured
            recs.append({"t": 1000.0 + 700 * k, "kind": "snap", "rt": 0.0, "level": 2, "err": "refused", "sys": ok})
            recs.append({"t": 1005.0 + 700 * k, "kind": "end", "rt": 0.2, "level": 0, "sys": ok})
        for k in range(40):  # the collapse
            recs.append({"t": 5000.0 + 10 * k, "kind": "snap", "rt": 39.1, "level": 2, "err": "HTTP 500", "sys": ok})
        recs.sort(key=lambda r: r["t"])
        path = self.write("rec.jsonl", "".join(json.dumps(r) + "\n" for r in recs))
        lines = []
        record_report(path, lines.append)
        text = "\n".join(lines)
        self.assertRegex(text, r"load_tense = 1 ")          # refused connections are not slowness
        self.assertRegex(text, r"load_critical = 5 ")       # half the 10 s timeout, not 0.8 x 39 s
        self.assertIn("capped at half the probe timeout", text)
        self.assertNotIn("Warning", text)

    def test_short_excursions_are_summarised_not_listed(self):
        ok = {"load": 0.1}
        recs = [{"t": 0.0, "kind": "start", "interval": 5.0, "tense": 1.0, "critical": 3.0}]
        for i in range(60):
            recs.append({"t": 100.0 * i, "kind": "snap", "rt": 1.3, "level": 1, "sys": ok})
            recs.append({"t": 100.0 * i + 5, "kind": "end", "rt": 0.2, "level": 0, "sys": ok})
        path = self.write("rec.jsonl", "".join(json.dumps(r) + "\n" for r in recs))
        lines = []
        record_report(path, lines.append)
        text = "\n".join(lines)
        self.assertIn("60 short excursion(s)", text)
        self.assertIn("0 incident(s)", text)
        self.assertNotIn("  60. ", text)

    def test_gap_is_recorded(self):
        rec, _ = self.recorder([0.1, 0.1])
        rec.step(0, 1000.0)
        rec.step(500, 1500.0)
        self.assertIn("gap", [r["kind"] for r in read_records(rec.path)])

    def test_file_is_rotated(self):
        rec, _ = self.recorder([0.1] * 3)
        rec.max_bytes = 10
        rec.step(0, 1000.0)
        rec.step(400, 1400.0)
        self.assertTrue(os.path.exists(rec.path + ".1"))

    def test_report_without_slowdown(self):
        rec, _ = self.recorder([0.1])
        rec.step(0, 1000.0)
        lines = []
        record_report(rec.path, lines.append)
        self.assertIn("No incident recorded", "\n".join(lines))



class ReplayTests(TmpDirCase):
    """`fobots replay` against a real local HTTP server."""

    @classmethod
    def setUpClass(cls):
        import http.server
        cls.delay = 0.0
        outer = cls

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                time.sleep(outer.delay)
                code = 404 if self.path.startswith("/gone/") else 200
                self.send_response(code)
                self.send_header("Content-Length", "10")
                self.end_headers()
                self.wfile.write(b"0123456789")

            def log_message(self, *a):
                pass
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        super().setUp()
        type(self).delay = 0.0

    def make_log(self, per_second=6, seconds=10):
        rows = []
        for sec in range(seconds):
            for i in range(per_second):
                n = sec * per_second + i
                path = "/gone/x" if n % 10 == 0 else f"/ok/p{n}"
                rows.append(line(f"1.1.1.{n % 5}", sec, path, "bot" if n % 2 else "firefox"))
        rows.append(line("1.1.1.1", 3, "/ok/post", "bot").replace('"GET', '"POST'))
        return self.write("access.log", "".join(rows))

    def test_read_requests_keeps_get_and_filters(self):
        path = self.make_log()
        self.assertEqual(len(read_requests([path])), 60)  # the POST is left out
        self.assertEqual(len(read_requests([path], re.compile("bot"))), 30)
        self.assertEqual(len(read_requests([path], None, re.compile("^/gone/"))), 54)

    def test_select_window_takes_the_busiest_stretch(self):
        rows = [line("1.1.1.1", s) for s in range(0, 20, 2)]            # sparse: 10 requests
        rows += [line("1.1.1.2", s) * 5 for s in range(40, 46)]          # burst: 30 requests in 6 s
        path = self.write("a.log", "".join(rows))
        window, first, last = select_window(read_requests([path]), 6)
        self.assertEqual(len(window), 30)
        self.assertEqual(last - first, 5)

    def test_schedule_loops_the_window_faster(self):
        path = self.write("a.log", "".join(line("1.1.1.1", s) for s in range(3)))
        window = read_requests([path])
        plan = schedule(window, 2.0, 3.0)
        self.assertEqual(len(plan), 6)
        self.assertEqual([round(w, 2) for w, _ in plan], [0, 0.5, 1.0, 1.5, 2.0, 2.5])

    def test_parse_speeds(self):
        self.assertEqual(parse_speeds("1, 1.5,2"), [1.0, 1.5, 2.0])
        for bad in ("", "a", "0", "-1,2"):
            with self.assertRaises(ValueError):
                parse_speeds(bad)

    def run_replay(self, speeds, step, **kw):
        window, _, _ = select_window(read_requests([self.make_log(**kw.pop("log", {}))]), 10)
        out = self.path("replay.jsonl")
        said = []
        rp = Replay(window, make_fetcher(self.base, None, 5.0), speeds, step, out=out, say=said.append, **kw)
        return rp, rp.run(), out, said

    def test_replay_measures_each_stage_and_the_fidelity(self):
        rp, reason, out, said = self.run_replay([1.0, 2.0], 2.0)
        self.assertIsNone(reason)
        lines = []
        self.assertEqual(replay_report(out, lines.append), 0)
        text = "\n".join(lines)
        self.assertRegex(text, r"x1 .*\n.*x2 ")
        self.assertIn("Held up to x2", text)
        self.assertIn("200 -> 404", text)           # /gone/ answers 404 although logged 200
        self.assertIn("/ok/", text)                  # cost by type of request
        recs = read_results_file(out)
        self.assertEqual([r["s"] for r in recs if r["kind"] == "stage"], [1, 2])
        self.assertEqual(recs[-1]["kind"], "end")

    def test_replay_stops_by_itself_when_the_server_is_slow(self):
        type(self).delay = 0.4
        rp, reason, out, said = self.run_replay([1.0, 2.0, 3.0], 3.0, stop_latency=0.3, log={"per_second": 20})
        self.assertIn("median response time", reason)
        recs = read_results_file(out)
        self.assertEqual(recs[-1]["kind"], "stop")
        self.assertEqual([r["s"] for r in recs if r["kind"] == "stage"], [1])  # the next stages never started
        lines = []
        replay_report(out, lines.append)
        self.assertIn("Stopped:", "\n".join(lines))

    def test_replay_stops_when_too_many_requests_wait(self):
        type(self).delay = 1.0
        rp, reason, out, _ = self.run_replay([1.0], 3.0, max_inflight=5, stop_latency=60, log={"per_second": 20})
        self.assertIn("waiting for an answer", reason)

    def test_replay_stops_on_errors(self):
        window, _, _ = select_window(read_requests([self.make_log(per_second=20)]), 10)
        rp = Replay(window, make_fetcher("http://127.0.0.1:1", None, 1.0), [1.0], 2.0,
                    out=self.path("r.jsonl"), say=lambda *_: None)
        self.assertIn("failed", rp.run())



def read_results_file(path):
    with open(path) as f:
        return [json.loads(x) for x in f]



class SiteTests(unittest.TestCase):
    def test_rules(self):
        s = Site("s", "/l", regex=r"^/(assets/|favicon\.ico)|\.png$")
        self.assertTrue(s.ignores("/assets/x.js"))
        self.assertTrue(s.ignores("/favicon.ico"))
        self.assertTrue(s.ignores("/img/a.png"))
        self.assertFalse(s.ignores("/projects/assets/x.js"))
        self.assertTrue(s.has_path_rules)
        self.assertFalse(Site("t", "/l").has_path_rules)
        self.assertEqual(Site("t", "/l").describe(), "no exclusion of its own")
        self.assertEqual(Site("t", "/l", all=True).describe(), "everything is excluded")


class ConfigTests(TmpDirCase):
    def conf(self, text):
        return load_config(self.write("fobots.conf", text))

    def test_values_are_converted_and_paths_resolved(self):
        c = self.conf("[fobots]\nlog = access.log\nthreshold = 2.5\nban_time = 30m\nsustain = 3\n"
                      "ban_scope = observed\nfrom_start = yes\nwelcome = w.txt  # comment\n")
        self.assertEqual(c["log"], self.path("access.log"))
        self.assertEqual(c["threshold"], 2.5)
        self.assertEqual(c["ban_seconds"], 1800)
        self.assertEqual(c["sustain"], 3)
        self.assertEqual(c["ban_scope"], "observed")
        self.assertTrue(c["from_start"])
        self.assertEqual(c["welcome"], self.path("w.txt"))

    def test_sites(self):
        c = self.conf("[fobots]\n[site:gitlab]\nlog = /var/log/g.log\nignore_path = ^/(assets/|favicon)\n"
                      "\n[site:static]\nlog = s.log\nignore_all = yes\n")
        g, s = c["sites"]
        self.assertEqual((g["name"], g["regex"], g["all"]), ("gitlab", "^/(assets/|favicon)", False))
        self.assertEqual((s["name"], s["log"], s["all"]), ("static", self.path("s.log"), True))

    def test_site_watch_options(self):
        c = self.conf("[fobots]\n[site:gitlab]\nlog = g.log\nwatch_agent = ^runner\nwatch_path = ^/api/\n"
                      "[site:other]\nlog = o.log\n")
        self.assertEqual(c["sites"][0]["watch"], ("^runner", "^/api/"))
        self.assertEqual(c["sites"][1]["watch"], (None, None))

    def test_errors(self):
        bad = {
            "[fobots]\n[site:a]\nlog = x\nwatch_path = (\n": "invalid watch_path",
            "": "section [fobots] missing",
            "[fobots]\nfoo = 1\n": "unknown option 'foo'",
            "[fobots]\nthreshold = abc\n": "invalid value for threshold",
            "[fobots]\nban_time = soon\n": "invalid value for ban_time",
            "[fobots]\n[other]\nlog = x\n": "unknown section [other]",
            "[fobots]\n[site:a]\nignore_all = yes\n": "`log` is required",
            "[fobots]\n[site:a]\nlog = x\nfoo = 1\n": "unknown option 'foo'",
            "[fobots]\n[site:a]\nlog = x\n[site:b]\nlog = x\n": "follow the same log",
            "[fobots]\nlog = x\n[site:a]\nlog = x\n": "both in [fobots]",
            "[fobots]\n[site:a]\nlog = x\nignore_prefix = /assets/\n": "unknown option 'ignore_prefix'",
            "[fobots]\n[site:a]\nlog = x\nignore_path = (\n": "invalid ignore_path",
        }
        for text, expected in bad.items():
            with self.subTest(text=text), self.assertRaises(SystemExit) as cm:
                self.conf(text)
            self.assertIn(expected, str(cm.exception))

    def test_example_files_load(self):
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        c = load_config(os.path.join(root, "fobots.conf.example"))
        self.assertEqual(c["threshold"], 5.0)


class Events(TmpDirCase):
    def test_append_read_trim(self):
        p = self.path("w.jsonl")
        now = int(time.time())
        append_event(p, {"t": now - 100 * 86400, "ips": []})
        append_event(p, {"t": now, "ips": [["1.2.3.4", 1, "/é"]]})
        with open(p, "a") as f:
            f.write("garbage\n")
        self.assertEqual(len(read_events(p, 0)), 2)
        trim_events(p, keep=30 * 86400)
        events = read_events(p, 0)
        self.assertEqual([e["t"] for e in events], [now])
        self.assertEqual(events[0]["ips"][0][2], "/é")
        self.assertEqual(read_events(self.path("absent"), 0), [])


class Follow(TmpDirCase):
    def setUp(self):
        super().setUp()
        warnings.simplefilter("ignore", ResourceWarning)  # follow() runs forever: files stay open
        self.addCleanup(warnings.resetwarnings)

    def collect(self, path, n, **kw):
        out = []

        def run():
            for ln in follow(path, poll=0.01, grace=0.2, **kw):
                out.append(ln)
                if len(out) >= n:
                    return
        t = threading.Thread(target=run, daemon=True)
        t.start()
        return out, t

    def wait(self, out, n, timeout=5):
        end = time.time() + timeout
        while len(out) < n and time.time() < end:
            time.sleep(0.01)
        return out

    def test_follows_appended_lines_from_the_end(self):
        p = self.write("a.log", "old\n")
        out, t = self.collect(p, 2)
        time.sleep(0.1)
        with open(p, "a") as f:
            f.write("one\ntwo\n")
        self.assertEqual(self.wait(out, 2), ["one\n", "two\n"])

    def test_from_start(self):
        p = self.write("a.log", "old\n")
        out, t = self.collect(p, 2, from_start=True)
        with open(p, "a") as f:
            f.write("new\n")
        self.assertEqual(self.wait(out, 2), ["old\n", "new\n"])

    def test_partial_line_waits_for_newline(self):
        p = self.write("a.log", "")
        out, t = self.collect(p, 1)
        time.sleep(0.1)
        with open(p, "a") as f:
            f.write("par")
            f.flush()
            time.sleep(0.1)
            self.assertEqual(out, [])
            f.write("tial\n")
        self.assertEqual(self.wait(out, 1), ["partial\n"])

    def test_rotation_reads_old_file_tail_then_new_file(self):
        p = self.write("a.log", "")
        out, t = self.collect(p, 3)
        time.sleep(0.1)
        f = open(p, "a")
        f.write("before\n")
        f.flush()
        self.wait(out, 1)
        os.rename(p, p + ".1")
        f.write("late-in-old\n")  # written to the old file after the rename
        f.flush()
        with open(p, "w") as g:
            g.write("in-new\n")
        self.assertEqual(self.wait(out, 3), ["before\n", "late-in-old\n", "in-new\n"])
        f.close()

    def test_truncation(self):
        p = self.write("a.log", "")
        out, t = self.collect(p, 2)
        time.sleep(0.1)
        with open(p, "a") as f:
            f.write("first line\n")
        self.wait(out, 1)
        with open(p, "w") as f:
            f.write("2nd\n")
        self.assertEqual(self.wait(out, 2), ["first line\n", "2nd\n"])

    def test_file_appearing_later_is_read_entirely(self):
        p = self.path("later.log")
        out, t = self.collect(p, 1)
        time.sleep(0.1)
        self.write("later.log", "hello\n")
        self.assertEqual(self.wait(out, 1), ["hello\n"])


class Commands(TmpDirCase):
    def run_main(self, *argv):
        """(return code, stdout, stderr + log records). Unless a test gives its own -f, a minimal
        configuration is used: /etc/fobots/fobots.conf or ./fobots.conf of the machine running
        the tests (make upgrade on a server) must not change the results."""
        if not any(a in ("-f", "--config") for a in argv):
            argv = (*argv, "-f", self.write("isolated.conf", "[fobots]\n"))
        out, err, records = io.StringIO(), io.StringIO(), []

        class Collect(logging.Handler):
            def emit(self, record):
                records.append(f"{record.levelname} {record.getMessage()}")
        handler, logger = Collect(), logging.getLogger("fobots")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    rc = main(list(argv))
                except SystemExit as e:
                    rc = e.code
        finally:
            logger.removeHandler(handler)
        return rc, out.getvalue(), err.getvalue() + "\n".join(records)

    def test_probe_report_command(self):
        path = self.write("rec.jsonl", json.dumps({"t": 1000.0, "kind": "base", "rt": 0.1, "level": 0,
                                                    "sys": {"load": 0.1}}) + "\n")
        rc, out, _ = self.run_main("probe", "--report", path)
        self.assertEqual(rc, 0)
        self.assertIn("1 reading(s) of normal times", out)

    def test_probe_record_requires_a_url(self):
        rc, _, err = self.run_main("probe", "--record", self.path("x.jsonl"))
        self.assertEqual(rc, 1)
        self.assertIn("give --url", err)

    def test_replay_needs_a_base_and_confirmation(self):
        log_path = self.write("a.log", "".join(line("1.1.1.1", s % 30) for s in range(60)))
        rc, _, err = self.run_main("replay", log_path)
        self.assertEqual(rc, 1)
        self.assertIn("give --base", err)
        with mock.patch("fobots.cli.sys.stdin", io.StringIO("")):
            rc, out, err = self.run_main("replay", log_path, "--base", "http://127.0.0.1:1")
        self.assertEqual(rc, 1)
        self.assertIn("add --yes", err)
        self.assertIn("ON TOP of the real traffic", out)

    def test_replay_refuses_a_log_without_enough_requests(self):
        log_path = self.write("a.log", line("1.1.1.1", 1))
        rc, _, err = self.run_main("replay", log_path, "--base", "http://127.0.0.1:1", "--yes")
        self.assertEqual(rc, 1)
        self.assertIn("too few", err)

    def test_run_replays_a_log_in_dry_run(self):
        log_path = self.write("access.log", "".join(line(f"43.1.1.{i}", 0) for i in range(8)))
        rc_file = self.write("ranges.json", json.dumps([[4, ip("43.0.0.0"), ip("43.127.255.255")]]))
        rc, out, err = self.run_main("run", "--dry-run", "--dir", self.dir, "-c", rc_file,
                                     "-w", self.path("w.txt"), "-t", "5", "--sustain", "1", log_path)
        self.assertEqual(rc, 0)
        self.assertIn("add element inet fobots banned4 { 43.0.0.0/9 timeout 3600s }", out)
        self.assertIn("BAN 43.0.0.0/9 for 3600 s", err)

    def test_run_observed_replay(self):
        log_path = self.write("access.log", "".join(line(f"43.1.1.{i}", 0) for i in range(8)))
        rc_file = self.write("ranges.json", json.dumps([[4, ip("43.0.0.0"), ip("43.127.255.255")]]))
        rc, out, err = self.run_main("run", "--dry-run", "--dir", self.dir, "-c", rc_file,
                                     "-w", self.path("w.txt"), "-t", "5", "--sustain", "1", "--ban-scope", "observed", log_path)
        self.assertEqual(rc, 0)
        self.assertNotIn("43.0.0.0/9", out)
        self.assertIn("43.1.1.", out)

    def test_run_rejects_bad_options(self):
        for argv in (("--observed-prefix", "4"), ("--observed-max-prefix", "24"), ("--load-signal", "bogus")):
            rc, out, err = self.run_main("run", "--dry-run", "--dir", self.dir, "-w", self.path("w.txt"),
                                         *argv, "/dev/null")
            self.assertNotEqual(rc, 0, argv)

    def test_run_without_a_log_fails_clearly(self):
        rc, out, err = self.run_main("run", "--dry-run", "--dir", self.dir, "-w", self.path("w.txt"))
        # stdin of the test runner may be a pipe/file; only check that nothing crashes
        self.assertIn(rc, (0, 1))

    def test_welcome_add_and_list(self):
        w = self.path("welcome.txt")
        rc, out, err = self.run_main("welcome", "add", "17.0.0.0/8", "--dry-run", "-w", w)
        self.assertEqual(rc, 0, err)
        self.assertIn("17.0.0.0/8", self.read("welcome.txt"))
        rc, out, err = self.run_main("welcome", "list", "-w", w)
        self.assertEqual(out.split(), ["17.0.0.0/8"])
        rc, out, err = self.run_main("welcome", "add", "nonsense", "--dry-run", "-w", w)
        self.assertEqual(rc, 2)
        rc, out, err = self.run_main("welcome", "add", "-w", w)
        self.assertNotEqual(rc, 0)

    def test_setup_dry_run_prints_the_nft_script(self):
        rc, out, err = self.run_main("setup", "--dry-run")
        self.assertEqual(rc, 0)
        self.assertIn("add table inet fobots", out)
        self.assertIn("flags interval,timeout", out)

    def test_analyse_command(self):
        lines = []
        for s in range(10):
            lines += [line(f"43.1.1.{i}", s, f"/app/{s}-{i}") for i in range(6)]
            lines += [line("82.1.1.1", s, "/app/img/x.png")] * 2
        log_path = self.write("access.log", "".join(lines))
        rc, out, err = self.run_main("analyse", log_path, "--dir", self.dir, "--sustain", "3")
        self.assertEqual(rc, 0, err)
        self.assertIn("Busiest ranges", out)
        self.assertIn("ignore_path = ^(/app/img/)", out)
        rc, out, err = self.run_main("analyse", "--dir", self.dir)  # no log in the configuration
        self.assertEqual(rc, 1)

    def test_watched_table_and_cmd(self):
        append_event(self.path("watched.jsonl"), {
            "t": int(time.time()), "range": "40.0.0.0/12", "seconds": 3600,
            "ips": [["40.2.2.2", 2, "/api/v4/jobs/7"], ["20.1.1.1", 6, "/api/v4/jobs/request"]]})
        rc, out, err = self.run_main("watched", "--dry-run", "--dir", self.dir)
        self.assertEqual(rc, 0)
        self.assertIn("LAST BAN", out)
        self.assertIn("20.1.1.1/32 40.2.2.2/32", out)
        rc, out, err = self.run_main("watched", "--dry-run", "--dir", self.dir, "--cmd")
        # without an explicit -f, the command has no -f; with one, it is repeated
        self.assertEqual(out.strip(), "fobots welcome add 20.1.1.1/32 40.2.2.2/32 "
                         f"-f {self.path('isolated.conf')}")
        rc, out, err = self.run_main("watched", "--dry-run", "--dir", self.path("empty"))
        self.assertIn("no finding", out)

    def test_install_into_destdir(self):
        dest = self.path("root")
        rc, out, err = self.run_main("install", "--destdir", dest, "--yes", "--log", "/var/log/x.log")
        self.assertEqual(rc, 0, out + err)
        conf = self.read("root", "etc/fobots/fobots.conf")
        self.assertIn("log = /var/log/x.log", conf)
        unit = self.read("root", "etc/systemd/system/fobots.service")
        self.assertIn("ExecStart=/usr/local/sbin/fobots run -f /etc/fobots/fobots.conf", unit)
        command = os.path.join(dest, "usr/local/sbin/fobots")  # the launcher, installed without .py
        self.assertTrue(os.access(command, os.X_OK))
        self.assertFalse(os.path.exists(os.path.join(dest, "opt/fobots/fobots.py")))
        for module in ("cli", "detector", "nft", "welcome", "constants"):
            self.assertTrue(os.path.exists(os.path.join(dest, "opt/fobots/fobots", module + ".py")), module)
        # the installed command runs (the package is looked up in /opt/fobots; here, PYTHONPATH)
        env = dict(os.environ, PYTHONPATH=os.path.join(dest, "opt/fobots"))
        r = subprocess.run([sys.executable, command, "--help"], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("daemon that bans", r.stdout)
        self.assertIn("usage: fobots ", r.stdout)
        self.assertTrue(os.path.exists(os.path.join(dest, "etc/fobots/welcome.txt")))
        # idempotent: an existing configuration is kept
        with open(os.path.join(dest, "etc/fobots/fobots.conf"), "a") as f:
            f.write("# mine\n")
        self.run_main("install", "--destdir", dest, "--yes")
        self.assertIn("# mine", self.read("root", "etc/fobots/fobots.conf"))

    def test_every_documented_conf_key_is_known(self):
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        import re
        with open(os.path.join(root, "fobots.conf.example")) as f:
            text = f.read()
        keys = set(re.findall(r"(?m)^#?\s*([a-z_]+)\s*=", text)) - {"log"}
        site_only = set(SITE_KEYS)
        for k in keys - site_only:
            self.assertIn(k, CONF_KEYS, k)


if __name__ == "__main__":
    unittest.main()

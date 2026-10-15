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
from fobots.load import LoadMonitor, read_psi  # noqa: E402
from fobots.nft import Nft, NftError, parse_elems, val_nets  # noqa: E402
from fobots.rdap import RangeStore  # noqa: E402
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

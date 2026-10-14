# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Calls to nftables (nft command) and parsing of its JSON output."""
import ipaddress
import json
import logging
import subprocess

log = logging.getLogger("fobots")


SETS = {4: "banned4", 6: "banned6"}

NFT_SETUP = """\
add table inet fobots
add set inet fobots banned4 { type ipv4_addr; flags interval,timeout; }
add set inet fobots banned6 { type ipv6_addr; flags interval,timeout; }
add chain inet fobots input { type filter hook input priority -10; policy accept; }
add rule inet fobots input tcp dport { 80, 443 } ip saddr @banned4 drop
add rule inet fobots input tcp dport { 80, 443 } ip6 saddr @banned6 drop
"""



class NftError(Exception):
    pass



def val_nets(val):
    if isinstance(val, str):
        return [ipaddress.ip_network(val, strict=False)]
    if "prefix" in val:
        p = val["prefix"]
        return [ipaddress.ip_network(f"{p['addr']}/{p['len']}", strict=False)]
    if "range" in val:
        a, b = (ipaddress.ip_address(x) for x in val["range"])
        return list(ipaddress.summarize_address_range(a, b))
    return []



def parse_elems(data):
    """[(network, remaining seconds or None)] from the output of `nft -j list set`."""
    out = []
    for item in data.get("nftables", []):
        for e in (item.get("set") or {}).get("elem", []):
            expires = None
            if isinstance(e, dict) and "elem" in e:
                expires, e = e["elem"].get("expires"), e["elem"]["val"]
            out += [(n, expires) for n in val_nets(e)]
    return out



class Nft:
    """Calls to nft; in dry-run mode, prints the scripts and simulates the sets in memory."""

    def __init__(self, binary="nft", dry_run=False):
        self.binary, self.dry_run = binary, dry_run
        self.sim = {4: [], 6: []}

    def _run(self, args, stdin=None):
        try:
            return subprocess.run([self.binary, *args], input=stdin, capture_output=True,
                                  text=True, timeout=15)
        except FileNotFoundError:
            raise NftError(f"command {self.binary!r} not found: install nftables "
                           "(e.g. apt install nftables) or give --nft-bin")
        except (OSError, subprocess.TimeoutExpired) as e:
            raise NftError(f"{self.binary}: {e}")

    def table_exists(self):
        return self._run(["list", "table", "inet", "fobots"]).returncode == 0

    def setup(self):
        r = self._run(["-f", "-"], NFT_SETUP)
        if r.returncode:
            raise NftError(r.stderr.strip())

    def selftest(self):
        """Checks on a throwaway table that nft handles interval sets with timeouts
        and that `nft -j` reads as the daemon expects. -> (ok, expires_visible, message)."""
        t, net = "fobots_selftest", ipaddress.ip_network("10.99.0.0/16")
        self._run(["delete", "table", "inet", t])  # left over from a previous attempt
        try:
            r = self._run(["-f", "-"], f"add table inet {t}\n"
                          f"add set inet {t} s {{ type ipv4_addr; flags interval,timeout; }}\n"
                          f"add element inet {t} s {{ {net} timeout 30s }}\n")
            if r.returncode:
                return False, False, r.stderr.strip() or "creation of the test table refused"
            r = self._run(["-j", "list", "set", "inet", t, "s"])
            if r.returncode:
                return False, False, "nft -j not available: " + (r.stderr.strip() or "failure")
            try:
                found = [(n, e) for n, e in parse_elems(json.loads(r.stdout))]
            except ValueError:
                return False, False, "output of nft -j unreadable"
            if not any(n == net for n, _ in found):
                return False, False, "element added but absent from the JSON output of nft"
            return True, any(e is not None for _, e in found), ""
        finally:
            self._run(["delete", "table", "inet", t])

    def elements(self, ver):
        if self.dry_run:
            return list(self.sim[ver])
        r = self._run(["-j", "list", "set", "inet", "fobots", SETS[ver]])
        if r.returncode:
            raise NftError(r.stderr.strip() or "set not found (run `setup`?)")
        return parse_elems(json.loads(r.stdout))

    def _script(self, script):
        if self.dry_run:
            print(script, end="", flush=True)
            return
        r = self._run(["-f", "-"], script)
        if r.returncode:
            raise NftError(r.stderr.strip())

    def apply(self, ver, deletes, adds, restore=()):
        """Removals then additions [(network, timeout in s)], in two transactions: nft 0.9.x
        refuses a single transaction that removes elements then adds one that overlaps them
        ("interval overlaps with an existing one"). If the addition fails, `restore`
        [(network, timeout)] puts the removed elements back."""
        name = SETS[ver]
        if deletes:
            self._script(f"delete element inet fobots {name} "
                         f"{{ {', '.join(str(n) for n in deletes)} }}\n")
            if self.dry_run:
                gone = set(deletes)
                self.sim[ver] = [(n, e) for n, e in self.sim[ver] if n not in gone]
        if adds:
            try:
                self._add(ver, adds)
            except NftError:
                if restore:
                    try:
                        self._add(ver, restore)
                    except NftError as e:
                        log.error("removed bans not restored: %s", e)
                raise

    def _add(self, ver, adds):
        elems = ", ".join(f"{n} timeout {max(1, int(t))}s" for n, t in adds)
        self._script(f"add element inet fobots {SETS[ver]} {{ {elems} }}\n")
        if self.dry_run:
            self.sim[ver] += [(n, t) for n, t in adds]

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
#
# Integration test against the REAL nft binary and kernel (nf_tables), with fake logs.
#
#   tests/integration.sh        (or: make integration)
#
# It runs inside a throwaway user+network namespace (`unshare -Urn`): no root needed, and the
# nft rules of the machine are never touched (the table is always called "inet fobots", so
# without this isolation the test would collide with a running daemon). Everything disappears
# when the script ends. Requirements: nft, unshare, python3.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)

if [ -z "${FOBOTS_IT_NS:-}" ]; then
    if ! command -v unshare >/dev/null; then
        echo "unshare not found (util-linux): cannot isolate the test from the real nft rules" >&2
        exit 1
    fi
    if ! unshare -Urn true 2>/dev/null; then
        echo "cannot create a user+network namespace (kernel.unprivileged_userns_clone=0?)." >&2
        echo "Run the script as root inside a container or a VM instead (never on a host" >&2
        echo "where fobots is running: the table inet fobots would be modified)." >&2
        exit 1
    fi
    exec unshare -Urn env FOBOTS_IT_NS=1 "$0" "$@"
fi

NFT=$(command -v nft || ls /usr/sbin/nft /sbin/nft 2>/dev/null | head -1 || true)
[ -n "$NFT" ] || { echo "nft not found (apt install nftables)" >&2; exit 1; }
W=$(mktemp -d)
echo "[fobots]" > "$W/fobots.conf"
trap 'rm -rf "$W"' EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "  ok   $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL $1"; }
section() { echo; echo "== $1"; }

# -f: a minimal configuration file, so that neither /etc/fobots/fobots.conf nor ./fobots.conf
# (e.g. ban_scope = observed) changes the scenarios.
fobots() { "$ROOT/fobots.py" "$@" -f "$W/fobots.conf" --nft-bin "$NFT"; }

# Elements of the real set, as CIDRs, one per line (read with the program's own parser).
# Arg 1: 4 or 6 (banned4/6, web ports), or the name of a set (trapped4…).
elems() {
    case $1 in [46]) set -- "banned$1" ;; esac
    "$NFT" -j list set inet fobots "$1" | python3 -c "
import json, sys
sys.path.insert(0, '$ROOT')
from fobots.nft import parse_elems
for n, _ in sorted(parse_elems(json.load(sys.stdin)), key=lambda e: e[0].network_address):
    print(n)"
}

# Number of addresses of the set that fall inside a network (arg 2), and in total (no arg).
covered() {
    elems "$1" | python3 -c "
import ipaddress, sys
inside = ipaddress.ip_network('${2:-}') if '${2:-}' else None
total = 0
for line in sys.stdin:
    n = ipaddress.ip_network(line.strip())
    if inside is None:
        total += n.num_addresses
    elif n.overlaps(inside):
        total += n.num_addresses
print(total)"
}

has()   { elems "${3:-4}" | grep -qx "$2" && ok "$1" || bad "$1 (missing $2)"; }
hasnt() { elems "${3:-4}" | grep -qx "$2" && bad "$1 (unexpected $2)" || ok "$1"; }
equal() { [ "$2" = "$3" ] && ok "$1" || bad "$1 (expected $3, got $2)"; }

# mklog FILE IP... : one request per IP, all at the same second.
mklog() {
    python3 - "$@" <<'PY'
import sys
out, ips = sys.argv[1], sys.argv[2:]
with open(out, "w") as f:
    for ip in ips:
        f.write(f'{ip} - - [14/Oct/2026:10:00:00 +0000] "GET /x HTTP/1.1" 200 10 "-" "it"\n')
PY
}
seq_ips() { local p=$1 a=$2 b=$3 i; for ((i = a; i <= b; i++)); do echo "$p$i"; done; }

# RDAP is never queried: the known ranges are given in a cache file.
python3 - "$W/ranges.json" <<'PY'
import ipaddress, json, sys
a = lambda s: [int(ipaddress.ip_address(s)), ]
ranges = [("43.0.0.0", "43.127.255.255"), ("34.64.0.0", "34.127.255.255"),
          ("2a00:1450::", "2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff")]
json.dump([[ipaddress.ip_address(s).version, int(ipaddress.ip_address(s)), int(ipaddress.ip_address(e))]
           for s, e in ranges], open(sys.argv[1], "w"))
PY
: > "$W/welcome.txt"
# one burst is enough here; the scenarios ban whole allocations unless they say --ban-scope observed
run() { fobots run --dir "$W" --cache "$W/ranges.json" -w "$W/welcome.txt" --sustain 1 --ban-scope allocation "$@" 2>"$W/err"; }
reset() { local s; for s in banned4 banned6 trapped4 trapped6; do "$NFT" flush set inet fobots $s; done; }
drops() { "$NFT" list chain inet fobots input | grep -c ' drop$'; }

echo "nft: $("$NFT" --version)   kernel: $(uname -r)"

section "setup completes a table of an older version (bans kept)"
"$NFT" -f - <<'NFT'
add table inet fobots
add set inet fobots banned4 { type ipv4_addr; flags interval,timeout; }
add set inet fobots banned6 { type ipv6_addr; flags interval,timeout; }
add chain inet fobots input { type filter hook input priority -10; policy accept; }
add rule inet fobots input tcp dport { 80, 443 } ip saddr @banned4 drop
add rule inet fobots input tcp dport { 80, 443 } ip6 saddr @banned6 drop
add element inet fobots banned4 { 43.9.9.0/24 timeout 1h }
NFT
out=$(fobots setup --dir "$W" 2>&1)
case $out in *"updated (bans kept)"*) ok "setup updates it" ;; *) bad "setup updates it ($out)" ;; esac
has "the ban of the older table is kept" 43.9.9.0/24
chain=$("$NFT" list chain inet fobots input)
case $chain in *"udp dport 443 ip saddr @banned4 drop"*) ok "HTTP/3 (UDP 443) is blocked" ;; *) bad "HTTP/3 (UDP 443) is blocked ($chain)" ;; esac
case $chain in *"ip saddr @trapped4 drop"*) ok "the every-port set is wired" ;; *) bad "the every-port set is wired ($chain)" ;; esac
equal "6 rules, none duplicated" "$(drops)" 6
out=$(fobots setup --dir "$W" 2>&1)
case $out in *"already in place"*) ok "setup is then idempotent" ;; *) bad "setup is then idempotent ($out)" ;; esac
equal "still 6 rules" "$(drops)" 6
"$NFT" delete table inet fobots

section "setup"
fobots setup --dir "$W" >/dev/null 2>&1 && ok "setup creates the table" || bad "setup creates the table"
out=$(fobots setup --dir "$W" 2>&1)
case $out in *"already in place"*) ok "setup is idempotent" ;; *) bad "setup is idempotent ($out)" ;; esac
sel=$(python3 - <<PY
import sys
sys.path.insert(0, "$ROOT")
from fobots.nft import Nft
print(Nft("$NFT").selftest())
PY
)
case $sel in "(True,"*) ok "nft handles interval sets with timeouts ($sel)" ;; *) bad "nft self-test: $sel" ;; esac

section "ban of the whole allocation (ban_scope = allocation)"
mklog "$W/log" $(seq_ips 43.1.1. 1 8)
run -t 5 "$W/log"
equal "exit status" $? 0
has "the allocation 43.0.0.0/9 is banned" 43.0.0.0/9
out=$(fobots bans --dir "$W" 2>&1)
case $out in *43.0.0.0/9*) ok "fobots bans lists it" ;; *) bad "fobots bans lists it ($out)" ;; esac

section "a short burst is not banned (sustain)"
reset
mklog "$W/log" $(seq_ips 43.1.1. 1 8)
run -t 5 --sustain 5 "$W/log"
equal "a one-second burst is tolerated" "$(covered 4)" 0

section "tight ban (ban_scope = observed)"
reset
mklog "$W/log" 34.100.9.9 $(seq_ips 34.67.1. 1 8)
run -t 5 --ban-scope observed "$W/log"
equal "exit status" $? 0
equal "only addresses of the scraper's /24 are banned" "$(covered 4 34.64.0.0/10)" "$(covered 4 34.67.1.0/24)"
hasnt "the bystander is not banned" 34.100.9.9/32
# the ban triggers at the 6th request, so it covers the scraper IPs seen by then (at least 5)
[ "$(covered 4 34.67.1.0/24)" -ge 5 ] && ok "the ban covers the scraper IPs seen so far" || bad "scraper IPs covered"

section "wider ban replacing smaller ones (the nft 0.9.x overlap case)"
mklog "$W/log" $(seq_ips 34.67.2. 1 3) $(for o in 66 68 70 72 74 76; do echo "34.$o.1.1"; done)
run -t 8 --ban-scope observed "$W/log"
equal "exit status" $? 0
grep -q "refused\|overlap" "$W/err" && bad "nft refused a transaction: $(grep -m1 'refused\|overlap' "$W/err")" || ok "no nft refusal"
has "the /16 block replaces the small bans" 34.67.0.0/16
equal "nothing inside 34.67.0.0/16 except the block" "$(covered 4 34.67.0.0/16)" 65536
# same, with the whole allocation as the fallback
reset
mklog "$W/log" $(seq_ips 34.67.1. 1 8)
run -t 5 --ban-scope observed "$W/log"
mklog "$W/log" $(for o in 66 68 70 72 74 76 78 80 82; do echo "34.$o.1.1"; done)
run -t 8 --ban-scope observed --observed-max-prefix 0 "$W/log"
equal "exit status" $? 0
grep -q "refused\|overlap" "$W/err" && bad "nft refused a transaction" || ok "no nft refusal"
has "the allocation 34.64.0.0/10 replaces the tight ban" 34.64.0.0/10
equal "the set holds only the allocation" "$(covered 4)" 4194304

section "welcome add carves a hole in a ban"
fobots welcome add 34.67.0.0/16 --dir "$W" -w "$W/welcome.txt" >/dev/null 2>&1
equal "exit status" $? 0
equal "nothing left inside the protected /16" "$(covered 4 34.67.0.0/16)" 0
equal "the rest of the /10 is still banned" "$(covered 4)" $((4194304 - 65536))
grep -qx "34.67.0.0/16" <(sed 's/ *#.*//' "$W/welcome.txt") && ok "welcome.txt updated" || bad "welcome.txt updated"
: > "$W/welcome.txt"

section "welcome list is honoured by the daemon"
reset
echo "43.0.0.0/9" > "$W/welcome.txt"
mklog "$W/log" $(seq_ips 43.1.1. 1 8)
run -t 5 "$W/log"
equal "nothing banned inside the welcome range" "$(covered 4)" 0
: > "$W/welcome.txt"

section "IPv6"
reset
mklog "$W/log" $(seq_ips 2a00:1450::1: 1 8 | sed 's/::1:\([0-9]*\)/::\1/')
run -t 5 "$W/log"
equal "exit status" $? 0
has "the IPv6 allocation is banned" 2a00:1450::/32 6

section "trap_scope = all: every port, except for the IPs of welcome.txt"
reset
python3 - "$W/log" <<'PY'
import sys
with open(sys.argv[1], "w") as f:
    for s, path in enumerate(("/.env", "/wp-login.php")):
        for ip in ("20.1.1.1", "30.1.1.1", "40.1.1.1", "50.1.1.1", "60.1.1.1"):
            f.write(f'{ip} - - [14/Oct/2026:10:00:0{s} +0000] "GET {path} HTTP/1.1" 404 10 "-" "it"\n')
PY
echo 20.1.1.1 > "$W/welcome-traps.txt"
fobots run --dir "$W" --cache "$W/ranges.json" -w "$W/welcome-traps.txt" -t 1000 \
    --traps --trap-ban --trap-scope all "$W/log" 2>"$W/err"
equal "exit status" $? 0
has "a flagged IP is banned on every port" 30.1.1.1/32 trapped4
has "... and the others too" 60.1.1.1/32 trapped4
has "the IP of welcome.txt is banned on the web ports only" 20.1.1.1/32 4
hasnt "... and keeps the other ports" 20.1.1.1/32 trapped4
out=$(fobots bans --dir "$W" --no-lookup 2>&1)
case $out in *"30.1.1.1/32"*"all ports"*) ok "fobots bans shows the scope" ;; *) bad "fobots bans shows the scope ($out)" ;; esac
fobots welcome add 30.1.1.1 --dir "$W" -w "$W/welcome-traps.txt" >/dev/null 2>&1
hasnt "welcome add clears the every-port set" 30.1.1.1/32 trapped4

section "expiry (real kernel timeout)"
reset
mklog "$W/log" $(seq_ips 43.1.1. 1 8)
run -t 5 --ban-time 2s "$W/log"
[ "$(covered 4)" -gt 0 ] && ok "banned for 2 s" || bad "banned for 2 s"
sleep 3.5
equal "the ban expired by itself" "$(covered 4)" 0

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

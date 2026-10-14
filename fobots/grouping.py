# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Grouping of observed IPs (ban_scope = observed)."""
from collections import Counter


def cluster_ips(ips, span):
    """Groups of IPs: [(integer address, requests)] -> [[start, end, requests, number of IPs]].
    Greedy sweep: a group grows as long as its extent stays under `span` addresses;
    it is bounded by its extreme IPs (observed interval), not by a CIDR prefix, so
    two neighbouring IPs on either side of a block boundary stay together."""
    out = []
    for a, n in sorted(ips):
        if out and a - out[-1][0] < span:
            c = out[-1]
            c[1], c[2], c[3] = a, c[2] + n, c[3] + 1
        else:
            out.append([a, a, n, 1])
    return out



def pick_groups(groups, coverage, max_groups):
    """The most active groups that cover `coverage` of the requests, or None if more than
    `max_groups` would be needed."""
    total = sum(g[2] for g in groups)
    picked, got = [], 0
    for g in sorted(groups, key=lambda g: -g[2]):
        picked.append(g)
        got += g[2]
        if got >= coverage * total:
            break
    return picked if len(picked) <= max_groups else None



def wide_blocks(ips, lo, hi, shift, coverage):
    """Fallback when the traffic is scattered: the aligned blocks of 2**shift addresses (cut at
    the bounds [lo, hi] of the allocation) that carry `coverage` of the requests -> [(start, end)]."""
    per = Counter()
    for a, n in ips:
        per[a >> shift] += n
    total, got, out = sum(per.values()), 0, []
    for b, n in per.most_common():
        out.append((max(b << shift, lo), min(((b + 1) << shift) - 1, hi)))
        got += n
        if got >= coverage * total:
            break
    return sorted(out)

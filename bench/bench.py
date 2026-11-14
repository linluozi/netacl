"""Benchmark: compiled interval table vs the naive per-rule scan.

Run from the repository root:

    python bench/bench.py --rules 1000 --queries 5000 --repeat 5

Every number is printed from a real run; no timing is asserted in the test
suite because shared-host noise makes such assertions flaky.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netacl.core import ACL  # noqa: E402

SEED = 20261115


def make_rules(count: int, seed: int = SEED) -> list[str]:
    rng = random.Random(seed)
    lines = []
    for _ in range(count):
        prefix = rng.randint(8, 32)
        address = rng.randrange(0, 1 << 32) & 0xFFFFFFFF
        network = ipaddress.ip_network((address, prefix), strict=False)
        lines.append("%s %s" % (rng.choice(["allow", "deny"]), network))
    return lines


def make_queries(count: int, seed: int = SEED) -> list[str]:
    rng = random.Random(seed + 1)
    return [str(ipaddress.IPv4Address(rng.randrange(0, 1 << 32))) for _ in range(count)]


def timed(fn, repeat: int) -> dict:
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    samples.sort()
    return {
        "median_s": statistics.median(samples),
        "min_s": samples[0],
        "max_s": samples[-1],
        "samples_s": samples,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", type=int, default=1000)
    parser.add_argument("--queries", type=int, default=5000)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--json", help="write raw samples here")
    args = parser.parse_args()

    lines = make_rules(args.rules)
    queries = make_queries(args.queries)

    t0 = time.perf_counter()
    acl = ACL(lines)
    build_s = time.perf_counter() - t0

    def fast():
        for ip in queries:
            acl.decide(ip)

    def slow():
        for ip in queries:
            acl.naive_decide(ip)

    # Warm up both paths, then time them.
    fast()
    slow()
    fast_run = timed(fast, args.repeat)
    slow_run = timed(slow, args.repeat)

    checksum_fast = sum(1 for ip in queries if acl.decide(ip).rule_index is not None)
    checksum_slow = sum(1 for ip in queries if acl.naive_decide(ip).rule_index is not None)
    assert checksum_fast == checksum_slow

    result = {
        "seed": SEED,
        "rules": len(lines),
        "intervals": acl.interval_count,
        "queries": len(queries),
        "build_s": build_s,
        "decide": fast_run,
        "naive": slow_run,
        "speedup_median": slow_run["median_s"] / fast_run["median_s"],
        "matched_queries": checksum_fast,
        "checksum_equal": checksum_fast == checksum_slow,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

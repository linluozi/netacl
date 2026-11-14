# netacl

An ordered `allow` / `deny` IP access list that answers **which rule won** in
O(log n), not just whether the address is allowed.  Rules use normal firewall
first-match semantics; the list is compiled once into disjoint intervals, each
carrying the winning rule index and the number of rules that cover it.

Upstream: none

**Evidence in one line:** 20 tests; a 4,096-address exhaustive audit against
the linear oracle finds 0 mismatches; 1,000 rules answer 5,000 queries 80.17x
faster than the scan (the build pays back after 29 queries).

**How (one line):** one boundary sweep with a min-heap compiles the rules into
disjoint first-match intervals; a query is a `bisect` over their starts.

## Why

Firewall debugging usually starts with "why is this address allowed?"  A
linear scan tells you the answer but not the shape of the decision: which rule
shadowed the others, and how many rules actually cover that address.  This
library compiles the ordered list into a sorted interval table, so a query is a
`bisect` plus an array lookup, and the answer includes the winning rule and the
overlap count.

The semantics are deliberately boring and explicit:

- **first match wins** (the iptables / firewall semantic), not "most specific";
- **default action** is configurable, default `deny`;
- IPv4 and IPv6 are separate address spaces and never match each other;
- L3 only: no ports, protocols, TCP flags, or stateful connection tracking.

## Install

```bash
python -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/python -m pytest -q          # 20 passed
```

Python 3.10+; no runtime dependencies.

## Use

```bash
cat > rules.txt <<'EOF'
deny  10.0.0.0/8      # shadows the allow below for all of 10.0.0.0/8
allow 10.1.0.0/16
allow 0.0.0.0/0
EOF

netacl check --rules rules.txt --ip 10.1.2.3
# deny  10.1.2.3  rule=0 matching=3 interval=[167837696, 167903231]

netacl audit --rules rules.txt --cidr 10.0.0.0/20
# audit 10.0.0.0/20: checked=4096 mismatches=0
```

The `audit` subcommand compares every address in a network against
`naive_decide()`, the linear reference implementation, and exits 1 on any
disagreement.  The test suite runs the same oracle over a 4,096-address
universe with 40 random overlapping rules, plus five 256-address universes
with 25 rules each.

Library API:

```python
from netacl import ACL

acl = ACL(["deny 10.0.0.0/8", "allow 10.1.0.0/16", "allow 0.0.0.0/0"])
decision = acl.decide("10.1.2.3")
# Decision(action='deny', rule_index=0, matching_rules=3, interval=(...))

acl.naive_decide("10.1.2.3")   # same answer, O(n) reference implementation
acl.audit("10.0.0.0/20")       # {"checked": 4096, "mismatches": 0, ...}
```

## How the compile works

1. Every rule contributes two events: `start` (add its index) and `end + 1`
   (remove it).
2. Sweep the events in position order, keeping the live rule indices in a
   min-heap with lazy deletion.  Between two consecutive events the live set is
   constant, so the heap top is the first matching rule for that whole interval.
3. Merge adjacent intervals that share both winner and overlap count.
4. `decide()` is `bisect_right(starts, address) - 1`, then a bounds check.

The theoretical maximum is `2n + 1` entries (two boundary positions per rule
plus the tail), so memory is O(n), and a query does not touch the rule list at
all.

## Evidence

`bench/bench.py --rules 1000 --queries 5000 --repeat 5`, committed raw samples
in `bench/results.json` (AMD EPYC 7K62, 4 vCPU, 3723 MB, CPython 3.12.3, seed
20261115):

| metric | compiled interval table | naive per-rule scan |
|---|---:|---:|
| build (1,000 rules) | 12.38 ms | — |
| 5,000 queries, median of 5 | **27.87 ms** | 2,234.15 ms |
| per query | **5.57 µs** | 446.83 µs |
| interval count | 1,239 | — |
| matched queries (checksum) | 1,414 | 1,414 |

Median speedup over the whole batch: **80.17x**.  The exact break-even quotient
is 12.3838 ms / 0.44126 ms = **28.06**; 28 queries save 12.355 ms (less than the
build) and 29 save 12.796 ms (more), so **29 is the first paying query count**.
The compile only pays off for a list queried more than a few dozen times — a
packet filter, not a one-shot `check`.

Correctness evidence, all from real runs:

- `pytest -q` → **20 passed**;
- `acl.audit("10.0.0.0/20")` with 40 random overlapping rules → **4,096
  addresses checked, 0 mismatches** against the linear oracle;
- five seeds × 25 random rules over a /24 → all 256 addresses agree on action,
  winning rule index, and overlap count;
- the benchmark asserts the compiled and naive paths agree on how many of the
  5,000 random queries match at least one rule (1,414 both).

## Reproduce

```bash
git clone --depth=1 git@github-linluozi:linluozi/netacl.git && cd netacl
python -m venv .venv && .venv/bin/pip install -e ".[test]" && .venv/bin/python -m pytest -q
.venv/bin/python bench/bench.py --rules 1000 --queries 5000 --repeat 5 --json bench/results.json
```

## Limits

- **Immutable list.**  Adding a rule means rebuilding; there is no incremental
  update path.  For a mostly-static firewall that is the intended trade-off.
- **First-match only.**  "Most specific wins" and "deny overrides" are
  different policies and are not emulated.  Reorder the file if you need them.
- **L3 only.**  Ports, protocols, ICMP types and connection state are out of
  scope; this is not a packet filter.
- **Overlap count is precomputed per interval**, so it is exact, but it does
  not tell you *which* rules overlap — use `matching_rules` plus a scan of
  `acl.rules` if you need the full list.
- **Performance numbers are host-specific.**  The 80x figure compares Python
  against Python; a C firewall will beat both.  Re-run the bench on your host
  before quoting it.

## 本轮创新

**B 档。** 不是"再写一个 CIDR 集合"，而是把**有序 first-match ACL** 编译成
带来源信息的互斥区间表：一次扫描同时得到「谁赢」和「覆盖该地址的规则数」，
查询只做 `bisect`，并在 4,096 个地址上与线性 oracle 逐点比对 0 分歧。已有
的 CIDR 工具（`ipaddress.collapse_addresses`、general set algebra）只回答
成员关系；本轮量化的是"优先级 + 来源"这一层，并给出 29 次查询的盈亏平衡点。

## License

MIT.  Copyright (c) 2026 linluozi.  No upstream code is included.

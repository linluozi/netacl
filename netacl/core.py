"""First-match ACL evaluation with O(log n) queries and rule provenance.

An access control list is an ordered list of ``allow``/``deny`` rules over IP
networks.  The address is decided by the **first** rule that contains it (the
iptables / firewall semantic), not by a set union.

Naively that is one linear scan per packet.  Here the list is compiled once
into a sorted table of disjoint elementary intervals, each labelled with the
index of the first rule that matches it; a query is then a ``bisect`` over the
interval starts.  The build is a boundary sweep with a min-heap, so the winner
of every interval is obtained without comparing all rules per address.
"""

from __future__ import annotations

import bisect
import heapq
import ipaddress
from dataclasses import dataclass

ACTIONS = ("allow", "deny")
_ANY = {4: ipaddress.IPv4Network("0.0.0.0/0"), 6: ipaddress.IPv6Network("::/0")}


@dataclass(frozen=True)
class Rule:
    index: int
    action: str
    network: object  # ipaddress.IPv4Network | ipaddress.IPv6Network

    @property
    def version(self) -> int:
        return self.network.version

    @property
    def start(self) -> int:
        return int(self.network.network_address)

    @property
    def end(self) -> int:
        return int(self.network.broadcast_address)

    def contains(self, address: int) -> bool:
        return self.start <= address <= self.end


@dataclass(frozen=True)
class Decision:
    ip: str
    action: str
    rule_index: int | None
    rule: Rule | None
    matching_rules: int
    interval: tuple[int, int] | None

    def as_dict(self) -> dict:
        return {
            "ip": self.ip,
            "action": self.action,
            "rule_index": self.rule_index,
            "rule": None
            if self.rule is None
            else {
                "index": self.rule.index,
                "action": self.rule.action,
                "network": str(self.rule.network),
            },
            "matching_rules": self.matching_rules,
            "interval": None if self.interval is None else list(self.interval),
        }


def parse_rule(line: str, index: int) -> Rule | None:
    """Parse ``allow 10.0.0.0/8`` / ``deny 2001:db8::/32``; ``#`` comments."""
    stripped = line.split("#", 1)[0].strip()
    if not stripped:
        return None
    parts = stripped.split()
    if len(parts) != 2:
        raise ValueError("rule must be '<allow|deny> <network>': %r" % line)
    action, network_text = parts
    action = action.lower()
    if action not in ACTIONS:
        raise ValueError("unknown action %r (expected allow or deny)" % action)
    if network_text == "*":
        raise ValueError("use 0.0.0.0/0 and ::/0 instead of '*'")
    network = ipaddress.ip_network(network_text, strict=True)
    return Rule(index=index, action=action, network=network)


class ACL:
    """An ordered allow/deny list with a compiled first-match interval table."""

    def __init__(self, rules, default: str = "deny"):
        if default not in ACTIONS:
            raise ValueError("default must be 'allow' or 'deny'")
        self.default = default
        parsed = []
        for position, item in enumerate(rules):
            if isinstance(item, Rule):
                rule = Rule(index=position, action=item.action, network=item.network)
            elif isinstance(item, str):
                rule = parse_rule(item, position)
                if rule is None:
                    continue
            else:
                raise TypeError("rules must be Rule objects or strings")
            parsed.append(rule)
        if not parsed:
            raise ValueError("ACL needs at least one rule")
        self.rules = tuple(parsed)
        self._tables = {}
        for version in (4, 6):
            family_rules = [r for r in self.rules if r.version == version]
            if family_rules:
                self._tables[version] = self._compile(family_rules)

    @classmethod
    def from_lines(cls, lines, default: str = "deny") -> "ACL":
        return cls(list(lines), default=default)

    @staticmethod
    def _compile(rules) -> tuple[list[int], list[int], list[int], list[int]]:
        """Boundary sweep; returns (starts, ends, winners, match counts)."""
        events = []
        for rule in rules:
            events.append((rule.start, 0, rule.index))  # 0 = add
            events.append((rule.end + 1, 1, rule.index))  # 1 = remove
        events.sort()

        alive = set()
        heap: list[int] = []
        raw = []  # (start, end, winner, active_rule_count)
        i = 0
        while i < len(events):
            position = events[i][0]
            while i < len(events) and events[i][0] == position:
                _, kind, index = events[i]
                if kind == 0:
                    alive.add(index)
                    heapq.heappush(heap, index)
                else:
                    alive.discard(index)
                i += 1
            if i >= len(events):
                break
            while heap and heap[0] not in alive:
                heapq.heappop(heap)
            next_position = events[i][0]
            if heap:
                raw.append((position, next_position - 1, heap[0], len(alive)))

        merged = []  # type: list[tuple[int, int, int, int]]
        for start, end, winner, count in raw:
            if (
                merged
                and merged[-1][2] == winner
                and merged[-1][3] == count
                and merged[-1][1] + 1 == start
            ):
                merged[-1] = (merged[-1][0], end, winner, count)
            else:
                merged.append((start, end, winner, count))
        starts = [m[0] for m in merged]
        ends = [m[1] for m in merged]
        winners = [m[2] for m in merged]
        counts = [m[3] for m in merged]
        return starts, ends, winners, counts

    @property
    def interval_count(self) -> int:
        return sum(len(table[0]) for table in self._tables.values())

    def _locate(self, address: int, version: int):
        table = self._tables.get(version)
        if table is None:
            return None
        starts, ends, winners, counts = table
        position = bisect.bisect_right(starts, address) - 1
        if position < 0 or address > ends[position]:
            return None
        return (
            winners[position],
            (starts[position], ends[position]),
            counts[position],
        )

    def decide(self, ip: str) -> Decision:
        """First matching rule, in O(log n) after the one-off compile."""
        parsed = ipaddress.ip_address(ip)
        address = int(parsed)
        located = self._locate(address, parsed.version)
        if located is None:
            return Decision(str(parsed), self.default, None, None, 0, None)
        winner, interval, matches = located
        rule = self.rules[winner]
        return Decision(
            str(parsed), rule.action, rule.index, rule, matches, interval
        )

    def naive_decide(self, ip: str) -> Decision:
        """Reference implementation: scan the rules in order.  Used by audits."""
        parsed = ipaddress.ip_address(ip)
        address = int(parsed)
        matching = 0
        for rule in self.rules:
            if rule.version != parsed.version:
                continue
            if rule.contains(address):
                matching += 1
                if matching == 1:
                    winner = rule
        if matching == 0:
            return Decision(str(parsed), self.default, None, None, 0, None)
        return Decision(
            str(parsed),
            winner.action,
            winner.index,
            winner,
            matching,
            None,
        )

    def audit(self, network: str, limit: int | None = None) -> dict:
        """Compare ``decide`` with ``naive_decide`` for every address in a net."""
        net = ipaddress.ip_network(network, strict=False)
        checked = 0
        mismatches = []
        for address in net:
            checked += 1
            fast = self.decide(str(address))
            slow = self.naive_decide(str(address))
            if (
                fast.action != slow.action
                or fast.rule_index != slow.rule_index
                or fast.matching_rules != slow.matching_rules
            ):
                mismatches.append(
                    {"ip": str(address), "fast": fast.as_dict(), "slow": slow.as_dict()}
                )
                if len(mismatches) >= 10:
                    break
            if limit is not None and checked >= limit:
                break
        return {
            "network": str(net),
            "checked": checked,
            "mismatches": len(mismatches),
            "first_mismatches": mismatches,
        }

    def __len__(self) -> int:
        return len(self.rules)

    def __repr__(self) -> str:
        return "ACL(%d rules, %d intervals, default=%s)" % (
            len(self.rules),
            self.interval_count,
            self.default,
        )

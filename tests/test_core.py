import ipaddress
import random

import pytest

from netacl.core import ACL, Rule, parse_rule


def test_parse_rule_and_comments():
    rule = parse_rule("  ALLOW 10.0.0.0/8  # office", 3)
    assert rule is not None
    assert rule.action == "allow"
    assert rule.index == 3
    assert str(rule.network) == "10.0.0.0/8"
    assert parse_rule("# just a comment", 0) is None
    assert parse_rule("", 0) is None


def test_parse_rule_rejects_bad_input():
    for line in ["allow", "permit 10.0.0.0/8", "allow 10.0.0.1/8", "allow *"]:
        with pytest.raises(ValueError):
            parse_rule(line, 0)


def test_first_match_wins_not_best_match():
    acl = ACL(["deny 10.0.0.0/8", "allow 10.1.0.0/16", "allow 0.0.0.0/0"])
    assert acl.decide("10.1.2.3").action == "deny"
    assert acl.decide("10.1.2.3").rule_index == 0

    bcl = ACL(["allow 10.1.0.0/16", "deny 10.0.0.0/8"])
    assert bcl.decide("10.1.2.3").action == "allow"
    assert bcl.decide("10.2.2.3").action == "deny"


def test_default_action_and_boundaries():
    acl = ACL(["deny 10.0.0.0/8"], default="deny")
    assert acl.decide("11.0.0.1").rule_index is None
    assert acl.decide("11.0.0.1").action == "deny"
    assert acl.decide("10.255.255.255").rule_index == 0

    any4 = ACL(["allow 0.0.0.0/0"])
    assert any4.decide("0.0.0.0").rule_index == 0
    assert any4.decide("255.255.255.255").rule_index == 0
    assert any4.interval_count == 1

    single = ACL(["deny 192.0.2.7/32"])
    assert single.decide("192.0.2.7").action == "deny"
    assert single.decide("192.0.2.8").rule_index is None


def test_ipv6_is_separate_from_ipv4():
    acl = ACL(["allow 2001:db8::/32", "deny ::/0", "allow 10.0.0.0/8"])
    assert acl.decide("2001:db8::1").action == "allow"
    assert acl.decide("2001:db9::1").action == "deny"
    assert acl.decide("10.1.2.3").action == "allow"
    assert acl.decide("11.1.2.3").rule_index is None


def test_matching_rules_counts_every_cover():
    acl = ACL(
        [
            "deny 10.0.0.0/8",
            "allow 10.1.0.0/16",
            "allow 10.1.2.0/24",
            "allow 0.0.0.0/0",
        ]
    )
    decision = acl.decide("10.1.2.3")
    assert decision.matching_rules == 4
    assert decision.rule_index == 0
    assert acl.decide("11.0.0.1").matching_rules == 1


def test_intervals_are_disjoint_and_sorted():
    acl = ACL(
        [
            "deny 10.0.0.0/8",
            "allow 10.0.0.0/9",
            "deny 10.128.0.0/9",
            "allow 0.0.0.0/0",
        ]
    )
    starts, ends, winners, counts = acl._tables[4]
    assert len(starts) == len(ends) == len(winners) == len(counts)
    assert starts == sorted(starts)
    for i in range(1, len(starts)):
        assert ends[i - 1] + 1 == starts[i]


def test_exhaustive_audit_matches_naive_oracle():
    rng = random.Random(20261115)
    lines = []
    for i in range(40):
        prefix = rng.randint(20, 32)
        base = rng.randrange(0, 4096)
        network = ipaddress.ip_network(
            ("10.0.%d.%d/%d" % (base // 256, base % 256, prefix)), strict=False
        )
        lines.append("%s %s" % (rng.choice(["allow", "deny"]), network))
    acl = ACL(lines)
    report = acl.audit("10.0.0.0/20")
    assert report["checked"] == 4096
    assert report["mismatches"] == 0, report["first_mismatches"]


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_random_small_universe_matches_naive(seed):
    rng = random.Random(seed)
    lines = []
    for _ in range(25):
        prefix = rng.randint(24, 32)
        last = rng.randrange(0, 256)
        network = ipaddress.ip_network("10.0.0.%d/%d" % (last, prefix), strict=False)
        lines.append("%s %s" % (rng.choice(["allow", "deny"]), network))
    acl = ACL(lines)
    for octet in range(256):
        ip = "10.0.0.%d" % octet
        fast, slow = acl.decide(ip), acl.naive_decide(ip)
        assert (fast.action, fast.rule_index, fast.matching_rules) == (
            slow.action,
            slow.rule_index,
            slow.matching_rules,
        ), ip


def test_build_is_deterministic_and_order_sensitive():
    lines = ["deny 10.0.0.0/9", "allow 10.0.0.0/8", "allow 0.0.0.0/0"]
    first = ACL(lines)
    second = ACL(lines)
    assert first._tables == second._tables
    assert first.decide("10.1.1.1").action == "deny"
    reordered = ACL(list(reversed(lines)))
    assert reordered.decide("10.1.1.1").action == "allow"


def test_rule_objects_are_reindexed_by_position():
    rules = [
        Rule(99, "allow", ipaddress.ip_network("10.0.0.0/8")),
        Rule(42, "deny", ipaddress.ip_network("0.0.0.0/0")),
    ]
    acl = ACL(rules)
    assert acl.decide("10.1.1.1").rule_index == 0
    assert acl.decide("11.1.1.1").rule_index == 1


def test_invalid_construction():
    with pytest.raises(ValueError):
        ACL([])
    with pytest.raises(ValueError):
        ACL(["allow 10.0.0.0/8"], default="maybe")
    with pytest.raises(TypeError):
        ACL([123])

"""Command line interface for netacl."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import ACL


def _load_rules(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.readlines()


def _rule_payload(acl: ACL) -> list[dict]:
    return [
        {
            "index": rule.index,
            "action": rule.action,
            "network": str(rule.network),
        }
        for rule in acl.rules
    ]


def _cmd_check(args: argparse.Namespace) -> int:
    acl = ACL(_load_rules(args.rules), default=args.default)
    decision = acl.decide(args.ip)
    payload = {"acl": _rule_payload(acl), "decision": decision.as_dict()}
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
    print(
        "%-5s %-39s rule=%s matching=%d interval=%s"
        % (
            decision.action,
            decision.ip,
            "-" if decision.rule_index is None else decision.rule_index,
            decision.matching_rules,
            "-" if decision.interval is None else list(decision.interval),
        )
    )
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    acl = ACL(_load_rules(args.rules), default=args.default)
    report = acl.audit(args.cidr, limit=args.limit)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
    print(
        "audit %s: checked=%d mismatches=%d"
        % (report["network"], report["checked"], report["mismatches"])
    )
    for mismatch in report["first_mismatches"]:
        print("  MISMATCH %s fast=%r slow=%r" % (
            mismatch["ip"], mismatch["fast"], mismatch["slow"]
        ))
    return 0 if report["mismatches"] == 0 else 1


def _cmd_eval(args: argparse.Namespace) -> int:
    acl = ACL(_load_rules(args.rules), default=args.default)
    rows = []
    with open(args.ips, "r", encoding="utf-8") as handle:
        for line in handle:
            ip = line.split("#", 1)[0].strip()
            if not ip:
                continue
            decision = acl.decide(ip)
            rows.append(decision.as_dict())
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, indent=2, sort_keys=True)
            handle.write("\n")
    for row in rows:
        print(
            "%-5s %-39s rule=%s"
            % (
                row["action"],
                row["ip"],
                "-" if row["rule_index"] is None else row["rule_index"],
            )
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netacl",
        description="Ordered allow/deny ACL evaluation with first-match provenance.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("--rules", required=True, help="file with one rule per line")
        p.add_argument("--default", choices=["allow", "deny"], default="deny")
        p.add_argument("--json", help="write the machine-readable result here")

    check = sub.add_parser("check", help="evaluate one address")
    common(check)
    check.add_argument("--ip", required=True)
    check.set_defaults(func=_cmd_check)

    audit = sub.add_parser("audit", help="compare with the naive oracle over a network")
    common(audit)
    audit.add_argument("--cidr", required=True)
    audit.add_argument("--limit", type=int, default=None)
    audit.set_defaults(func=_cmd_audit)

    evaluate = sub.add_parser("eval", help="evaluate a file of addresses")
    common(evaluate)
    evaluate.add_argument("--ips", required=True)
    evaluate.set_defaults(func=_cmd_eval)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

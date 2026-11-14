"""netacl: ordered allow/deny ACLs with O(log n) first-match queries."""

__version__ = "0.1.0"

from .core import ACL, Decision, Rule, parse_rule

__all__ = ["ACL", "Decision", "Rule", "parse_rule", "__version__"]

import json

from netacl.cli import main


def _write(path, text):
    path.write_text(text)
    return str(path)


def test_cli_check(tmp_path):
    rules = _write(tmp_path / "rules.txt", "deny 10.0.0.0/8\nallow 0.0.0.0/0\n")
    out = tmp_path / "check.json"
    rc = main(["check", "--rules", rules, "--ip", "10.1.2.3", "--json", str(out)])
    assert rc == 0
    payload = json.loads(out.read_text())
    assert payload["decision"]["action"] == "deny"
    assert payload["decision"]["rule_index"] == 0
    assert payload["decision"]["matching_rules"] == 2


def test_cli_audit_is_clean(tmp_path, capsys):
    rng_lines = [
        "deny 10.0.0.0/9",
        "allow 10.0.0.0/10",
        "allow 10.128.0.0/9",
        "deny 10.0.4.0/24",
        "allow 0.0.0.0/0",
    ]
    rules = _write(tmp_path / "rules.txt", "\n".join(rng_lines) + "\n")
    rc = main(["audit", "--rules", rules, "--cidr", "10.0.0.0/20"])
    assert rc == 0
    assert "checked=4096 mismatches=0" in capsys.readouterr().out


def test_cli_audit_reports_mismatch(tmp_path, monkeypatch):
    rules = _write(tmp_path / "rules.txt", "allow 0.0.0.0/0\n")
    from netacl.core import ACL

    monkeypatch.setattr(
        ACL,
        "audit",
        lambda self, cidr, limit=None: {
            "network": cidr,
            "checked": 1,
            "mismatches": 1,
            "first_mismatches": [{"ip": "10.0.0.1", "fast": {}, "slow": {}}],
        },
    )
    rc = main(["audit", "--rules", rules, "--cidr", "10.0.0.0/20"])
    assert rc == 1


def test_cli_eval(tmp_path, capsys):
    rules = _write(tmp_path / "rules.txt", "deny 10.0.0.0/8\nallow 0.0.0.0/0\n")
    ips = _write(tmp_path / "ips.txt", "10.1.2.3\n# comment\n11.0.0.1\n")
    out = tmp_path / "eval.json"
    rc = main(["eval", "--rules", rules, "--ips", ips, "--json", str(out)])
    assert rc == 0
    rows = json.loads(out.read_text())
    assert [row["action"] for row in rows] == ["deny", "allow"]
    assert "10.1.2.3" in capsys.readouterr().out

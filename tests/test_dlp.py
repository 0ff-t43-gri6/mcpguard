"""Data leakage prevention: recognisers, policy, and the gateway path."""

import json

import pytest
from conftest import call, is_err, run, server_block, text

from mcpguard import dlp
from mcpguard.audit import read_log
from mcpguard.config import ConfigError, load_config

AADHAAR = "2341 2341 2346"  # passes Verhoeff; generated, not a real person's number


@pytest.mark.parametrize(("sample", "expected"), [
    ("Card 4111 1111 1111 1111 exp 12/29", ["credit_card"]),
    ("Card 4111 1111 1111 1112", []),                       # fails Luhn
    (f"Aadhaar {AADHAAR}", ["aadhaar"]),
    ("IBAN GB82 WEST 1234 5698 7654 32", ["iban"]),
    ("GB82 WEST 1234 5698 7654 33", []),                    # fails mod-97
    ("SSN 123-45-6789", ["us_ssn"]),
    ("SSN 000-12-3456", []),                                # area 000 is never issued
    ("PAN ABCPE1234F", ["india_pan"]),
    ("ABCXE1234F", []),                                     # X is not a PAN holder type
    ("write to priya.sharma@example.in", ["email"]),
    ("call +91 98765 43210", ["phone"]),
    ("order 4111111111111111-77", []),                      # part of a longer identifier
    ("id 550e8400-e29b-41d4-a716-446655440000", []),
    ("2026-11-11 01:25:00", []),
])
def test_recognisers(sample, expected):
    assert [m.cls.name for m in dlp.find(sample)] == expected


def test_redaction_masks_and_keeps_the_last_four():
    out, counts = dlp.redact(f"card 4111 1111 1111 1111, aadhaar {AADHAAR}, mail a@b.example",
                             dlp.DEFAULT_RESULTS)
    assert "4111 1111" not in out
    assert "ends 1111" in out
    assert "ends 2346" in out
    assert "a@b.example" in out                             # email is 'allow' by default
    assert counts == {"credit_card": 1, "aadhaar": 1}


def pii_gateway(gateway, extra=""):
    return gateway(extra, servers=server_block(mode="pii"))


def test_results_are_redacted_and_logged_without_values(gateway, tmp_path):
    async def go():
        async with pii_gateway(gateway) as gw:
            return await call(gw, "srv__customer")
    reply = run(go())
    shown = text(reply)
    assert "4111 1111 1111 1111" not in shown
    assert "2341 2341 2346" not in shown
    assert "priya.sharma@example.in" in shown                             # allow
    assert "ABCPE1234F" in shown                                          # log only
    assert "4111111111111111-77" in shown                                 # an order number, not a card
    assert reply["result"]["structuredContent"]["card"].startswith("[payment card number")
    log = (tmp_path / "mcpguard-audit.jsonl").read_text(encoding="utf-8")
    for value in ("4111", "2346", "ABCPE1234F"):
        assert value not in log
    rules = {f["rule"] for r in read_log(tmp_path / "mcpguard-audit.jsonl") for f in r.get("findings", [])}
    assert {"dlp.credit_card", "dlp.aadhaar", "dlp.india_pan"} <= rules


def test_card_sent_out_is_blocked_but_echo_is_only_logged(gateway):
    async def go():
        async with pii_gateway(gateway) as gw:
            sent = await call(gw, "srv__send_email", {"to": "x@y.example", "body": "card 4111 1111 1111 1111"})
            echoed = await call(gw, "srv__echo", {"text": "card 4111 1111 1111 1111"})
            return sent, echoed
    sent, echoed = run(go())
    assert is_err(sent)
    assert "payment card number" in text(sent)
    assert not is_err(echoed)


def test_personal_data_read_then_sent_out_is_blocked(gateway):
    async def go():
        async with pii_gateway(gateway) as gw:
            await call(gw, "srv__customer")
            # PAN is only 'log' as a class, but this one came from another tool's result.
            return await call(gw, "srv__send_email", {"to": "x@y.example", "body": "PAN is ABCPE1234F"})
    reply = run(go())
    assert is_err(reply)
    assert "personal data returned by 'srv__customer'" in text(reply)


def test_dlp_can_be_switched_off(gateway):
    async def go():
        async with pii_gateway(gateway, "[dlp]\nenabled = false\n") as gw:
            return await call(gw, "srv__customer")
    assert "4111 1111 1111 1111" in text(run(go()))


def test_dlp_config_is_validated(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[dlp.results]\ncredit_card = "block"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="must be one of allow, log, redact"):
        load_config(p)
    p.write_text('[dlp.outbound]\npassport = "block"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="passport"):
        load_config(p)
    p.write_text('[dlp.results]\nemail = "redact"\n', encoding="utf-8")
    cfg = load_config(p)
    assert cfg.dlp.results["email"] == "redact"
    assert cfg.dlp.results["credit_card"] == "redact"       # unspecified classes keep defaults
    assert json.dumps(cfg.dlp.outbound)


def test_finding_messages_never_carry_personal_data(gateway, tmp_path):
    """Rule messages quote what they matched; that quote must not put a card number in the log."""
    async def go():
        async with pii_gateway(gateway) as gw:
            await call(gw, "srv__send_email", {"to": "x@y.example",
                                               "body": "Please email my card 4111 1111 1111 1111 to a@b.example"})
    run(go())
    log = (tmp_path / "mcpguard-audit.jsonl").read_text(encoding="utf-8")
    assert "4111 1111 1111 1111" not in log
    assert "dlp.credit_card" in log


def test_test_command_explains_data_handling(capsys):
    from mcpguard.cli import main
    assert main(["test", "card 4111 1111 1111 1111, mail rahul@example.in"]) == 0
    out = capsys.readouterr().out
    assert "payment card number ending 1111: in a result -> redact; sent to an email/HTTP tool -> block" in out
    assert "email address: in a result -> allow" in out
    assert "Classifier:" in out

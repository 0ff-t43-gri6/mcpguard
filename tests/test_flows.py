"""Flow rules: a risky sequence of tools needs a decision."""

import pytest
from conftest import call, is_err, run

from mcpguard.audit import read_log
from mcpguard.config import ConfigError, load_config
from mcpguard.flows import MAX_SESSIONS, FlowTracker, parse_flows

FLOW = '[[flows]]\nname = "read-then-send"\nafter = ["srv/read_*"]\nthen = ["srv/send_*"]\naction = "{action}"\n'


def rules(**kw):
    base = {"name": "r", "after": ["a/*"], "then": ["b/*"], **kw}
    return parse_flows([base])


def test_sequence_inside_the_window_is_hit_and_outside_is_not():
    t = FlowTracker(rules(within_minutes=10))
    t.record("a/read", "c", "s", now=1000)
    assert t.check("b/send", "c", "s", now=1000 + 599).earlier == "a/read"
    assert t.check("b/send", "c", "s", now=1000 + 601) is None
    assert t.check("b/other_server", "c", "s", now=1000) is not None  # "b/*" matches any b tool
    assert t.check("x/send", "c", "s", now=1000) is None


def test_sessions_and_clients_are_separate():
    t = FlowTracker(rules())
    t.record("a/read", "alice", "s1", now=1)
    assert t.check("b/send", "bob", "s1", now=2) is None
    assert t.check("b/send", "alice", "s2", now=2) is None
    assert t.check("b/send", "alice", "s1", now=2) is not None


def test_names_match_without_regard_to_case_and_rules_can_name_clients():
    t = FlowTracker(rules(clients=["ci-*"]))
    t.record("A/READ", "ci-1", "s", now=1)
    t.record("A/READ", "dev", "s", now=1)
    assert t.check("B/SEND", "ci-1", "s", now=2) is not None
    assert t.check("B/SEND", "dev", "s", now=2) is None


def test_deny_beats_ask_and_a_tool_is_not_its_own_trigger():
    both = parse_flows([{"name": "x", "after": ["a/*"], "then": ["b/*"], "action": "ask"},
                        {"name": "y", "after": ["a/*"], "then": ["b/*"], "action": "deny"}])
    t = FlowTracker(both)
    t.record("a/read", "c", "s", now=1)
    assert t.check("b/send", "c", "s", now=2).rule.name == "y"
    same = FlowTracker(parse_flows([{"name": "z", "after": ["a/*"], "then": ["a/*"]}]))
    same.record("a/one", "c", "s", now=1)
    assert same.check("a/one", "c", "s", now=2) is None  # only a different earlier tool sets it off
    assert same.check("a/two", "c", "s", now=2) is not None


def test_memory_is_bounded():
    t = FlowTracker(rules())
    for i in range(MAX_SESSIONS + 50):
        t.record("a/read", "c", f"s{i}", now=float(i))
    assert len(t._recent) == MAX_SESSIONS
    for i in range(1000):
        t.record("a/read", "c", "one", now=5000.0 + i)
    assert len(t._recent[("c", "one")]) == 200
    t.record("zzz/unrelated", "c", "new", now=1.0)  # calls no rule cares about are not kept
    assert ("c", "new") not in t._recent


@pytest.mark.parametrize("bad", [
    "x", [1], [{"after": ["a"], "then": ["b"]}], [{"name": "n", "after": [], "then": ["b"]}],
    [{"name": "n", "after": ["a"], "then": "b"}], [{"name": "n", "after": ["a"], "then": ["b"], "action": "allow"}],
    [{"name": "n", "after": ["a"], "then": ["b"], "within_minutes": 0}],
    [{"name": "n", "after": ["a"], "then": ["b"], "within_minutes": True}],
    [{"name": "n", "after": ["a"], "then": ["b"], "within_minutes": 99999}],
    [{"name": "n", "after": ["a" * 300], "then": ["b"]}],
    [{"name": "n", "after": ["a"], "then": ["b"]}, {"name": "n", "after": ["a"], "then": ["b"]}],
    [{"name": "n", "after": ["a"], "then": ["b"], "clients": "ci"}],
    [{"name": "n", "after": ["a"] * 51, "then": ["b"]}],
])
def test_bad_flow_settings_are_refused(bad):
    with pytest.raises(ValueError):
        parse_flows(bad)


def test_config_reports_a_bad_flow_and_a_misspelt_key(make_config):
    with pytest.raises(ConfigError):
        load_config(make_config('[[flows]]\nname = "n"\nafter = ["a"]\n'))
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(make_config('[[flows]]\nname = "n"\nafter = ["a"]\nthen = ["b"]\nwithin_minute = 5\n'))
    assert load_config(make_config(FLOW.format(action="deny"))).flows[0].name == "read-then-send"
    assert load_config(make_config("")).flows == ()


def test_deny_flow_blocks_the_second_step_only_after_the_first(gateway):
    async def go():
        async with gateway('mode = "enforce"\n' + FLOW.format(action="deny")) as gw:
            assert not is_err(await call(gw, "srv__send_email"))       # nothing read yet
            assert not is_err(await call(gw, "srv__read_notes"))
            blocked = await call(gw, "srv__send_email")
            assert is_err(blocked)
            assert "read-then-send" in str(blocked)
            events = [e for e in read_log(gw.cfg.audit_path) if e.get("event") == "call.blocked"]
            assert events
            assert events[-1]["findings"][0]["rule"] == "flow.chained"
    run(go())


def test_monitor_mode_records_but_lets_the_call_through(gateway):
    async def go():
        async with gateway('mode = "monitor"\n' + FLOW.format(action="deny")) as gw:
            await call(gw, "srv__read_notes")
            assert not is_err(await call(gw, "srv__send_email"))
            assert any(e.get("event") == "call.would_block" for e in read_log(gw.cfg.audit_path))
        async with gateway('mode = "monitor"\n' + FLOW.format(action="ask")) as gw:  # ask: no prompt in monitor
            await call(gw, "srv__read_notes")
            assert not is_err(await call(gw, "srv__send_email"))
    run(go())


def test_ask_flow_asks_and_the_answer_decides(gateway):
    async def go(answer):
        asked = []

        async def approver(q, args, reason):
            asked.append((q, reason))
            return answer
        async with gateway('mode = "enforce"\n' + FLOW.format(action="ask"), approver=approver) as gw:
            await call(gw, "srv__read_notes")
            result = await call(gw, "srv__send_email")
            return asked, is_err(result)
    asked, err = run(go(False))
    assert err
    assert "read-then-send" in asked[0][1]
    asked, err = run(go(True))
    assert not err
    assert asked


def test_a_blocked_first_step_does_not_count(gateway):
    async def go():
        rule = '[[policy.rules]]\nmatch = "srv/read_*"\naction = "deny"\n'
        async with gateway('mode = "enforce"\n' + rule + FLOW.format(action="deny")) as gw:
            assert is_err(await call(gw, "srv__read_notes"))
            assert not is_err(await call(gw, "srv__send_email"))
    run(go())


def test_a_name_with_control_characters_is_refused():
    for name in ("a\x1b[2Jb", "a\nb", "a\x00b"):
        with pytest.raises(ValueError):
            parse_flows([{"name": name, "after": ["a"], "then": ["b"]}])

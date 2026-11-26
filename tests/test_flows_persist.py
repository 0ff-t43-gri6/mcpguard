"""Flow memory survives a restart."""

import json
import time

from mcpguard.flows import MAX_CALLS_KEPT, FlowTracker, parse_flows

RULES = parse_flows([{"name": "r", "after": ["a/*"], "then": ["b/*"], "within_minutes": 30}])


def test_memory_survives_a_new_tracker(tmp_path):
    path = tmp_path / "flows.json"
    one = FlowTracker(RULES, path)
    one.record("a/read", "c", "stdio")
    one.save()
    two = FlowTracker(RULES, path)  # a restarted gateway
    assert two.check("b/send", "c", "stdio").earlier == "a/read"


def test_old_calls_are_not_restored(tmp_path):
    path = tmp_path / "flows.json"
    one = FlowTracker(RULES, path)
    one.record("a/read", "c", "s", now=time.time() - 3 * 24 * 3600)
    one.save()
    assert FlowTracker(RULES, path).check("b/send", "c", "s") is None


def test_nothing_is_written_when_nothing_changed(tmp_path):
    path = tmp_path / "flows.json"
    t = FlowTracker(RULES, path)
    t.save()
    t.record("x/unrelated", "c", "s")  # no rule cares, so nothing is remembered
    t.save()
    assert not path.exists()


def test_two_processes_merge(tmp_path):
    path = tmp_path / "flows.json"
    a, b = FlowTracker(RULES, path), FlowTracker(RULES, path)
    a.record("a/one", "c", "s")
    b.record("a/two", "c", "s")
    a.save()
    b.save()
    merged = json.loads(path.read_text(encoding="utf-8"))["sessions"][0]["calls"]
    assert {n for _, n in merged} == {"a/one", "a/two"}


def test_damaged_file_is_ignored(tmp_path):
    path = tmp_path / "flows.json"
    for text in ("not json", "[]", '{"sessions": 5}', '{"sessions": [1, {"calls": 3}, {"client": 1}]}',
                 '{"sessions": [{"client": "c", "session": "s", "calls": [["x", "y"], [1], "z", [true, "a/x"]]}]}'):
        path.write_text(text, encoding="utf-8")
        t = FlowTracker(RULES, path)
        assert t.check("b/send", "c", "s") is None, text


def test_a_planted_file_cannot_grow_memory(tmp_path):
    path = tmp_path / "flows.json"
    now = time.time()
    planted = {"sessions": [{"client": "c", "session": "s", "calls": [[now, "a/x"]] * (MAX_CALLS_KEPT * 10)}]}
    path.write_text(json.dumps(planted), encoding="utf-8")
    t = FlowTracker(RULES, path)
    assert len(t._recent[("c", "s")]) <= MAX_CALLS_KEPT


def test_no_path_means_memory_only():
    t = FlowTracker(RULES)
    t.record("a/read", "c", "s")
    t.save()  # does nothing, does not fail
    assert t.check("b/send", "c", "s") is not None


def test_a_restarted_gateway_still_asks(gateway):
    import conftest
    from conftest import call, is_err

    from test_flows import FLOW

    async def go():
        cfg = 'mode = "enforce"\n' + FLOW.format(action="deny")
        async with gateway(cfg) as gw:
            await call(gw, "srv__read_notes")
        async with gateway(cfg) as gw:  # same folder, new process
            assert is_err(await call(gw, "srv__send_email"))
    conftest.run(go())

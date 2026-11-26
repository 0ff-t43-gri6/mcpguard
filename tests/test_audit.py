import json

from mcpguard.audit import AuditLog, ChainVerifier, read_log, segments, verify


def _rewrite(path, fn):
    lines = path.read_text(encoding="utf-8").splitlines()
    fn(lines)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_chain_verifies(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.write("e", n=i)
    ok, msg = verify(tmp_path / "a.jsonl")
    assert ok
    assert "5 records" in msg


def test_detects_modified_record(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(5):
        log.write("e", n=i)

    def tamper(lines):
        rec = json.loads(lines[2])
        rec["n"] = 99
        lines[2] = json.dumps(rec, sort_keys=True)
    _rewrite(p, tamper)
    ok, msg = verify(p)
    assert not ok
    assert "record 2" in msg


def test_detects_deleted_record(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(4):
        log.write("e", n=i)
    _rewrite(p, lambda lines: lines.pop(1))
    assert not verify(p)[0]


def test_partial_line_is_recovered_on_start(tmp_path):
    """A crash mid-write used to make the log unreadable and the gateway unable to start."""
    p = tmp_path / "a.jsonl"
    AuditLog(p).write("first")
    with p.open("a", encoding="utf-8") as f:
        f.write('{"seq": 1, "event": "trunc')
    assert [r["event"] for r in read_log(p)] == ["first"]  # readers skip it
    log = AuditLog(p)                                     # writer recovers it
    log.write("after")
    assert verify(p)[0]
    assert [r["event"] for r in read_log(p)] == ["first", "audit.recovered", "after"]
    assert "trunc" in (tmp_path / "a.jsonl.partial").read_text(encoding="utf-8")


def test_rotation_keeps_one_chain(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p, max_bytes=400)
    for i in range(25):
        log.write("e", n=i)
    assert len(segments(p)) > 2
    ok, msg = verify(p)
    assert ok
    assert "25 records" in msg
    assert [r["n"] for r in read_log(p)] == list(range(25))


def test_restart_continues_chain_after_rotation(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p, max_bytes=300)
    for i in range(10):
        log.write("e", n=i)
    AuditLog(p, max_bytes=300).write("e", n=10)
    assert verify(p)[0]


def test_incremental_verifier_follows_appends_and_rotation(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p, max_bytes=500)
    v = ChainVerifier(p)
    for i in range(40):
        log.write("e", n=i)
        if i % 9 == 0:
            assert v.check()[0]
    ok, msg = v.check()
    assert ok
    assert "40 records" in msg


def test_incremental_verifier_notices_tampering(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(5):
        log.write("e", n=i)
    v = ChainVerifier(p, full_interval=0)
    assert v.check()[0]
    _rewrite(p, lambda lines: lines.__setitem__(0, lines[0].replace('"n": 0', '"n": 7')))
    assert not v.check()[0]


def test_two_writers_on_one_log_keep_a_single_chain(tmp_path):
    # What Claude Desktop does when it starts the gateway twice: each process opens the
    # log, then they take turns writing. Before the fix the second writer forked the chain.
    from mcpguard.audit import AuditLog, read_log, verify
    p = tmp_path / "a.jsonl"
    key = bytes(range(32))
    first, second = AuditLog(p, key=key), AuditLog(p, key=key)
    first.write("server.up")
    second.write("server.up")
    first.write("call.allowed")
    second.write("call.allowed")
    first.write("call.allowed")
    ok, msg = verify(p, key)
    assert ok, msg
    assert [r["seq"] for r in read_log(p)] == [0, 1, 2, 3, 4]
    assert first.count == second.count == 5
    assert first.head == second.head


def _writer(path, key_hex, n, go):
    import time

    from mcpguard.audit import AuditLog
    log = AuditLog(path, key=bytes.fromhex(key_hex))
    go.wait(30)  # every process opens the log first, then all write at once
    for i in range(n):
        log.write("call.allowed", i=i)
        time.sleep(0.002)


def test_concurrent_processes_extend_one_chain(tmp_path):
    import multiprocessing as mp
    import time

    from mcpguard.audit import read_log, verify
    p = tmp_path / "a.jsonl"
    key = bytes(range(32))
    ctx = mp.get_context("spawn")  # the start method Windows uses
    go = ctx.Event()
    procs = [ctx.Process(target=_writer, args=(str(p), key.hex(), 40, go)) for _ in range(4)]
    for proc in procs:
        proc.start()
    time.sleep(2)  # let every process open the log
    go.set()
    for proc in procs:
        proc.join(60)
        assert proc.exitcode == 0
    ok, msg = verify(p, key)
    assert ok, msg
    assert len(read_log(p)) == 160


def test_concurrent_writers_with_rotation(tmp_path):
    from mcpguard.audit import AuditLog, read_log, segments, verify
    p = tmp_path / "a.jsonl"
    logs = [AuditLog(p, max_bytes=600) for _ in range(3)]
    for i in range(30):
        logs[i % 3].write("call.allowed", i=i)
    ok, msg = verify(p)
    assert ok, msg
    assert len(read_log(p)) == 30
    assert len(segments(p)) > 1


def _forked_log(path, key):
    """What mcpguard before 0.8.0 produced with two processes: two records after record 1."""
    import json

    from mcpguard.audit import HMAC_ALG, _digest
    first = AuditLog(path, key=key)
    first.write("server.up")
    first.write("call.allowed")
    lines = path.read_text(encoding="utf-8").splitlines()
    rec1 = json.loads(lines[1])
    body = {"seq": 1, "ts": 1.0, "event": "server.up", "alg": HMAC_ALG}
    forked = {**body, "prev": rec1["prev"], "hash": _digest(rec1["prev"], body, key)}
    path.write_text("\n".join([*lines, json.dumps(forked, sort_keys=True)]) + "\n", encoding="utf-8")


def test_verify_explains_a_fork(tmp_path):
    from mcpguard.audit import verify
    p = tmp_path / "a.jsonl"
    key = bytes(range(32))
    _forked_log(p, key)
    ok, msg = verify(p, key)
    assert not ok
    assert "chain forked" in msg
    assert "continues from record 0" in msg
    assert "audit-new" in msg


def test_a_forged_record_is_not_called_a_fork(tmp_path):
    import json

    from mcpguard.audit import verify
    p = tmp_path / "a.jsonl"
    key = bytes(range(32))
    _forked_log(p, key)
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[-1])
    rec["event"] = "call.denied"  # edited after signing
    p.write_text("\n".join([*lines[:-1], json.dumps(rec, sort_keys=True)]) + "\n", encoding="utf-8")
    ok, msg = verify(p, key)
    assert not ok
    assert "forked" not in msg


def test_audit_new_archives_every_segment_and_starts_a_verified_log(tmp_path, monkeypatch, capsys):
    from mcpguard.audit import read_log, segments, verify
    from mcpguard.cli import main
    monkeypatch.chdir(tmp_path)
    (tmp_path / "mcpguard.toml").write_text('[audit]\nrotate_bytes = 400\n', encoding="utf-8")
    key = bytes(range(32))
    (tmp_path / "mcpguard-audit.key").write_text(key.hex(), encoding="utf-8")
    log_path = tmp_path / "mcpguard-audit.jsonl"
    log = AuditLog(log_path, max_bytes=400, key=key)
    for i in range(12):
        log.write("call.allowed", i=i)
    old_files = {f.name for f in segments(log_path)}
    assert len(old_files) > 1
    assert main(["audit-new", "--reason", "fork after two gateways"]) == 0
    out = capsys.readouterr().out
    assert "Moved the old log" in out
    archived = next((tmp_path / "audit-archive").iterdir())
    assert {f.name for f in archived.iterdir()} == old_files
    assert verify(log_path, key)[0]
    first = read_log(log_path)[0]
    assert first["event"] == "audit.new"
    assert first["previous_verified"] is True
    assert first["reason"] == "fork after two gateways"
    log.write("call.allowed", i=99)  # a gateway that was running continues in the new log
    assert verify(log_path, key)[0]
    assert len(read_log(log_path)) == 2


def test_rotation_blocked_by_windows_file_lock_never_loses_a_record(tmp_path, monkeypatch):
    # On Windows a rename fails while another process (say the dashboard) has the file open.
    import os as _os

    from mcpguard import fileio
    from mcpguard.audit import read_log, segments, verify
    real = _os.replace
    state = {"blocked": True}

    def flaky(src, dst):
        if state["blocked"] and str(src).endswith("a.jsonl"):
            raise PermissionError("in use")
        return real(src, dst)

    monkeypatch.setattr(fileio.os, "replace", flaky)
    monkeypatch.setattr(fileio.time, "sleep", lambda _s: None)
    p = tmp_path / "a.jsonl"
    log = AuditLog(p, max_bytes=300)
    for i in range(10):
        log.write("call.allowed", i=i)
    assert len(segments(p)) == 1  # could not rotate, but kept writing
    state["blocked"] = False
    log.write("call.allowed", i=10)
    assert len(segments(p)) == 2  # rotated as soon as the file was free
    assert len(read_log(p)) == 11
    assert verify(p)[0]


def _create_key_and_token(folder, go, out):
    from mcpguard.approvals import token_for
    from mcpguard.audit import load_key
    go.wait(30)
    try:
        out.put((load_key(f"{folder}/mcpguard-audit.key", create=True).hex(), token_for(f"{folder}/ap")))
    except Exception as e:  # report instead of dying silently
        out.put(("error", repr(e)))


def test_first_start_of_several_gateways_at_once(tmp_path):
    """On a fresh install Claude Desktop may start two gateways together. Both create the signing
    key and the dashboard token; one used to crash with FileExistsError or read a half-written file."""
    import multiprocessing as mp
    ctx = mp.get_context("spawn")
    go, out = ctx.Event(), ctx.Queue()
    procs = [ctx.Process(target=_create_key_and_token, args=(str(tmp_path), go, out)) for _ in range(6)]
    for p in procs:
        p.start()
    import time
    time.sleep(2)
    go.set()
    results = [out.get(timeout=60) for _ in procs]
    for p in procs:
        p.join(30)
    assert not [r for r in results if r[0] == "error"], results
    assert len(set(results)) == 1          # every process got the same key and token
    key, token = results[0]
    assert len(key) == 64
    assert token
    assert not list(tmp_path.glob(".*.new"))
    assert not list((tmp_path / "ap").glob(".*.new"))


def test_rotation_never_overwrites_a_segment_when_the_clock_stands_still(tmp_path, monkeypatch):
    """The Windows clock moves in ~16 ms steps, so rapid rotations can read the same time."""
    import datetime as real_dt

    from mcpguard import audit

    frozen = real_dt.datetime(2026, 1, 1, tzinfo=real_dt.UTC)

    class Frozen(real_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return frozen

    monkeypatch.setattr(audit.dt, "datetime", Frozen)
    p = tmp_path / "a.jsonl"
    log = AuditLog(p, max_bytes=400)
    for i in range(25):
        log.write("e", n=i)
    assert len(segments(p)) > 2
    ok, msg = verify(p)
    assert ok, msg
    assert [r["n"] for r in read_log(p)] == list(range(25))

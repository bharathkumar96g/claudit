import json

import duckdb

from claudit.db import SCHEMA_VERSION, connect
from claudit.detect import scan
from claudit.ingest import ScanStats, extract_segments, scan_dir

SECRET = "sk-ant-api03-" + "q9Wz" * 20


def _user(text, sid="s1"):
    return {"type": "user", "uuid": f"u-{len(text)}", "sessionId": sid, "cwd": "/p",
            "timestamp": "2026-09-01T10:00:00.000Z", "message": {"role": "user", "content": text}}


def _tool_result(text, sid="s1", path="/p/.env"):
    return {"type": "user", "uuid": "u-tr", "sessionId": sid, "cwd": "/p",
            "timestamp": "2026-09-01T10:01:00.000Z",
            "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": text}]},
            "toolUseResult": {"type": "text", "file": {"filePath": path, "content": text}}}


def _assistant(sid="s1"):
    return {"type": "assistant", "uuid": "a-1", "sessionId": sid, "cwd": "/p",
            "timestamp": "2026-09-01T10:00:30.000Z",
            "message": {"role": "assistant", "model": "m", "content": [
                {"type": "thinking", "thinking": "the user's key is " + SECRET, "signature": "x"},
                {"type": "text", "text": "Reading it."},
                {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/p/.env"}}]}}


def _count(con, table):
    return con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def test_segments_carry_source_path_and_thinking():
    segs = extract_segments(_assistant())
    assert [(s.source, s.path) for s in segs] == [
        ("assistant_thinking", None), ("assistant_text", None), ("tool_input", "/p/.env")]
    assert SECRET in segs[0].text

    (seg,) = extract_segments(_tool_result("KEY=x", path="/p/tests/fixtures.env"))
    assert seg.source == "tool_result" and seg.path == "/p/tests/fixtures.env"


def test_tool_input_keeps_real_newlines_so_multiline_secrets_match_exactly():
    key = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow\nAbCdEf\n-----END RSA " + "PRIVATE KEY-----"
    url = "postgresql://app:s3cretPW@db.internal:5432/prod"
    rec = {"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "t1", "name": "Write",
         "input": {"file_path": "/p/deploy/id_rsa", "content": f"{key}\nDATABASE_URL={url}\n"}}]}}
    (seg,) = extract_segments(rec)
    assert seg.source == "tool_input" and "\n" in seg.text and seg.path == "/p/deploy/id_rsa"

    by_cat = {m.category: m for m in scan(seg.text)}
    assert by_cat["private_key"].value == key
    assert by_cat["connection_string"].value == url
    assert by_cat["private_key"].preview.startswith("-----BEGIN RSA")
    assert "MIIEow" not in by_cat["private_key"].preview and len(by_cat["private_key"].preview) <= 41


def test_one_file_is_one_session_and_one_project_even_when_cwd_moves(tmp_path):
    con = connect(tmp_path / "t.duckdb")
    d = tmp_path / "-Users-me-work"
    d.mkdir()
    f = d / "abc-123.jsonl"
    recs = [
        {"type": "system", "subtype": "init"},
        {"type": "user", "uuid": "u1", "sessionId": "abc-123", "cwd": "/Users/me/work", "message": {"role": "user", "content": "hi"}},
        {"type": "user", "uuid": "u2", "sessionId": "abc-123", "cwd": "/Users/me/work/sub", "message": {"role": "user", "content": "moved dirs"}},
    ]
    f.write_text("".join(json.dumps(r) + "\n" for r in recs))
    scan_dir(con, tmp_path, ScanStats())

    rows = con.execute("SELECT session_id, project, cwd FROM events ORDER BY line_no").fetchall()
    assert [r[0] for r in rows] == ["abc-123"] * 3
    assert [r[1] for r in rows] == ["/Users/me/work"] * 3
    assert [r[2] for r in rows] == [None, "/Users/me/work", "/Users/me/work/sub"]

    with f.open("a") as fh:
        fh.write(json.dumps({"type": "user", "uuid": "u3", "sessionId": "abc-123", "cwd": "/elsewhere",
                             "message": {"role": "user", "content": "later"}}) + "\n")
    scan_dir(con, tmp_path, ScanStats())
    assert con.execute("SELECT DISTINCT project FROM events").fetchall() == [("/Users/me/work",)]


def test_incremental_scan_is_idempotent_and_stores_no_transcript_text(tmp_path):
    con = connect(tmp_path / "t.duckdb")
    d = tmp_path / "proj"
    d.mkdir()
    f = d / "s1.jsonl"
    f.write_text("".join(json.dumps(r) + "\n" for r in [_user("hello"), _assistant(), _tool_result(f"KEY={SECRET}")]))

    s1 = ScanStats()
    scan_dir(con, tmp_path, s1)
    assert s1.events == 3
    assert s1.findings == 2  # once in the thinking block, once in the file Claude read
    assert set(con.execute("SELECT source FROM findings").fetchall()) == {("assistant_thinking",), ("tool_result",)}

    s2 = ScanStats()
    scan_dir(con, tmp_path, s2)
    assert s2.lines == 0 and _count(con, "events") == 3

    with f.open("a") as fh:
        fh.write(json.dumps(_user("partial line, no newline yet")))
    s3 = ScanStats()
    scan_dir(con, tmp_path, s3)
    assert s3.lines == 0 and _count(con, "events") == 3

    with f.open("a") as fh:
        fh.write("\n")
    s4 = ScanStats()
    scan_dir(con, tmp_path, s4)
    assert s4.events == 1 and _count(con, "events") == 4

    columns = {r[0] for r in con.execute(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'segments'").fetchall()}
    assert "text_redacted" not in columns and {"path", "char_len", "text_sha256"} <= columns
    for table in ("events", "segments", "findings"):
        blob = " ".join(str(r) for r in con.execute(f"SELECT * FROM {table}").fetchall())
        assert SECRET not in blob and SECRET[10:30] not in blob


def test_known_events_are_skipped_before_scanning(tmp_path):
    con = connect(tmp_path / "t.duckdb")
    d = tmp_path / "proj"
    d.mkdir()
    (d / "a.jsonl").write_text(json.dumps(_user("first")) + "\n")
    scan_dir(con, tmp_path, ScanStats())
    (d / "b.jsonl").write_text(json.dumps(_user("first")) + "\n" + json.dumps(_user("second")) + "\n")
    s = ScanStats()
    scan_dir(con, tmp_path, s)
    assert s.duplicates == 1 and s.events == 1 and _count(con, "events") == 2


def test_schema_version_mismatch_rebuilds_the_database(tmp_path):
    path = tmp_path / "old.duckdb"
    con = connect(path)
    con.execute("INSERT INTO events VALUES ('e1','f',1,'s','p','user',NULL,NULL,NULL,NULL,NULL,now())")
    con.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", [str(SCHEMA_VERSION - 1)])
    con.close()

    con = connect(path)
    assert _count(con, "events") == 0
    assert con.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == str(SCHEMA_VERSION)

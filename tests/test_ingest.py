import json

from claudit.db import connect
from claudit.detect import scan
from claudit.ingest import ScanStats, extract_segments, scan_dir

SECRET = "sk-ant-api03-" + "q9Wz" * 20


def _user(text, sid="s1"):
    return {"type": "user", "uuid": f"u-{len(text)}", "sessionId": sid, "cwd": "/p",
            "timestamp": "2026-09-01T10:00:00.000Z", "message": {"role": "user", "content": text}}


def _tool_result(text, sid="s1"):
    return {"type": "user", "uuid": "u-tr", "sessionId": sid, "cwd": "/p",
            "timestamp": "2026-09-01T10:01:00.000Z",
            "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": text}]}}


def _assistant(sid="s1"):
    return {"type": "assistant", "uuid": "a-1", "sessionId": sid, "cwd": "/p",
            "timestamp": "2026-09-01T10:00:30.000Z",
            "message": {"role": "assistant", "model": "m", "content": [
                {"type": "text", "text": "Reading it."},
                {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/p/.env"}}]}}


def test_tool_input_keeps_real_newlines_so_multiline_secrets_match_exactly():
    key = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow\nAbCdEf\n-----END RSA " + "PRIVATE KEY-----"
    url = "postgresql://app:s3cretPW@db.internal:5432/prod"
    rec = {"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "t1", "name": "Write",
         "input": {"file_path": "/p/deploy/id_rsa", "content": f"{key}\nDATABASE_URL={url}\n"}}]}}
    (source, text), = extract_segments(rec)
    assert source == "tool_input" and "\n" in text

    by_cat = {m.category: m for m in scan(text)}
    assert by_cat["private_key"].value == key
    assert by_cat["connection_string"].value == url
    assert by_cat["private_key"].preview.startswith("-----BEGIN RSA")
    assert "MIIEow" not in by_cat["private_key"].preview and len(by_cat["private_key"].preview) <= 41


def _count(con, table):
    return con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def test_incremental_scan_is_idempotent_and_never_stores_raw_secret(tmp_path):
    con = connect(tmp_path / "t.duckdb")
    d = tmp_path / "proj"
    d.mkdir()
    f = d / "s1.jsonl"
    f.write_text("".join(json.dumps(r) + "\n" for r in [_user("hello"), _assistant(), _tool_result(f"KEY={SECRET}")]))

    s1 = ScanStats()
    scan_dir(con, tmp_path, s1)
    assert (s1.events, s1.findings) == (3, 1)

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

    stored = con.execute("SELECT text_redacted FROM segments").fetchall()
    assert all(SECRET not in row[0] for row in stored)
    assert any("[REDACTED:anthropic_api_key]" in row[0] for row in stored)
    source, preview, fingerprint = con.execute("SELECT source, preview, fingerprint FROM findings").fetchone()
    assert source == "tool_result" and SECRET not in preview and len(fingerprint) == 64

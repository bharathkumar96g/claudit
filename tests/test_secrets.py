import json

import pytest
from fastapi.testclient import TestClient

from claudit.db import connect, truncate_all
from claudit.ingest import ScanStats, scan_dir
from claudit.secrets import list_secrets, rotation_hint, set_state
from claudit.server import create_app

KEY = "AKIA" + "J4K7QZ2M9XP3RT6W"
POST = {"X-Requested-With": "claudit"}


def _user(uid, sid, text, ts):
    return {"type": "user", "uuid": uid, "sessionId": sid, "cwd": "/p",
            "timestamp": ts, "message": {"role": "user", "content": text}}


def _populate(root):
    d = root / "proj"
    d.mkdir(parents=True, exist_ok=True)
    (d / "s1.jsonl").write_text(json.dumps(_user("u1", "s1", f"AWS_ACCESS_KEY_ID={KEY}", "2026-09-01T10:00:00.000Z")) + "\n")
    (d / "s2.jsonl").write_text(
        json.dumps(_user("u2", "s2", f"still using AWS_ACCESS_KEY_ID={KEY}", "2026-09-05T10:00:00.000Z")) + "\n"
        + json.dumps(_user("u3", "s2", 'DB_PASSWORD = "Tr0ub4dor&3xyz!!"', "2026-09-05T11:00:00.000Z")) + "\n")


def test_same_value_across_sessions_is_one_secret_and_state_survives_rescan(tmp_path):
    con = connect(tmp_path / "t.duckdb")
    _populate(tmp_path)
    scan_dir(con, tmp_path, ScanStats())

    rows = list_secrets(con)
    assert [(r["category"], r["findings"], r["sessions"]) for r in rows] == [
        ("aws_access_key_id", 2, 2), ("generic_secret", 1, 1)]
    aws = rows[0]
    assert aws["first_seen"].startswith("2026-09-01") and aws["last_seen"].startswith("2026-09-05")
    assert aws["verdict"] == "unjudged" and aws["state"] == "open"
    assert "IAM" in aws["rotation"]

    fp = set_state(con, aws["fingerprint"][:10], "rotated", "rolled on 9/12")
    assert fp == aws["fingerprint"]
    assert [r["category"] for r in list_secrets(con)] == ["generic_secret"]
    assert list_secrets(con, "rotated")[0]["note"] == "rolled on 9/12"

    truncate_all(con)
    scan_dir(con, tmp_path, ScanStats())
    assert [r["category"] for r in list_secrets(con)] == ["generic_secret"]
    assert list_secrets(con, "all")[0]["state"] == "rotated"

    with pytest.raises(LookupError):
        set_state(con, "zzzz", "dismissed")
    with pytest.raises(ValueError):
        set_state(con, aws["fingerprint"][:10], "nonsense")


def test_rotation_hint_falls_back_to_provider_name():
    assert "GitHub" in rotation_hint("github_token")
    assert rotation_hint("sendgrid-api-token").startswith("sendgrid:")


def test_secrets_api(tmp_path):
    _populate(tmp_path / "transcripts")
    app = create_app(tmp_path / "t.duckdb", tmp_path / "transcripts", None, "http://127.0.0.1:9", "m", demo=False)
    client = TestClient(app, base_url="http://127.0.0.1")
    client.post("/api/scan", headers=POST)

    rows = client.get("/api/secrets").json()
    assert len(rows) == 2 and rows[0]["sessions"] == 2
    fp = rows[0]["fingerprint"]
    assert client.post(f"/api/secrets/{fp}/state", json={"state": "dismissed", "note": "test key"}, headers=POST).json()["state"] == "dismissed"
    assert len(client.get("/api/secrets").json()) == 1
    assert client.post(f"/api/secrets/{fp}/state", json={"state": "bogus"}, headers=POST).status_code == 400
    assert client.post("/api/secrets/nope/state", json={"state": "open"}, headers=POST).status_code == 404

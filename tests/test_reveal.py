import json

from claudit.db import connect
from claudit.ingest import ScanStats, scan_dir
from claudit.reveal import reveal_finding

TOKEN = "ghp_" + "A1b2C3d4" * 5


def _rec(text):
    return {"type": "user", "uuid": "u1", "sessionId": "s1", "cwd": "/p",
            "timestamp": "2026-09-01T10:00:00.000Z", "message": {"role": "user", "content": text}}


def test_reveal_returns_exact_value_and_detects_tampering(tmp_path):
    con = connect(tmp_path / "t.duckdb")
    f = tmp_path / "proj" / "s1.jsonl"
    f.parent.mkdir()
    f.write_text(json.dumps(_rec(f"use GITHUB_TOKEN={TOKEN} for the deploy step")) + "\n")
    scan_dir(con, tmp_path, ScanStats())

    finding_id, preview = con.execute("SELECT finding_id, preview FROM findings").fetchone()
    assert TOKEN not in preview

    value, excerpt = reveal_finding(con, finding_id)
    assert value == TOKEN
    assert f"«{TOKEN}»" in excerpt and excerpt.endswith("for the deploy step")

    f.write_text(json.dumps(_rec("use GITHUB_TOKEN=ghp_" + "Z9y8X7w6" * 5 + " for the deploy step")) + "\n")
    assert reveal_finding(con, finding_id) is None

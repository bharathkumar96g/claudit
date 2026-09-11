import json

from claudit.db import connect
from claudit.ingest import ScanStats, scan_dir
from claudit.judge import adjudicate, semantic_scan
from claudit.ollama import OllamaClient

REAL = "Tr0ub4dor&3xyz!!"
FAKE = "Xy7#pQ2!mN9@kL4$"


def _user(uid, text):
    return {"type": "user", "uuid": uid, "sessionId": "s1", "cwd": "/p",
            "timestamp": "2026-09-01T10:00:00.000Z", "message": {"role": "user", "content": text}}


def _write(path, recs):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))


def _setup(tmp_path, recs):
    con = connect(tmp_path / "t.duckdb")
    _write(tmp_path / "proj" / "s1.jsonl", recs)
    scan_dir(con, tmp_path, ScanStats())
    return con


def test_adjudicate_persists_verdicts_scrubs_reasons_and_is_idempotent(tmp_path, fake_ollama):
    url, server = fake_ollama
    con = _setup(tmp_path, [
        _user("u1", f'DB_PASSWORD = "{REAL}"'),
        _user("u2", f'# fixture for unit tests\nTEST_PASSWORD = "{FAKE}"'),
    ])
    assert con.execute("SELECT count(*) FROM findings").fetchone()[0] == 2

    stats = adjudicate(con, OllamaClient(url), "qwen2.5:7b")
    assert (stats.judged, stats.confirmed, stats.benign) == (2, 1, 1)

    rows = con.execute("SELECT verdict, reason FROM judgments").fetchall()
    assert {v for v, _ in rows} == {"confirmed", "benign"}
    assert all(REAL not in r and FAKE not in r for _, r in rows)
    assert all("…" in r for _, r in rows)

    again = adjudicate(con, OllamaClient(url), "qwen2.5:7b")
    assert again.judged == 0 and len(server.requests) == 2


def test_adjudicate_marks_unavailable_when_transcript_changed(tmp_path, fake_ollama):
    url, server = fake_ollama
    con = _setup(tmp_path, [_user("u1", f'DB_PASSWORD = "{REAL}"')])
    _write(tmp_path / "proj" / "s1.jsonl", [_user("u1", 'DB_PASSWORD = "somethingElse123!"')])

    stats = adjudicate(con, OllamaClient(url), "qwen2.5:7b")
    assert stats.unavailable == 1 and stats.judged == 0
    assert server.requests == []
    assert con.execute("SELECT verdict FROM judgments").fetchone()[0] == "unavailable"


def test_semantic_scan_sees_redacted_text_and_is_idempotent(tmp_path, fake_ollama):
    url, server = fake_ollama
    phone = "(214) 555-0143"
    con = _setup(tmp_path, [
        _user("u1", f"Our customer Priya reported a double charge; callback {phone}. Trace the order please."),
        _user("u2", "short prompt"),
    ])

    stats = semantic_scan(con, OllamaClient(url), "qwen2.5:7b")
    assert (stats.scanned, stats.findings) == (1, 1)
    sent = server.requests[-1]["messages"][-1]["content"]
    assert phone not in sent and "[REDACTED:phone]" in sent

    kind, severity, summary = con.execute("SELECT kind, severity, summary FROM semantic_findings").fetchone()
    assert kind == "customer_or_employee_data" and severity == "high" and summary

    again = semantic_scan(con, OllamaClient(url), "qwen2.5:7b")
    assert again.scanned == 0 and len(server.requests) == 1

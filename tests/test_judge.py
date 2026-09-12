import json

from claudit.db import connect
from claudit.ingest import ScanStats, scan_dir
from claudit.judge import JUDGE_PROMPT_VERSION, _scrub, _scrub_summary, adjudicate, needs_model, semantic_scan
from claudit.ollama import OllamaClient
from claudit.reveal import redacted_window

REAL = "Tr0ub4dor&3xyz!!"
FAKE = "Xy7#pQ2!mN9@kL4$"
GHP = "ghp_" + "A1b2C3d4" * 5


def _user(uid, text):
    return {"type": "user", "uuid": uid, "sessionId": "s1", "cwd": "/p",
            "timestamp": "2026-09-01T10:00:00.000Z", "message": {"role": "user", "content": text}}


def _tool_result(uid, text, path):
    return {"type": "user", "uuid": uid, "sessionId": "s1", "cwd": "/p",
            "timestamp": "2026-09-01T10:01:00.000Z",
            "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": text}]},
            "toolUseResult": {"type": "text", "file": {"filePath": path}}}


def _write(path, recs):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))


def _setup(tmp_path, recs):
    con = connect(tmp_path / "t.duckdb")
    _write(tmp_path / "proj" / "s1.jsonl", recs)
    scan_dir(con, tmp_path, ScanStats())
    return con


def test_scrub_removes_fragments_of_the_value_not_just_the_whole():
    url = "postgresql://app_user:nQrS7RPeMOkIUpkD@db.internal:5432/prod"
    reason = "a database URL with the password nQrS7RPeMOkIUpkD for user app_user on db.internal"
    out = _scrub(reason, url, "post…od")
    assert "nQrS7RPeMOkIUpkD" not in out and "app_user" not in out
    assert "post…od" in out
    assert _scrub("no overlap here", url, "post…od") == "no overlap here"


def test_redacted_window_hides_neighbouring_secrets_but_marks_the_target():
    other = "sk-ant-api03-" + "q9Wz" * 20
    text = f'ANTHROPIC_API_KEY={other}\nDB_PASSWORD = "{REAL}"\nAPP_ENV=prod'
    start = text.index(REAL)
    out = redacted_window(text, start, start + len(REAL), 400)
    assert f"«{REAL}»" in out
    assert other not in out and "[REDACTED:anthropic_api_key]" in out
    assert out.endswith("APP_ENV=prod")


def test_routing_sends_only_ambiguous_or_benign_looking_findings_to_the_model():
    assert needs_model("generic_secret", "medium", None)
    assert needs_model("phone", "low", "/p/src/main.py")
    assert not needs_model("github_token", "high", "/p/src/deploy.py")
    assert needs_model("github_token", "high", "/p/tests/test_auth.py")
    assert needs_model("aws_access_key_id", "high", "/p/.env.example")
    assert needs_model("openai_api_key", "high", "/p/docs/setup.md")


def test_adjudicate_routes_by_rule_and_judges_the_rest(tmp_path, fake_ollama):
    url, server = fake_ollama
    con = _setup(tmp_path, [
        _tool_result("u1", f"GITHUB_TOKEN={GHP}", "/p/src/deploy.py"),                     # vendor key, prod path -> rule
        _tool_result("u2", f"# fixture for unit tests\nTOKEN = '{GHP}'", "/p/tests/test_auth.py"),  # benign path -> model
        _user("u3", f'DB_PASSWORD = "{REAL}"'),                                             # ambiguous -> model
    ])
    assert con.execute("SELECT count(*) FROM findings").fetchone()[0] == 3

    stats = adjudicate(con, OllamaClient(url), "qwen2.5:7b")
    assert (stats.routed, stats.judged) == (1, 2)
    assert len(server.requests) == 2
    rows = dict(con.execute("SELECT s.path, j.model || ':' || j.verdict FROM judgments j"
                            " JOIN findings f USING (finding_id) JOIN segments s USING (segment_id)").fetchall())
    assert rows["/p/src/deploy.py"] == "rules:confirmed"
    assert rows["/p/tests/test_auth.py"] == "qwen2.5:7b:benign"
    assert rows[None] == "qwen2.5:7b:confirmed"
    assert {r[0] for r in con.execute("SELECT prompt_version FROM judgments").fetchall()} == {JUDGE_PROMPT_VERSION}
    assert all("File:" in r["messages"][-1]["content"] for r in server.requests)

    reasons = [r[0] for r in con.execute("SELECT reason FROM judgments").fetchall()]
    assert all(REAL not in r and GHP not in r for r in reasons)

    again = adjudicate(con, OllamaClient(url), "qwen2.5:7b")
    assert again.judged == 0 and again.routed == 0 and len(server.requests) == 2


def test_adjudicate_marks_unavailable_when_transcript_changed(tmp_path, fake_ollama):
    url, server = fake_ollama
    con = _setup(tmp_path, [_user("u1", f'DB_PASSWORD = "{REAL}"')])
    _write(tmp_path / "proj" / "s1.jsonl", [_user("u1", 'DB_PASSWORD = "somethingElse123!"')])

    stats = adjudicate(con, OllamaClient(url), "qwen2.5:7b")
    assert stats.unavailable == 1 and stats.judged == 0
    assert server.requests == []
    assert con.execute("SELECT verdict FROM judgments").fetchone()[0] == "unavailable"


def test_semantic_scan_reads_redacted_text_from_source_and_scrubs_summaries(tmp_path, fake_ollama):
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
    assert kind == "customer_or_employee_data" and severity == "high" and phone not in summary

    again = semantic_scan(con, OllamaClient(url), "qwen2.5:7b")
    assert again.scanned == 0 and len(server.requests) == 1


def test_scrub_summary_removes_identifiers_that_appear_in_the_source():
    src = "ticket for Priya Nair, order ORD-88213-XK, mail priya.nair@northwind-freight.com, ref 2026091100042"
    out = _scrub_summary("Customer Priya Nair (order ORD-88213-XK, priya.nair@northwind-freight.com, ref 2026091100042) complained", src)
    assert "ORD-88213-XK" not in out and "priya.nair@" not in out and "2026091100042" not in out
    assert "Customer" in out

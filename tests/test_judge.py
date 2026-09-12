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


def test_routing_sends_ambiguous_pathless_benign_path_or_commented_findings_to_the_model():
    bare = "APP_ENV=production\nLOG_LEVEL=info\nGITHUB_TOKEN=«x»\nFEATURE_FLAGS=beta\n"
    commented = "# stub value wired into the CI pipeline; GitHub never issued it\nGITHUB_TOKEN = \"«x»\"\n"
    assert needs_model("generic_secret", "medium", None, bare)
    assert needs_model("phone", "low", "/p/src/main.py", bare)
    assert not needs_model("github_token", "high", "/p/src/deploy.py", bare)          # bare config line
    assert needs_model("github_token", "high", "/p/ci/pipeline_stub.py", commented)   # comment beside it
    assert needs_model("github_token", "high", None, bare)                            # pasted: no path
    assert needs_model("github_token", "high", "/p/tests/test_auth.py", bare)
    assert needs_model("aws_access_key_id", "high", "/p/.env.example", bare)
    assert needs_model("openai_api_key", "high", "/p/docs/setup.md", bare)
    prose = "The screenshots in this walkthrough use the canned credentials from the vendor tutorial:\n\n    AWS_ACCESS_KEY_ID=«x»\n"
    assert needs_model("aws_access_key_id", "high", "/p/onboarding/walkthrough.md", prose)


def test_adjudicate_routes_by_rule_and_judges_the_rest(tmp_path, fake_ollama):
    url, server = fake_ollama
    con = _setup(tmp_path, [
        _tool_result("u1", f"APP_ENV=prod\nGITHUB_TOKEN={GHP}\nLOG_LEVEL=info", "/p/src/deploy.py"),  # bare vendor key, prod path -> rule
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


def test_semantic_scan_chunks_long_tool_results_and_records_piece_offsets(tmp_path, fake_ollama):
    url, server = fake_ollama
    filler = "\n".join(f"row {i:04d}: nothing sensitive here" for i in range(120))  # ~4 KB -> 2 pieces
    text = filler + "\nTicket: the customer disputed the charge and asked for a callback.\n"
    con = _setup(tmp_path, [_tool_result("u1", text, "/p/support/ticket.txt")])

    stats = semantic_scan(con, OllamaClient(url), "qwen2.5:7b")
    assert stats.scanned == 1 and stats.pieces == 2 and stats.findings == 1
    assert len(server.requests) == 2
    assert "(part 1 of 2)" in server.requests[0]["messages"][-1]["content"]

    piece, start, end, kind = con.execute("SELECT piece, start_off, end_off, kind FROM semantic_findings").fetchone()
    assert piece == 1 and kind == "customer_or_employee_data"
    assert "customer" in text[start:end] and "customer" not in text[:start]
    assert con.execute("SELECT n_pieces FROM semantic_scans").fetchone()[0] == 2


def test_semantic_credentials_findings_are_dropped_where_rules_already_redacted_one():
    from claudit.judge import _filter_semantic

    found = [("credentials", "high", "a token is hardcoded"), ("financial", "high", "revenue figure")]
    assert _filter_semantic(found, "GITHUB_TOKEN=[REDACTED:github_token]\nrevenue 4.2M") == [found[1]]
    assert _filter_semantic(found, "the api token is passed in the header value") == found  # no marker: keep


def test_scrub_summary_removes_identifiers_that_appear_in_the_source():
    src = "ticket for Priya Nair, order ORD-88213-XK, mail priya.nair@northwind-freight.com, ref 2026091100042"
    out = _scrub_summary("Customer Priya Nair (order ORD-88213-XK, priya.nair@northwind-freight.com, ref 2026091100042) complained", src)
    assert "ORD-88213-XK" not in out and "priya.nair@" not in out and "2026091100042" not in out
    assert "Customer" in out

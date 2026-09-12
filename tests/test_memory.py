import json

from claudit import memory
from claudit.db import connect
from claudit.ingest import ScanStats, scan_dir
from claudit.judge import RAG_PROMPT_VERSION, adjudicate
from claudit.ollama import OllamaClient
from claudit.secrets import set_state
from claudit.synth import generate

GHP = "ghp_" + "A1b2C3d4" * 5


def test_placeholder_excerpt_removes_the_value():
    out = memory.placeholder_excerpt(f"# fixture\nTOKEN = «{GHP}»\n", "github_token")
    assert GHP not in out and "«[github_token]»" in out


def test_build_from_labels_excludes_heldout_and_stores_no_values(tmp_path, fake_ollama):
    url, server = fake_ollama
    out = tmp_path / "synthetic"
    manifest = generate(out, n_sessions=30, seed=3)
    con = connect(tmp_path / "t.duckdb")
    scan_dir(con, out, ScanStats())

    n = memory.build_from_labels(con, OllamaClient(url), "fake-embed", out)
    assert n > 0
    origins = {r[0] for r in memory.stats(con)}
    assert "synthetic-heldout" not in origins and origins <= {"synthetic-seen", "synthetic-real"}

    stored = con.execute("SELECT excerpt, fingerprint FROM examples").fetchall()
    previews = {p["fingerprint"]: p for p in manifest["plants"]}
    for excerpt, fp in stored:
        assert "«[" in excerpt and "]»" in excerpt
        assert previews[fp]["preview"].split("…")[0][:4] not in excerpt.replace("«[", "") or len(previews[fp]["preview"]) < 6
    assert any("/api/embed" in str(r.get("input", "")) or "input" in r for r in server.requests)


def test_retrieve_excludes_same_session_and_fingerprint(tmp_path, fake_ollama):
    url, _ = fake_ollama
    con = connect(tmp_path / "t.duckdb")
    memory.ensure_schema(con)
    client = OllamaClient(url)
    rows = [
        ("# fixture value for unit tests\nTOKEN = «[github_token]»", "github_token", "benign", "fixture", "synthetic-seen", "s1", "fp1"),
        ("# fixture value for unit tests\nTOKEN = «[github_token]»", "github_token", "benign", "fixture", "synthetic-seen", "s2", "fp2"),
        ("APP_ENV=production\nTOKEN = «[github_token]»", "github_token", "confirmed", "no marker", "synthetic-real", "s3", "fp3"),
    ]
    memory._insert(con, client, "fake-embed", rows)

    hits = memory.retrieve(con, client, "fake-embed", f"# fixture value for unit tests\nTOKEN = «{GHP}»", "github_token",
                           exclude_session="s1", exclude_fingerprint="fp1", floor=0.0)
    assert hits and hits[0].verdict == "benign"
    assert all(h.excerpt.count("fixture") for h in hits[:1])
    assert len(hits) == 2  # s1/fp1 excluded
    rendered = memory.render_examples(hits)
    assert "Similar past cases" in rendered and "verdict=benign" in rendered and GHP not in rendered


def test_adjudicate_with_retriever_appends_examples_and_records_rag_prompt_version(tmp_path, fake_ollama):
    url, server = fake_ollama
    con = connect(tmp_path / "t.duckdb")
    d = tmp_path / "proj"
    d.mkdir()
    (d / "s9.jsonl").write_text(json.dumps({
        "type": "user", "uuid": "u1", "sessionId": "s9", "cwd": "/p", "timestamp": "2026-09-01T10:00:00.000Z",
        "message": {"role": "user", "content": f'DB_PASSWORD = "{"Tr0ub4dor&3xyz!!"}"'}}) + "\n")
    scan_dir(con, tmp_path, ScanStats())
    memory.ensure_schema(con)
    client = OllamaClient(url)
    memory._insert(con, client, "fake-embed", [
        ('DB_PASSWORD = "«[generic_secret]»"', "generic_secret", "confirmed", "no marker", "synthetic-real", "other", "fpX")])

    def retriever(excerpt, category, session_id, fingerprint):
        return memory.render_examples(memory.retrieve(con, client, "fake-embed", excerpt, category, session_id, fingerprint, floor=0.0))

    stats = adjudicate(con, client, "qwen2.5:7b", retriever=retriever)
    assert stats.judged == 1 and stats.with_examples == 1
    chat = [r for r in server.requests if "messages" in r][-1]
    assert "Similar past cases" in chat["messages"][-1]["content"]
    assert con.execute("SELECT prompt_version FROM judgments").fetchone()[0] == RAG_PROMPT_VERSION


def test_add_verdicts_uses_user_state(tmp_path, fake_ollama):
    url, _ = fake_ollama
    con = connect(tmp_path / "t.duckdb")
    d = tmp_path / "proj"
    d.mkdir()
    (d / "s1.jsonl").write_text(json.dumps({
        "type": "user", "uuid": "u1", "sessionId": "s1", "cwd": "/p", "timestamp": "2026-09-01T10:00:00.000Z",
        "message": {"role": "user", "content": f"GITHUB_TOKEN={GHP}"}}) + "\n")
    scan_dir(con, tmp_path, ScanStats())
    fp = con.execute("SELECT fingerprint FROM findings").fetchone()[0]
    set_state(con, fp[:12], "dismissed", "test key")
    assert memory.add_verdicts(con, OllamaClient(url), "fake-embed") == 1
    assert memory.stats(con) == [("user-verdict", "benign", 1)]

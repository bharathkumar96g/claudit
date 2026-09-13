import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from claudit import distill
from claudit.db import connect
from claudit.ingest import ScanStats, scan_dir
from claudit.judge import ADJUDICATE_SYSTEM
from claudit.synth import generate


@pytest.fixture
def corpus(tmp_path):
    out = tmp_path / "synthetic"
    manifest = generate(out, n_sessions=12, seed=3)
    con = connect(tmp_path / "t.duckdb")
    scan_dir(con, out, ScanStats())
    return con, out, manifest


def _judge_everything(con, model="qwen", reason="marker: 'dummy value for the README'"):
    rows = con.execute("SELECT finding_id FROM findings").fetchall()
    for (fid,) in rows:
        con.execute(
            "INSERT INTO judgments VALUES (?, 'benign', 0.8, ?, ?, 7, 10, 5, 100, now())", [fid, reason, model]
        )


def test_build_uses_the_judge_prompt_excludes_heldout_and_splits_by_session(corpus, tmp_path):
    con, out, manifest = corpus
    _judge_everything(con)  # teacher says benign for everything: only benign labels inherit its reason
    stats = distill.build_dataset(con, out / "labels.json", tmp_path / "ds", valid_share=0.2)

    heldout = sum(1 for p in manifest["plants"] if p.get("benign_set") == "heldout")
    assert stats.skipped_heldout == heldout
    assert stats.train + stats.valid == len(manifest["plants"]) - heldout
    assert stats.teacher_reasons == stats.by_verdict["benign"]
    assert stats.template_reasons == stats.by_verdict["confirmed"]

    train = [json.loads(line) for line in (tmp_path / "ds" / "train.jsonl").read_text().splitlines()]
    valid = [json.loads(line) for line in (tmp_path / "ds" / "valid.jsonl").read_text().splitlines()]
    assert len(train) == stats.train and len(valid) == stats.valid
    ex = train[0]["messages"]
    assert [m["role"] for m in ex] == ["system", "user", "assistant"]
    assert ex[0]["content"] == ADJUDICATE_SYSTEM
    assert "<excerpt>" in ex[1]["content"] and "«" in ex[1]["content"]
    target = json.loads(ex[2]["content"])
    assert target["verdict"] in ("confirmed", "benign") and 0 <= target["confidence"] <= 1

    # session-level split: no excerpt appears on both sides
    assert not ({e["messages"][1]["content"] for e in train} & {e["messages"][1]["content"] for e in valid})


def test_build_refuses_findings_without_a_label(corpus, tmp_path):
    con, out, manifest = corpus
    manifest["plants"] = manifest["plants"][1:]
    (out / "labels.json").write_text(json.dumps(manifest))
    with pytest.raises(distill.DistillError, match="not synthetic"):
        distill.build_dataset(con, out / "labels.json", tmp_path / "ds")


def test_train_argv_masks_the_prompt_and_pins_the_seed(tmp_path):
    argv = distill.train_argv(tmp_path / "ds", tmp_path / "ad", iters=50, seed=4)
    assert argv[1:4] == ["-m", "mlx_lm", "lora"]
    assert "--mask-prompt" in argv and "--train" in argv
    assert argv[argv.index("--seed") + 1] == "4" and argv[argv.index("--iters") + 1] == "50"
    assert argv[argv.index("--model") + 1] == distill.BASE_MODEL


def test_student_app_speaks_ollama_shape():
    def fake_generate(messages):
        assert messages[0]["role"] == "system"
        return '{"verdict": "benign", "confidence": 0.9, "reason": "r"}', 120, 18

    client = TestClient(distill.create_student_app(fake_generate), base_url="http://127.0.0.1")
    assert client.get("/api/tags").json()["models"][0]["name"] == distill.STUDENT_NAME
    body = {"model": distill.STUDENT_NAME, "messages": [{"role": "system", "content": "s"}], "format": {"type": "object"}}
    r = client.post("/api/chat", json=body).json()
    assert json.loads(r["message"]["content"])["verdict"] == "benign"
    assert r["prompt_eval_count"] == 120 and r["eval_count"] == 18 and r["total_duration"] >= 0
    assert client.post("/api/chat", json={"model": "other", "messages": []}).status_code == 404
    assert client.get("/api/version").json()["calls"] == 1


def test_student_app_rejects_foreign_hosts():
    client = TestClient(distill.create_student_app(lambda m: ("", 0, 0)), base_url="http://evil.example")
    assert client.get("/api/tags").status_code == 403


def test_reason_templates_cover_every_verdict():
    assert set(distill.TEMPLATE_REASON) == {"confirmed", "benign", "unsure"}
    assert Path(distill.__file__).exists()


def test_compare_reads_two_databases_side_by_side(tmp_path):
    out = tmp_path / "synthetic"
    manifest = generate(out, n_sessions=10, seed=5)
    paths = []
    for name, model, verdict, ms in (("a", "qwen2.5:7b", "confirmed", 8000), ("b", distill.STUDENT_NAME, "unsure", 900)):
        con = connect(tmp_path / f"{name}.duckdb")
        scan_dir(con, out, ScanStats())
        for (fid,) in con.execute("SELECT finding_id FROM findings").fetchall():
            reason = "model returned unparseable output" if verdict == "unsure" else "r"
            con.execute("INSERT INTO judgments VALUES (?, ?, 0.9, ?, ?, 7, 500, 40, ?, now())", [fid, verdict, reason, model, ms])
        con.close()
        paths.append(tmp_path / f"{name}.duckdb")
    rows = distill.compare(paths, out)
    n_real = sum(1 for p in manifest["plants"] if p["expected_verdict"] == "confirmed")
    a, b = rows
    assert a["model"] == "qwen2.5:7b" and a["real_kept"] == n_real and a["unparseable"] == 0 and a["p50_ms"] == 8000
    assert b["model"] == distill.STUDENT_NAME and b["real_unsure"] == n_real and b["unparseable"] == b["model_calls"]
    table = distill.compare_rows(rows)
    assert len(table) == 2 and len(table[0]) == len(distill.COMPARE_COLUMNS)

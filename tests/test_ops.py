import json

from fastapi.testclient import TestClient

from claudit.db import connect
from claudit.ops import health, latency, recent_runs, record_run, timed_run
from claudit.server import create_app
from claudit.util import utc_now

POST = {"X-Requested-With": "claudit"}


def test_runs_are_recorded_even_when_the_body_raises(tmp_path):
    con = connect(tmp_path / "t.duckdb")
    holder = [{"files": 2}]
    with timed_run(con, "scan", holder):
        pass
    try:
        with timed_run(con, "judge", []):
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    runs = recent_runs(con)
    assert [r["kind"] for r in runs] == ["judge", "scan"]
    assert runs[1]["stats"] == {"files": 2} and runs[0]["stats"] == {"error": "no stats"}
    assert all(r["duration_ms"] >= 0 for r in runs)


def test_json_log_line_is_emitted_when_enabled(tmp_path, monkeypatch, capsys):
    con = connect(tmp_path / "t.duckdb")
    monkeypatch.setenv("CLAUDIT_LOG", "json")
    record_run(con, "scan", utc_now(), 12, {"events": 3})
    line = json.loads(capsys.readouterr().err.strip())
    assert line["run"] == "scan" and line["events"] == 3 and line["duration_ms"] == 12


def test_latency_and_health_with_nothing_running(tmp_path):
    con = connect(tmp_path / "t.duckdb")
    con.execute("INSERT INTO judgments VALUES ('f1','confirmed',NULL,'r','qwen',7,10,5,800,now()),"
                " ('f2','benign',NULL,'r','qwen',7,10,5,1200,now()), ('f3','confirmed',NULL,'r','rules',7,0,0,0,now())")
    lat = latency(con)
    assert lat["judge_calls"]["n"] == 2 and lat["judge_calls"]["p50_ms"] == 1000.0
    h = health(con, "http://127.0.0.1:9", guard_port=9)
    assert h["db"]["ok"] and not h["ollama"]["ok"] and not h["guard"]["ok"] and h["guard"]["status"] is None


def test_health_and_metrics_endpoints(tmp_path):
    transcripts = tmp_path / "t"
    transcripts.mkdir()
    (transcripts / "s.jsonl").write_text(json.dumps({"type": "user", "uuid": "u1", "sessionId": "s", "cwd": "/p",
                                                     "message": {"role": "user", "content": "hello"}}) + "\n")
    app = create_app(tmp_path / "t.duckdb", transcripts, None, "http://127.0.0.1:9", "m", demo=False, guard_port=9)
    client = TestClient(app, base_url="http://127.0.0.1")
    assert client.post("/api/scan", headers=POST).status_code == 200
    h = client.get("/api/health").json()
    assert h["db"]["ok"] and not h["guard"]["ok"]
    m = client.get("/api/metrics").json()
    assert m["runs"][0]["kind"] == "scan" and m["runs"][0]["stats"]["events"] == 1
    assert m["latency"]["scans"]["n"] == 1

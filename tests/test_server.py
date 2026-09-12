import json
import time

from fastapi.testclient import TestClient

from claudit.server import create_app

SECRET = "sk-ant-api03-" + "q9Wz" * 20
POST = {"X-Requested-With": "claudit"}


def _user(uid, text):
    return {"type": "user", "uuid": uid, "sessionId": "s1", "cwd": "/p",
            "timestamp": "2026-09-01T10:00:00.000Z", "message": {"role": "user", "content": text}}


def _client(tmp_path, ollama_url="http://127.0.0.1:9", demo=False):
    transcripts = tmp_path / "transcripts"
    transcripts.mkdir()
    (transcripts / "s1.jsonl").write_text(json.dumps(_user("u1", f'DB_PASSWORD = "{SECRET}"')) + "\n")
    app = create_app(tmp_path / "t.duckdb", transcripts, None, ollama_url, "qwen2.5:7b", demo=demo)
    return TestClient(app, base_url="http://127.0.0.1"), transcripts


def _wait(client, job_id):
    for _ in range(50):
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] != "running":
            return job
        time.sleep(0.1)
    return job


def test_scan_then_summary_and_findings_never_expose_the_value(tmp_path):
    client, transcripts = _client(tmp_path)
    assert client.get("/").status_code == 200
    assert client.get("/api/summary").json()["totals"]["findings"] == 0

    scan = client.post("/api/scan", headers=POST).json()
    assert (scan["events"], scan["findings"]) == (1, 1)

    findings = client.get("/api/findings").json()
    assert len(findings) == 1 and findings[0]["category"] == "anthropic_api_key"
    body = client.get("/api/findings").text + client.get("/api/summary").text
    assert SECRET not in body

    (transcripts / "s1.jsonl").open("a").write(json.dumps(_user("u2", "hello")) + "\n")
    assert client.post("/api/scan", headers=POST).json()["events"] == 1
    assert client.get("/api/summary").json()["totals"]["events"] == 2


def test_posts_without_the_header_or_from_a_foreign_host_are_refused(tmp_path):
    client, _ = _client(tmp_path)
    assert client.post("/api/scan").status_code == 403
    assert client.post("/api/scan", headers={"X-Requested-With": "XMLHttpRequest"}).status_code == 403
    assert client.get("/api/summary", headers={"Host": "evil.example"}).status_code == 403
    assert client.post("/api/scan", headers=POST).status_code == 200


def test_judge_job_runs_in_background_and_reports_progress(tmp_path, fake_ollama):
    url, server = fake_ollama
    client, _ = _client(tmp_path, ollama_url=url)
    client.post("/api/scan", headers=POST)

    job = _wait(client, client.post("/api/judge", headers=POST).json()["job"])
    assert job["status"] == "done", job
    # a key pasted into a prompt has no file path, so its context is unknown and the model is asked
    assert (job["result"]["judge"]["routed"], job["result"]["judge"]["judged"]) == (0, 1)
    finding = client.get("/api/findings").json()[0]
    assert (finding["verdict"], finding["judged_by"]) == ("confirmed", "qwen2.5:7b")


def test_judge_job_surfaces_unreachable_ollama(tmp_path):
    client, _ = _client(tmp_path)
    client.post("/api/scan", headers=POST)
    job = _wait(client, client.post("/api/judge", headers=POST).json()["job"])
    assert job["status"] == "error" and "cannot reach Ollama" in job["error"]


def test_synth_is_refused_outside_demo_mode(tmp_path):
    client, _ = _client(tmp_path)
    assert client.post("/api/synth", headers=POST).status_code == 403

"""A fake Ollama server implementing just enough of /api/chat, /api/tags, /api/version for tests."""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

FAKE_MODEL = "qwen2.5:7b"
_DIMS = 64


def _fake_embedding(text: str) -> list[float]:
    vec = [0.0] * _DIMS
    for word in re.findall(r"[a-z]{3,}", text.lower()):
        vec[hash(word) % _DIMS] += 1.0
    norm = sum(x * x for x in vec) ** 0.5 or 1.0
    return [x / norm for x in vec]


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, payload, status=200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/version":
            self._json({"version": "0.0.0-fake"})
        elif self.path == "/api/tags":
            self._json({"models": [{"name": FAKE_MODEL}]})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.requests.append(body)
        if self.path == "/api/embed":
            # Deterministic bag-of-words vectors: texts sharing words get high cosine similarity.
            inputs = body["input"] if isinstance(body["input"], list) else [body["input"]]
            self._json({"model": body["model"], "embeddings": [_fake_embedding(t) for t in inputs], "prompt_eval_count": 1})
            return
        if self.path != "/api/chat":
            self._json({"error": "not found"}, 404)
            return
        if body["model"] != FAKE_MODEL:
            self._json({"error": f"model '{body['model']}' not found"}, 404)
            return

        user = body["messages"][-1]["content"]
        props = body.get("format", {}).get("properties", {})
        if "verdict" in props:
            value = re.search("«(.*?)»", user, re.S).group(1)
            verdict = "benign" if "fixture" in user.lower() else "confirmed"
            # Deliberately echoes the value so tests can prove the reason gets scrubbed.
            content = {"verdict": verdict, "confidence": 0.9, "reason": f"the value {value} looks {verdict}"}
        else:
            hit = "customer" in user.lower()
            content = {"findings": [
                {"kind": "customer_or_employee_data", "severity": "high", "summary": "customer contact details present"}
            ] if hit else []}
        self._json({
            "model": body["model"],
            "message": {"role": "assistant", "content": json.dumps(content)},
            "done": True,
            "prompt_eval_count": 10,
            "eval_count": 5,
            "total_duration": 1_000_000,
        })


@pytest.fixture
def fake_ollama():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    server.requests = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", server
    finally:
        server.shutdown()
        server.server_close()

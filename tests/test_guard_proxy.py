"""The proxy against an in-process fake upstream that records what it receives and streams what it was told to."""

import json
import re

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.testclient import TestClient

from claudit.guard.proxy import create_guard_app, mask_request_body, unmask_json_body
from claudit.guard.pseudonym import Session

REAL = "ghp_" + "A1b2C3d4" * 5
AKIA = "AKIA" + "J4K7QZ2M9XP3RT6W"
GHP_RE = re.compile(r"ghp_[A-Za-z0-9]{40}")


def sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def make_upstream(mode="echo"):
    """Streams back the ghp_ token it received, split across two deltas, plus a Write tool call carrying it."""
    app = FastAPI()
    app.state.received = []

    @app.post("/v1/messages")
    async def messages(request: Request):
        body = await request.body()
        app.state.received.append({"body": json.loads(body), "headers": dict(request.headers), "query": str(request.url.query)})
        token = GHP_RE.search(body.decode())
        seen = token.group(0) if token else "none"
        if mode == "altered":
            seen = seen[:20] + "X" + seen[21:]  # the model "changed" one character of the pseudonym
        if not app.state.received[-1]["body"].get("stream"):
            return JSONResponse({"id": "m", "type": "message", "role": "assistant",
                                 "content": [{"type": "text", "text": f"the key is {seen}"}], "stop_reason": "end_turn"})

        async def gen():
            yield sse("message_start", {"type": "message_start", "message": {"id": "m"}})
            yield sse("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
            yield sse("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Your token " + seen[:12]}})
            yield sse("ping", {"type": "ping"})
            yield sse("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": seen[12:] + " is set."}})
            yield sse("content_block_stop", {"type": "content_block_stop", "index": 0})
            yield sse("content_block_start", {"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "t1", "name": "Write", "input": {}}})
            partial = json.dumps({"file_path": "/p/.env", "content": f"GITHUB_TOKEN={seen}\n"})
            yield sse("content_block_delta", {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": partial[:30]}})
            yield sse("content_block_delta", {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": partial[30:]}})
            yield sse("content_block_stop", {"type": "content_block_stop", "index": 1})
            yield sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 9}})
            yield sse("message_stop", {"type": "message_stop"})

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.post("/v1/messages/count_tokens")
    async def count(request: Request):
        app.state.received.append({"body": json.loads(await request.body())})
        return JSONResponse({"input_tokens": 42})

    @app.get("/v1/models")
    async def models():
        return JSONResponse({"data": [{"id": "claude-sonnet-5"}]})

    return app


def _proxy(upstream_app):
    session = Session()
    app = create_guard_app("https://upstream.test", session=session, transport=httpx.ASGITransport(app=upstream_app))
    return TestClient(app, base_url="http://127.0.0.1"), session


def _request_body(stream=True):
    return {
        "model": "claude-sonnet-5", "max_tokens": 100, "stream": stream,
        "system": [{"type": "text", "text": "You are Claude Code.", "cache_control": {"type": "ephemeral"}}],
        "messages": [
            {"role": "user", "content": f"Here is my .env:\nGITHUB_TOKEN={REAL}\nAWS_ACCESS_KEY_ID={AKIA}\nplease check it"},
            {"role": "assistant", "content": [{"type": "text", "text": "Reading."}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t0", "content": f"GITHUB_TOKEN={REAL}"}]},
        ],
    }


def test_streaming_roundtrip_masks_outbound_and_restores_inbound():
    upstream = make_upstream()
    client, session = _proxy(upstream)
    headers = {"anthropic-beta": "oauth-2025-04-20,prompt-caching-2024-07-31", "anthropic-version": "2023-06-01",
               "authorization": "Bearer sk-ant-oat01-secret", "x-api-key": "should-not-matter"}

    with client.stream("POST", "/v1/messages?beta=true", json=_request_body(), headers=headers) as r:
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
        out = b"".join(r.iter_bytes())

    received = upstream.state.received[-1]
    sent = json.dumps(received["body"])
    assert REAL not in sent and AKIA not in sent  # upstream never sees real values
    fake = session.real_to_fake[REAL]
    assert sent.count(fake) == 2  # both the prompt and the tool_result carry the same pseudonym
    assert received["body"]["system"] == _request_body()["system"]  # untouched
    assert received["headers"]["anthropic-beta"] == headers["anthropic-beta"]
    assert received["headers"]["authorization"] == headers["authorization"]
    assert received["headers"]["accept-encoding"] == "identity"
    assert received["query"] == "beta=true"

    text = out.decode()
    assert REAL in text and fake not in text  # restored in the text delta split across two frames
    assert "event: ping" in text
    tool_json = "".join(json.loads(f.split("data: ", 1)[1])["delta"]["partial_json"]
                        for f in text.split("\n\n") if '"input_json_delta"' in f)
    assert json.loads(tool_json)["content"] == f"GITHUB_TOKEN={REAL}\n"  # restored inside the tool call too
    assert "claudit_guard_blocked_write" not in text

    status = client.get("/guard/status").json()
    assert status["messages_requests"] == 1 and status["streamed"] == 1
    assert status["values_masked"] == 3 and status["values_restored"] == 2 and status["blocked_writes"] == 0
    assert status["masked_by_category"] == {"github_token": 2, "aws_access_key_id": 1}


def test_altered_pseudonym_inside_a_write_blocks_the_write_and_never_leaks():
    upstream = make_upstream(mode="altered")
    client, _session = _proxy(upstream)
    with client.stream("POST", "/v1/messages", json=_request_body()) as r:
        out = b"".join(r.iter_bytes()).decode()
    assert REAL not in out  # nothing restored because the model changed the pseudonym: the safe direction
    error_at = out.find("claudit_guard_blocked_write")
    assert error_at != -1 and error_at < out.rfind("event: message_stop")  # the client sees the error before the end
    status = client.get("/guard/status").json()
    assert status["blocked_writes"] >= 1 and status["suspected_misses"] >= 1


def test_non_streaming_reply_is_unmasked_and_other_routes_pass_through():
    upstream = make_upstream()
    client, _session = _proxy(upstream)
    r = client.post("/v1/messages", json=_request_body(stream=False))
    assert r.status_code == 200
    assert r.json()["content"][0]["text"] == f"the key is {REAL}"

    r = client.post("/v1/messages/count_tokens", json={"model": "m", "messages": [{"role": "user", "content": f"k={REAL}"}]})
    assert r.json() == {"input_tokens": 42}
    assert REAL not in json.dumps(upstream.state.received[-1]["body"])  # masked on the way to count_tokens too

    assert client.get("/v1/models").json()["data"][0]["id"] == "claude-sonnet-5"
    assert client.head("/api/hello").status_code == 200
    assert client.get("/guard/status", headers={"Host": "evil.example"}).status_code == 403


def test_mask_and_unmask_helpers_touch_only_message_text():
    session = Session()
    body = json.dumps({"system": [{"type": "text", "text": f"never touch {REAL}"}], "tools": [{"name": "x"}],
                       "messages": [{"role": "user", "content": [{"type": "text", "text": f"a {REAL} b"}, {"type": "image", "source": {}}]}]}).encode()
    masked, n = mask_request_body(body, session)
    data = json.loads(masked)
    assert n == 1 and REAL in data["system"][0]["text"] and REAL not in data["messages"][0]["content"][0]["text"]
    assert data["tools"] == [{"name": "x"}] and data["messages"][0]["content"][1] == {"type": "image", "source": {}}
    fake = session.real_to_fake[REAL]
    restored, k = unmask_json_body(json.dumps({"content": [{"type": "text", "text": f"use {fake}"}]}).encode(), session.fake_to_real)
    assert k == 1 and json.loads(restored)["content"][0]["text"] == f"use {REAL}"
    assert mask_request_body(b"not json", session) == (b"not json", 0)

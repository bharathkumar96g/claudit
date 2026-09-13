"""The gateway: masks outbound requests, un-masks the streamed reply, forwards everything else byte-for-byte.

Honours the Claude Code gateway contract (Design 03): headers forwarded unchanged (anthropic-beta included),
the `system` array untouched, the stream never buffered, pings forwarded immediately. Only text inside
`messages[*].content` is rewritten. No request or response body is ever logged.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from .pseudonym import Session
from .rewrite import StreamRewriter

DEFAULT_UPSTREAM = "https://api.anthropic.com"
DEFAULT_PORT = 8787
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_DROP_REQUEST_HEADERS = frozenset({"host", "content-length", "connection", "accept-encoding", "transfer-encoding"})
_DROP_RESPONSE_HEADERS = frozenset({"content-length", "content-encoding", "transfer-encoding", "connection"})


@dataclass
class GuardStats:
    requests: int = 0
    messages_requests: int = 0
    streamed: int = 0
    values_masked: int = 0
    values_restored: int = 0
    suspected_misses: int = 0
    blocked_writes: int = 0
    mask_ms_total: float = 0.0
    upstream_errors: int = 0
    masked_by_category: dict[str, int] = field(default_factory=dict)


def _mask_block_text(session: Session, text: str) -> tuple[str, int]:
    masked, matches = session.mask_text(text)
    return masked, len(matches)


def mask_request_body(body: bytes, session: Session) -> tuple[bytes, int]:
    """Rewrite text inside messages[*].content only. Anything unparseable passes through unchanged."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body, 0
    messages = data.get("messages") if isinstance(data, dict) else None
    if not isinstance(messages, list):
        return body, 0
    n = 0
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if isinstance(content, str):
            msg["content"], k = _mask_block_text(session, content)
            n += k
        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text" and isinstance(block.get("text"), str):
                    block["text"], k = _mask_block_text(session, block["text"])
                    n += k
                elif block.get("type") == "tool_result":
                    inner = block.get("content")
                    if isinstance(inner, str):
                        block["content"], k = _mask_block_text(session, inner)
                        n += k
                    elif isinstance(inner, list):
                        for sub in inner:
                            if isinstance(sub, dict) and sub.get("type") == "text" and isinstance(sub.get("text"), str):
                                sub["text"], k = _mask_block_text(session, sub["text"])
                                n += k
    return json.dumps(data, ensure_ascii=False).encode("utf-8"), n


def unmask_json_body(body: bytes, fake_to_real: dict[str, str]) -> tuple[bytes, int]:
    """Non-streaming replies: pseudonyms sit inside JSON strings, so the real value goes back in escaped."""
    text = body.decode("utf-8", errors="replace")
    n = 0
    for fake, real in fake_to_real.items():
        if fake in text:
            n += text.count(fake)
            text = text.replace(fake, json.dumps(real, ensure_ascii=False)[1:-1])
    return text.encode("utf-8"), n


def _host_only(header: str) -> str:
    if header.startswith("["):
        return header.split("]")[0] + "]"
    return header.rsplit(":", 1)[0] if ":" in header else header


def create_guard_app(
    upstream: str = DEFAULT_UPSTREAM,
    session: Session | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    allowed_hosts: frozenset[str] | None = LOOPBACK_HOSTS,
) -> FastAPI:
    session = session or Session()
    stats = GuardStats()
    upstream = upstream.rstrip("/")
    client = httpx.AsyncClient(
        transport=transport, timeout=httpx.Timeout(600.0, connect=30.0), follow_redirects=False
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await client.aclose()
            session.clear()  # the mapping is the most valuable object on the machine; it dies with the process

    app = FastAPI(title="claudit guard", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.session = session
    app.state.stats = stats

    @app.middleware("http")
    async def loopback_only(request: Request, call_next):
        if allowed_hosts is not None and _host_only(request.headers.get("host", "")) not in allowed_hosts:
            return JSONResponse({"error": "forbidden host"}, status_code=403)
        return await call_next(request)

    @app.get("/guard/status")
    def status():
        stats.masked_by_category = dict(session.masked_by_category)
        return {"upstream": upstream, **asdict(stats), "mapping_size": len(session.fake_to_real)}

    @app.head("/api/hello")
    def hello():
        return Response(status_code=200)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"])
    async def forward(path: str, request: Request):
        stats.requests += 1
        body = await request.body()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _DROP_REQUEST_HEADERS}
        headers["accept-encoding"] = "identity"  # rewriting needs plain bytes

        is_messages = request.method == "POST" and path.rstrip("/").endswith("v1/messages")
        if request.method == "POST" and (is_messages or path.rstrip("/").endswith("count_tokens")):
            t0 = time.perf_counter()
            body, n = mask_request_body(body, session)
            stats.mask_ms_total += (time.perf_counter() - t0) * 1000
            stats.values_masked += n
            if is_messages:
                stats.messages_requests += 1

        url = f"{upstream}/{path}" + (f"?{request.url.query}" if request.url.query else "")
        req = client.build_request(request.method, url, content=body, headers=headers)
        try:
            resp = await client.send(req, stream=True)
        except httpx.HTTPError as e:
            stats.upstream_errors += 1
            return JSONResponse({"error": {"type": "claudit_guard_upstream", "message": str(e)}}, status_code=502)

        resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in _DROP_RESPONSE_HEADERS}
        content_type = resp.headers.get("content-type", "")

        if is_messages and content_type.startswith("text/event-stream"):
            stats.streamed += 1
            rewriter = StreamRewriter(dict(session.fake_to_real))

            async def stream() -> AsyncIterator[bytes]:
                try:
                    async for chunk in resp.aiter_raw():
                        out = rewriter.feed(chunk)
                        if out:
                            yield out
                    tail = rewriter.finish()
                    if tail:
                        yield tail
                finally:
                    await resp.aclose()
                    stats.values_restored += rewriter.replaced
                    stats.suspected_misses += rewriter.suspected_misses
                    stats.blocked_writes += rewriter.blocked_writes

            return StreamingResponse(stream(), status_code=resp.status_code, headers=resp_headers, media_type=content_type)

        raw = await resp.aread()
        await resp.aclose()
        if is_messages and content_type.startswith("application/json"):
            raw, n = unmask_json_body(raw, session.fake_to_real)
            stats.values_restored += n
        return Response(content=raw, status_code=resp.status_code, headers=resp_headers, media_type=content_type or None)

    return app


def env_hint(port: int) -> str:
    return (
        f"export ANTHROPIC_BASE_URL=http://127.0.0.1:{port}\n"
        "Then start Claude Code (CLI or VS Code) in that shell. Your claude.ai login keeps working; only the\n"
        "request path changes. `unset ANTHROPIC_BASE_URL` to go back. The desktop app uses its own gateway\n"
        "configuration and is not affected by this variable."
    )

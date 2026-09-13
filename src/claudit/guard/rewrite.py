"""Un-mask pseudonyms in a streamed Messages API response, event by event.

Works on SSE bytes. Only `content_block_delta` payloads are touched (text_delta.text, thinking_delta.thinking,
input_json_delta.partial_json); every other event is forwarded unchanged and immediately, `ping` included.
A pseudonym can be split across two deltas, so per content block the rewriter holds back a tail no longer
than the longest pseudonym prefix that could still be completing, and flushes it on content_block_stop.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

_REWRITABLE = {"text_delta": "text", "thinking_delta": "thinking", "input_json_delta": "partial_json"}


def _sse_event(event: str, data: dict) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False, separators=(',', ':'))}\n\n".encode()


@dataclass
class StreamRewriter:
    fake_to_real: dict[str, str]
    _prefixes: set[str] = field(init=False, default_factory=set)
    _max_len: int = field(init=False, default=0)
    _buf: bytes = field(init=False, default=b"")
    _carry: dict[int, tuple[str, str]] = field(init=False, default_factory=dict)  # index -> (kind, held text)
    replaced: int = 0
    suspected_misses: int = 0

    def __post_init__(self) -> None:
        for fake in self.fake_to_real:
            self._max_len = max(self._max_len, len(fake))
            for i in range(1, len(fake)):
                self._prefixes.add(fake[:i])

    # --- SSE framing -------------------------------------------------------------------------------------

    def feed(self, chunk: bytes) -> bytes:
        """Feed upstream bytes; returns bytes to send downstream now."""
        self._buf += chunk
        out = bytearray()
        while True:
            cut = self._buf.find(b"\n\n")
            if cut == -1:
                break
            raw, self._buf = self._buf[: cut + 2], self._buf[cut + 2 :]
            out += self._rewrite_frame(raw)
        return bytes(out)

    def finish(self) -> bytes:
        """Flush anything held back; call when the upstream closes."""
        out = bytearray()
        for index in list(self._carry):
            out += self._flush(index)
        if self._buf:
            out += self._buf
            self._buf = b""
        return bytes(out)

    # --- events -----------------------------------------------------------------------------------------

    def _rewrite_frame(self, raw: bytes) -> bytes:
        if not self.fake_to_real:
            return raw
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw
        event, data = None, None
        for line in text.split("\n"):
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data = line[5:].strip()
        if data is None or event not in ("content_block_delta", "content_block_stop", "message_stop"):
            return raw
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            return raw

        if event == "content_block_stop":
            return self._flush(int(payload.get("index", 0))) + raw
        if event == "message_stop":
            out = bytearray()
            for index in list(self._carry):
                out += self._flush(index)
            return bytes(out) + raw

        delta = payload.get("delta") or {}
        kind = str(delta.get("type") or "")
        key = _REWRITABLE.get(kind)
        if key is None or not isinstance(delta.get(key), str):
            return raw
        index = int(payload.get("index", 0))
        held = self._carry.get(index, (kind, ""))[1]
        combined = held + delta[key]
        emit, keep = self._split(combined)
        emit = self._replace(emit, escaped=(kind == "input_json_delta"))
        self._carry[index] = (kind, keep) if keep else (kind, "")
        if not keep:
            self._carry.pop(index, None)
        if not emit:
            return b""
        delta[key] = emit
        payload["delta"] = delta
        return _sse_event(event, payload)

    def _flush(self, index: int) -> bytes:
        kind, held = self._carry.pop(index, (None, ""))
        if not held or kind is None:
            return b""
        key = _REWRITABLE[kind]
        return _sse_event("content_block_delta", {"type": "content_block_delta", "index": index,
                                                  "delta": {"type": kind, key: self._replace(held, escaped=(kind == "input_json_delta"))}})

    # --- text --------------------------------------------------------------------------------------------

    def _split(self, s: str) -> tuple[str, str]:
        """Emit everything except a tail that is a proper prefix of some pseudonym."""
        max_hold = min(self._max_len - 1, len(s))
        for k in range(max_hold, 0, -1):
            if s[-k:] in self._prefixes:
                return s[:-k], s[-k:]
        return s, ""

    def _replace(self, s: str, escaped: bool) -> str:
        if not s:
            return s
        for fake, real in self.fake_to_real.items():
            if fake in s:
                self.replaced += s.count(fake)
                s = s.replace(fake, json.dumps(real, ensure_ascii=False)[1:-1] if escaped else real)
        return s

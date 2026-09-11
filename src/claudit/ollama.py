"""Minimal client for a local Ollama server (https://github.com/ollama/ollama/blob/main/docs/api.md)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5:7b"


class OllamaError(RuntimeError):
    pass


class OllamaUnavailable(OllamaError):
    pass


@dataclass(frozen=True)
class ChatResult:
    content: str
    prompt_tokens: int
    output_tokens: int
    duration_ms: int


class OllamaClient:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: float = 180.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            self.base_url + path, data=data, method=method, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:300]
            raise OllamaError(f"Ollama returned HTTP {e.code} for {path}: {detail}") from e
        except urllib.error.URLError as e:
            raise OllamaUnavailable(
                f"cannot reach Ollama at {self.base_url} ({e.reason}); is the Ollama app running?"
            ) from e

    def version(self) -> str:
        return str(self._request("GET", "/api/version").get("version", "unknown"))

    def models(self) -> list[str]:
        return [m["name"] for m in self._request("GET", "/api/tags").get("models", [])]

    def chat(
        self,
        model: str,
        messages: list[dict],
        schema: dict | None = None,
        temperature: float = 0.0,
        num_ctx: int = 8192,
    ) -> ChatResult:
        body: dict = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_ctx": num_ctx},
            "keep_alive": "10m",
        }
        if schema is not None:
            body["format"] = schema
        r = self._request("POST", "/api/chat", body)
        return ChatResult(
            content=str(r.get("message", {}).get("content", "")),
            prompt_tokens=int(r.get("prompt_eval_count", 0)),
            output_tokens=int(r.get("eval_count", 0)),
            duration_ms=int(r.get("total_duration", 0)) // 1_000_000,
        )

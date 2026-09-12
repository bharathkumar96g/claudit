"""Minimal client for a local Ollama server (https://github.com/ollama/ollama/blob/main/docs/api.md)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5:7b"
DEFAULT_EMBED_MODEL = "nomic-embed-text"


class OllamaError(RuntimeError):
    pass


class OllamaUnavailableError(OllamaError):
    pass


@dataclass(frozen=True)
class ChatResult:
    content: str
    prompt_tokens: int
    output_tokens: int
    duration_ms: int


class OllamaClient:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: float = 180.0) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError(f"Ollama base URL must be http(s): {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(  # noqa: S310  scheme is validated in __init__
            self.base_url + path, data=data, method=method, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 # nosec B310
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:300]
            raise OllamaError(f"Ollama returned HTTP {e.code} for {path}: {detail}") from e
        except urllib.error.URLError as e:
            raise OllamaUnavailableError(
                f"cannot reach Ollama at {self.base_url} ({e.reason}); is the Ollama app running?"
            ) from e

    def version(self) -> str:
        return str(self._request("GET", "/api/version").get("version", "unknown"))

    def models(self) -> list[str]:
        return [m["name"] for m in self._request("GET", "/api/tags").get("models", [])]

    def embed(self, model: str, inputs: list[str]) -> list[list[float]]:
        """POST /api/embed. One vector per input, in order."""
        if not inputs:
            return []
        r = self._request("POST", "/api/embed", {"model": model, "input": inputs, "keep_alive": "10m"})
        vectors = r.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(inputs):
            raise OllamaError(f"embed returned {len(vectors) if isinstance(vectors, list) else 'no'} vectors for {len(inputs)} inputs")
        return [[float(x) for x in v] for v in vectors]

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

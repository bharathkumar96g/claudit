import json

import pytest

from claudit.judge import ADJUDICATE_SCHEMA
from claudit.ollama import OllamaClient, OllamaError, OllamaUnavailable


def test_client_roundtrip(fake_ollama):
    url, server = fake_ollama
    client = OllamaClient(url)
    assert client.version() == "0.0.0-fake"
    assert client.models() == ["qwen2.5:7b"]

    result = client.chat("qwen2.5:7b", [{"role": "user", "content": "«abc» fixture"}], schema=ADJUDICATE_SCHEMA)
    assert json.loads(result.content)["verdict"] == "benign"
    assert (result.prompt_tokens, result.output_tokens, result.duration_ms) == (10, 5, 1)

    sent = server.requests[-1]
    assert sent["stream"] is False
    assert sent["format"] == ADJUDICATE_SCHEMA
    assert sent["options"]["temperature"] == 0.0


def test_unreachable_server_gives_clear_error():
    with pytest.raises(OllamaUnavailable, match="cannot reach Ollama"):
        OllamaClient("http://127.0.0.1:9", timeout=2).version()


def test_missing_model_surfaces_server_error(fake_ollama):
    url, _ = fake_ollama
    with pytest.raises(OllamaError, match="not found"):
        OllamaClient(url).chat("nope", [{"role": "user", "content": "x"}])

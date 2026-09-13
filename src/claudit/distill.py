"""Distil the 7B judge into a 0.5B LoRA student.

Three steps, all local:

  build  - turn a *synthetic* corpus (labels.json + the 7B judge's stored verdicts) into chat-format
           training data. The prompt is assembled by the same code the judge uses, so the student is
           trained on exactly the messages it will be asked at inference.
  train  - LoRA on an Apple-silicon quantised base via mlx-lm (subprocess; the `train` dependency group).
  serve  - expose the trained student behind Ollama's /api/chat shape on loopback, so `claudit judge
           --base-url http://127.0.0.1:8790 --model claudit-student` runs the unchanged judge pipeline
           (routing, instruction stripping, policy, scrubbing) against it. Same prompts, same grader.

Privacy rule, enforced not promised: `build` refuses unless every finding in the database matches a
planted label. Training data therefore only ever contains generated values. Held-out benign plants are
excluded from training so they stay held out for the comparison.
"""

from __future__ import annotations

import json
import queue
import subprocess  # nosec B404  fixed argv, no shell
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass, field
from pathlib import Path

import duckdb
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .judge import ADJUDICATE_SYSTEM, WINDOW, build_user_message, strip_instructions
from .reveal import redacted_window, reveal_segment
from .util import sha256

BASE_MODEL = "mlx-community/Qwen2.5-0.5B-Instruct-4bit"  # 290 MB; QLoRA on the quantised weights
STUDENT_NAME = "claudit-student"
TEMPLATE_REASON = {
    "confirmed": "no marker in the excerpt or path says this value is disconnected from a live system",
    "benign": "the excerpt or path describes this value as not connected to anything real",
    "unsure": "the excerpt carries markers pointing both ways",
}
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


class DistillError(RuntimeError):
    pass


@dataclass
class BuildStats:
    train: int = 0
    valid: int = 0
    skipped_heldout: int = 0
    teacher_reasons: int = 0
    template_reasons: int = 0
    by_verdict: Counter = field(default_factory=Counter)


def _load_plants(labels_path: Path) -> dict[tuple[str, str, str], dict]:
    manifest = json.loads(labels_path.read_text())
    return {(p["session_id"], p["category"], p["fingerprint"]): p for p in manifest["plants"]}


def _target(verdict: str, reason: str) -> str:
    confidence = 0.9 if verdict != "unsure" else 0.5
    return json.dumps({"verdict": verdict, "confidence": confidence, "reason": reason}, ensure_ascii=False)


def build_dataset(
    con: duckdb.DuckDBPyConnection, labels_path: Path, out_dir: Path, valid_share: float = 0.1
) -> BuildStats:
    plants = _load_plants(labels_path)
    rows = con.execute(
        "SELECT f.finding_id, f.segment_id, f.category, f.start_off, f.end_off, f.fingerprint, f.session_id,"
        " s.path, j.verdict, j.reason, j.model"
        " FROM findings f JOIN segments s ON s.segment_id = f.segment_id"
        " LEFT JOIN judgments j ON j.finding_id = f.finding_id"
        " ORDER BY f.session_id, f.ts"
    ).fetchall()
    stats = BuildStats()
    train: list[dict] = []
    valid: list[dict] = []
    for finding_id, segment_id, category, start, end, fingerprint, session_id, path, t_verdict, t_reason, t_model in rows:
        plant = plants.get((session_id, category, fingerprint))
        if plant is None:
            raise DistillError(
                f"finding {finding_id} ({category}) has no planted label: refusing to build training data"
                " from anything that is not synthetic"
            )
        if plant.get("benign_set") == "heldout":
            stats.skipped_heldout += 1
            continue
        text = reveal_segment(con, segment_id)
        if text is None or sha256(text[start:end]) != fingerprint:
            continue
        excerpt, _ = strip_instructions(redacted_window(text, start, end, WINDOW))
        label = plant["expected_verdict"]
        if t_verdict == label and t_model not in (None, "rules") and t_reason:
            reason, stats.teacher_reasons = t_reason, stats.teacher_reasons + 1
        else:
            reason, stats.template_reasons = TEMPLATE_REASON[label], stats.template_reasons + 1
        example = {
            "messages": [
                {"role": "system", "content": ADJUDICATE_SYSTEM},
                {"role": "user", "content": build_user_message(category, path, excerpt)},
                {"role": "assistant", "content": _target(label, reason)},
            ]
        }
        stats.by_verdict[label] += 1
        # Split by session so the two files never share an excerpt; the hash keeps the split stable.
        bucket = int(sha256(session_id)[:8], 16) % 1000
        (valid if bucket < valid_share * 1000 else train).append(example)
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, examples in (("train", train), ("valid", valid)):
        with (out_dir / f"{name}.jsonl").open("w") as fh:
            for ex in examples:
                fh.write(json.dumps(ex, ensure_ascii=False) + "\n")
    stats.train, stats.valid = len(train), len(valid)
    return stats


def train_argv(
    data_dir: Path,
    adapter_dir: Path,
    base_model: str = BASE_MODEL,
    iters: int = 600,
    num_layers: int = 8,
    batch_size: int = 1,
    max_seq_length: int = 2048,
    learning_rate: float = 1e-4,
    seed: int = 0,
) -> list[str]:
    """mlx-lm LoRA invocation. --mask-prompt: loss on the assistant JSON only, never on the excerpt."""
    return [
        sys.executable, "-m", "mlx_lm", "lora",
        "--model", base_model, "--train", "--data", str(data_dir), "--adapter-path", str(adapter_dir),
        "--fine-tune-type", "lora", "--mask-prompt",
        "--iters", str(iters), "--batch-size", str(batch_size), "--num-layers", str(num_layers),
        "--max-seq-length", str(max_seq_length), "--learning-rate", str(learning_rate), "--seed", str(seed),
        "--steps-per-report", "20", "--steps-per-eval", "100", "--val-batches", "-1", "--grad-checkpoint",
    ]


def train(argv: list[str]) -> int:
    started = time.time()
    proc = subprocess.run(argv, check=False)  # noqa: S603  # nosec B603  argv built above, no shell
    print(f"training finished in {time.time() - started:.0f}s with exit code {proc.returncode}")
    return proc.returncode


def compare(db_paths: list[Path], eval_dir: Path) -> list[dict]:
    """One row per database: the judge confusion from `report.evaluate_data` plus the per-model latency,
    so two databases judged over the same test set by different models read side by side."""
    from .ops import latency_by_model
    from .report import evaluate_data

    out = []
    for path in db_paths:
        con = duckdb.connect(str(path), read_only=True)
        try:
            ev = evaluate_data(con, eval_dir)
            models = latency_by_model(con)
        finally:
            con.close()
        judge = ev.get("judge") or {"rows": [], "by_rule": 0, "accuracy": None}
        by = {r["expected"]: r for r in judge["rows"]}
        real, seen, held = by.get("confirmed", {}), by.get("benign/seen", {}), by.get("benign/heldout", {})
        m = models[0] if models else {}
        out.append({
            "db": path.stem, "model": m.get("model", "—"), "model_calls": m.get("n", 0), "by_rule": judge["by_rule"],
            "real_kept": real.get("confirmed", 0), "real_dismissed": real.get("benign", 0), "real_unsure": real.get("unsure", 0),
            "seen_benign": seen.get("benign", 0), "seen_n": sum(seen.get(k, 0) for k in ("confirmed", "benign", "unsure")),
            "heldout_benign": held.get("benign", 0), "heldout_n": sum(held.get(k, 0) for k in ("confirmed", "benign", "unsure")),
            "unparseable": m.get("unparseable", 0), "p50_ms": m.get("p50_ms"), "p95_ms": m.get("p95_ms"),
            "accuracy": judge["accuracy"],
        })
    return out


COMPARE_COLUMNS = ["db", "model", "calls", "by rule", "real kept", "real dismissed", "real unsure",
                   "benign seen", "benign heldout", "unparseable", "p50 ms", "p95 ms", "strict acc"]


def compare_rows(rows: list[dict]) -> list[tuple]:
    return [(
        r["db"], r["model"], r["model_calls"], r["by_rule"], r["real_kept"], r["real_dismissed"], r["real_unsure"],
        f"{r['seen_benign']}/{r['seen_n']}", f"{r['heldout_benign']}/{r['heldout_n']}", r["unparseable"],
        r["p50_ms"] if r["p50_ms"] is not None else "—", r["p95_ms"] if r["p95_ms"] is not None else "—",
        f"{r['accuracy']:.2f}" if r["accuracy"] is not None else "—",
    ) for r in rows]


Generate = Callable[[list[dict]], tuple[str, int, int]]  # messages -> (content, prompt_tokens, output_tokens)


def rss_mb() -> int | None:
    try:
        import resource

        return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // (1024 * 1024))  # macOS reports bytes
    except (ImportError, OSError):
        return None


class Student:
    """Base + adapter loaded once, on a dedicated thread that also runs every generation: MLX streams are
    bound to the thread that created them, and FastAPI serves sync endpoints from a worker pool."""

    def __init__(self, base_model: str, adapter_dir: Path | None, max_tokens: int = 200) -> None:
        self.max_tokens = max_tokens
        self._queue: queue.Queue[tuple[list[dict], Future]] = queue.Queue()
        self._ready = threading.Event()
        self._error: BaseException | None = None
        threading.Thread(target=self._run, args=(base_model, adapter_dir), daemon=True, name="student").start()
        self._ready.wait()
        if self._error is not None:
            raise self._error

    def _run(self, base_model: str, adapter_dir: Path | None) -> None:
        try:
            from mlx_lm import generate, load  # the `train` dependency group
            from mlx_lm.sample_utils import make_sampler

            loaded = load(base_model, adapter_path=str(adapter_dir) if adapter_dir else None)
            model, tokenizer = loaded[0], loaded[1]
            sampler = make_sampler(temp=0.0)
        except BaseException as e:  # surfaced to the constructor
            self._error = e
            self._ready.set()
            return
        self._ready.set()
        while True:
            messages, fut = self._queue.get()
            try:
                prompt = tokenizer.apply_chat_template(messages, add_generation_prompt=True, tokenize=False)
                text = generate(model, tokenizer, prompt=prompt, max_tokens=self.max_tokens, sampler=sampler, verbose=False)
                fut.set_result((text.strip(), len(tokenizer.encode(prompt)), len(tokenizer.encode(text))))
            except BaseException as e:  # handed to the caller, worker stays alive
                fut.set_exception(e)

    def __call__(self, messages: list[dict]) -> tuple[str, int, int]:
        fut: Future = Future()
        self._queue.put((messages, fut))
        return fut.result()


def create_student_app(
    generate: Generate, model_name: str = STUDENT_NAME, allowed_hosts: frozenset[str] | None = LOOPBACK_HOSTS
) -> FastAPI:
    """The subset of Ollama's HTTP API that OllamaClient uses, so the judge needs no new code path."""
    app = FastAPI(title="claudit-student", docs_url=None, redoc_url=None)
    calls = {"n": 0, "ms": 0}

    @app.middleware("http")
    async def host_guard(request: Request, call_next):
        host = request.headers.get("host", "").rsplit(":", 1)[0] if allowed_hosts is not None else ""
        if allowed_hosts is not None and host not in allowed_hosts:
            return JSONResponse({"detail": "forbidden host"}, status_code=403)
        return await call_next(request)

    @app.get("/api/version")
    def version() -> dict:
        return {"version": f"{model_name} (mlx-lm)", "calls": calls["n"], "ms": calls["ms"], "rss_mb": rss_mb()}

    @app.get("/api/tags")
    def tags() -> dict:
        return {"models": [{"name": model_name}]}

    @app.post("/api/chat")
    def chat(body: dict) -> JSONResponse:
        if body.get("model") != model_name:
            return JSONResponse({"error": f"model '{body.get('model')}' not found, try {model_name}"}, status_code=404)
        started = time.perf_counter()
        content, n_in, n_out = generate(body.get("messages", []))  # `format` (JSON schema) is not enforced
        elapsed_ns = int((time.perf_counter() - started) * 1e9)
        calls["n"] += 1
        calls["ms"] += elapsed_ns // 1_000_000
        return JSONResponse({
            "model": model_name, "message": {"role": "assistant", "content": content}, "done": True,
            "prompt_eval_count": n_in, "eval_count": n_out, "total_duration": elapsed_ns,
        })

    return app

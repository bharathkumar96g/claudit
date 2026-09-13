"""Operational history, health probes and latency metrics (Design 05). Nothing here carries content."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any

import duckdb

from .util import one, utc_now


def _plain(stats: Any) -> dict:
    if is_dataclass(stats) and not isinstance(stats, type):
        return asdict(stats)
    return dict(stats) if isinstance(stats, dict) else {"value": str(stats)}


def record_run(con: duckdb.DuckDBPyConnection, kind: str, started: datetime, duration_ms: int, stats: Any) -> str:
    run_id = uuid.uuid4().hex[:12]
    payload = _plain(stats)
    con.execute("INSERT INTO runs VALUES (?,?,?,?,?)", [run_id, kind, started, duration_ms, json.dumps(payload)])
    if os.environ.get("CLAUDIT_LOG") == "json":
        line = {"ts": started.isoformat(), "run": kind, "duration_ms": duration_ms, **payload}
        print(json.dumps(line, default=str), file=sys.stderr)
    return run_id


@contextmanager
def timed_run(con: duckdb.DuckDBPyConnection, kind: str, stats_holder: list):
    """Usage: with timed_run(con, "scan", holder): ...; holder.append(stats). Records even if the body raises."""
    started = utc_now()
    t0 = time.perf_counter()
    try:
        yield
    finally:
        duration = int((time.perf_counter() - t0) * 1000)
        record_run(con, kind, started, duration, stats_holder[0] if stats_holder else {"error": "no stats"})


def recent_runs(con: duckdb.DuckDBPyConnection, limit: int = 20) -> list[dict]:
    rows = con.execute(
        "SELECT run_id, kind, started_at, duration_ms, stats FROM runs ORDER BY started_at DESC LIMIT ?", [limit]
    ).fetchall()
    return [{"run_id": r, "kind": k, "started_at": s.isoformat(), "duration_ms": d, "stats": json.loads(st)}
            for r, k, s, d, st in rows]


def latency(con: duckdb.DuckDBPyConnection) -> dict:
    """p50/p95 per model call from what judgments and semantic scans already store."""
    judge = one(con, """
        SELECT count(*), quantile_cont(duration_ms, 0.5), quantile_cont(duration_ms, 0.95), avg(prompt_tokens)
        FROM judgments WHERE model <> 'rules' AND duration_ms > 0""")
    semantic = one(con, """
        SELECT count(*), quantile_cont(duration_ms, 0.5), quantile_cont(duration_ms, 0.95), avg(n_pieces)
        FROM semantic_scans WHERE model NOT IN ('unavailable') AND duration_ms > 0""")
    scans = one(con, "SELECT count(*), quantile_cont(duration_ms, 0.5), max(duration_ms) FROM runs WHERE kind = 'scan'")
    f = lambda v: None if v is None else round(float(v), 1)  # noqa: E731
    return {
        "judge_calls": {"n": judge[0], "p50_ms": f(judge[1]), "p95_ms": f(judge[2]), "avg_prompt_tokens": f(judge[3])},
        "semantic_segments": {"n": semantic[0], "p50_ms": f(semantic[1]), "p95_ms": f(semantic[2]), "avg_pieces": f(semantic[3])},
        "scans": {"n": scans[0], "p50_ms": f(scans[1]), "max_ms": f(scans[2])},
    }


def latency_by_model(con: duckdb.DuckDBPyConnection) -> list[dict]:
    """One row per judge model: volume, latency percentiles, verdict mix and how often its output was unparseable.
    This is the table the distilled-student comparison reads; 'rules' rows are routing, not a model."""
    rows = con.execute("""
        SELECT model, count(*), quantile_cont(duration_ms, 0.5), quantile_cont(duration_ms, 0.95), avg(prompt_tokens),
               sum(CASE WHEN verdict = 'confirmed' THEN 1 ELSE 0 END), sum(CASE WHEN verdict = 'benign' THEN 1 ELSE 0 END),
               sum(CASE WHEN verdict = 'unsure' THEN 1 ELSE 0 END),
               sum(CASE WHEN reason = 'model returned unparseable output' THEN 1 ELSE 0 END)
        FROM judgments WHERE model <> 'rules' AND verdict <> 'unavailable' GROUP BY model ORDER BY count(*) DESC""").fetchall()
    f = lambda v: None if v is None else round(float(v), 1)  # noqa: E731
    return [
        {"model": m, "n": int(n), "p50_ms": f(p50), "p95_ms": f(p95), "avg_prompt_tokens": f(tok),
         "confirmed": int(c), "benign": int(b), "unsure": int(u), "unparseable": int(bad)}
        for m, n, p50, p95, tok, c, b, u, bad in rows
    ]


def probe_http(url: str, timeout: float = 2.0) -> dict:
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 # nosec B310
            body = r.read(20_000).decode("utf-8", errors="replace")
        return {"ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1), "body": body}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"ok": False, "ms": round((time.perf_counter() - t0) * 1000, 1), "error": str(e)[:120]}


def health(con: duckdb.DuckDBPyConnection, ollama_url: str, guard_port: int) -> dict:
    db_ok = True
    try:
        one(con, "SELECT 1")
    except duckdb.Error:
        db_ok = False
    ollama = probe_http(f"{ollama_url.rstrip('/')}/api/version")
    guard = probe_http(f"http://127.0.0.1:{guard_port}/guard/status")
    guard_status = None
    if guard["ok"]:
        try:
            guard_status = json.loads(guard.pop("body"))
        except json.JSONDecodeError:
            guard_status = None
    ollama.pop("body", None)
    return {"db": {"ok": db_ok}, "ollama": ollama, "guard": {**guard, "status": guard_status}}

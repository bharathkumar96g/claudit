"""Local web UI over the same DuckDB file. Binds to localhost by default; raw values are never served."""

from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .db import connect, truncate_all
from .ingest import ScanStats, scan_dir
from .judge import adjudicate, semantic_scan
from .ollama import OllamaClient, OllamaError
from .report import evaluate_data
from .synth import generate

WEB_DIR = Path(__file__).parent / "web"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
CSRF_HEADER = ("x-requested-with", "claudit")


@dataclass
class Job:
    id: str
    kind: str
    status: str = "running"
    log: list[str] = field(default_factory=list)
    result: dict | None = None
    error: str | None = None


def _iso(v: object) -> str | None:
    return v.isoformat() if isinstance(v, datetime) else None


def _host_only(header: str) -> str:
    if header.startswith("["):
        return header.split("]")[0] + "]"
    return header.rsplit(":", 1)[0] if ":" in header else header


def create_app(
    db_path: Path,
    transcripts_dir: Path,
    eval_dir: Path | None,
    ollama_url: str,
    model: str,
    demo: bool,
    allowed_hosts: frozenset[str] | None = LOOPBACK_HOSTS,
) -> FastAPI:
    con = connect(db_path)
    lock = threading.Lock()
    jobs: dict[str, Job] = {}
    app = FastAPI(title="claudit", docs_url=None, redoc_url=None)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # A page in your browser can POST to localhost without your consent; a custom header stops that.
        if allowed_hosts is not None and _host_only(request.headers.get("host", "")) not in allowed_hosts:
            return JSONResponse({"detail": "forbidden host"}, status_code=403)
        if request.method == "POST" and request.headers.get(CSRF_HEADER[0]) != CSRF_HEADER[1]:
            return JSONResponse({"detail": "missing X-Requested-With: claudit"}, status_code=403)
        return await call_next(request)

    @app.get("/")
    def index():
        return FileResponse(WEB_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/api/summary")
    def summary():
        with lock:
            events, segments, sessions, projects, findings = con.execute(
                "SELECT (SELECT count(*) FROM events), (SELECT count(*) FROM segments),"
                " (SELECT count(DISTINCT session_id) FROM events), (SELECT count(DISTINCT project) FROM events),"
                " (SELECT count(*) FROM findings)"
            ).fetchone()
            last_scan = con.execute("SELECT max(updated_at) FROM checkpoints").fetchone()[0]
            judged = con.execute("SELECT count(*) FROM judgments").fetchone()[0]
            semantic = [
                {"ts": _iso(ts), "kind": k, "severity": s, "summary": sm, "source": src, "project": p}
                for ts, k, s, sm, src, p in con.execute(
                    "SELECT ts, kind, severity, summary, source, project FROM semantic_findings"
                    " ORDER BY ts DESC NULLS LAST LIMIT 100"
                ).fetchall()
            ]
            evaluation = None
            if eval_dir and (eval_dir / "labels.json").is_file():
                evaluation = evaluate_data(con, eval_dir)
        return {
            "db": str(db_path),
            "transcripts_dir": str(transcripts_dir),
            "demo": demo,
            "model": model,
            "totals": {"events": events, "segments": segments, "sessions": sessions,
                       "projects": projects, "findings": findings, "judged": judged},
            "last_scan": _iso(last_scan),
            "semantic": semantic,
            "evaluation": evaluation,
        }

    @app.get("/api/findings")
    def findings():
        with lock:
            rows = con.execute(
                "SELECT f.finding_id, f.ts, f.severity, f.category, f.preview, f.source, f.project,"
                " f.session_id, s.path, j.verdict, j.model, j.reason"
                " FROM findings f JOIN segments s ON s.segment_id = f.segment_id"
                " LEFT JOIN judgments j ON j.finding_id = f.finding_id"
                " ORDER BY f.ts DESC NULLS LAST"
            ).fetchall()
        return [
            {"id": fid, "ts": _iso(ts), "severity": sev, "category": cat, "preview": prev, "source": src,
             "project": proj, "session": sid, "path": path, "verdict": verdict, "judged_by": jmodel, "reason": reason}
            for fid, ts, sev, cat, prev, src, proj, sid, path, verdict, jmodel, reason in rows
        ]

    @app.post("/api/scan")
    def scan():
        if not transcripts_dir.is_dir():
            raise HTTPException(400, f"no such directory: {transcripts_dir}")
        stats = ScanStats()
        with lock:
            scan_dir(con, transcripts_dir, stats)
        return asdict(stats)

    @app.post("/api/synth")
    def synth(sessions: int = 24, seed: int = 42):
        if not demo or eval_dir is None:
            raise HTTPException(403, "only available in demo mode")
        manifest = generate(eval_dir, sessions, seed)
        stats = ScanStats()
        with lock:
            truncate_all(con)
            scan_dir(con, transcripts_dir, stats)
        return {"sessions": len(manifest["sessions"]), "plants": len(manifest["plants"]), "scan": asdict(stats)}

    @app.post("/api/judge")
    def judge(semantic: bool = False, rejudge: bool = False):
        if any(j.status == "running" and j.kind == "judge" for j in jobs.values()):
            raise HTTPException(409, "a judge run is already in progress")
        job = Job(id=uuid.uuid4().hex[:8], kind="judge")
        jobs[job.id] = job

        def run() -> None:
            cur = con.cursor()
            try:
                client = OllamaClient(ollama_url)
                version = client.version()
                names = client.models()
                if model not in names and f"{model}:latest" not in names:
                    raise OllamaError(f"model {model} not installed in Ollama (have: {', '.join(names) or 'none'})")
                job.log.append(f"Ollama {version}, model {model}")
                if rejudge:
                    cur.execute("DELETE FROM judgments")
                stats = adjudicate(
                    cur, client, model,
                    on_result=lambda cat, prev, verdict, reason: job.log.append(f"{verdict:11} {cat:22} {prev}"),
                )
                result = {"judge": asdict(stats)}
                if semantic:
                    job.log.append("scanning prompts for pattern-less sensitive content")
                    sstats = semantic_scan(
                        cur, client, model,
                        on_result=lambda source, n: job.log.append(f"semantic {source}: {n} finding(s)") if n else None,
                    )
                    result["semantic"] = asdict(sstats)
                job.result = result
                job.status = "done"
            except Exception as e:  # surfaced to the UI, never swallowed
                job.error = str(e)
                job.status = "error"
            finally:
                cur.close()

        threading.Thread(target=run, daemon=True).start()
        return {"job": job.id}

    @app.get("/api/jobs/{job_id}")
    def job_status(job_id: str):
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "no such job")
        return asdict(job)

    return app


def serve(app: FastAPI, host: str, port: int) -> None:
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="warning")

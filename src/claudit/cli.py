from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .db import connect, truncate_all
from .ingest import ScanStats, scan_dir
from .judge import adjudicate, semantic_scan
from .ollama import DEFAULT_BASE_URL, DEFAULT_MODEL, OllamaClient, OllamaUnavailable
from .report import _table, evaluate, summary
from .reveal import reveal_finding
from .synth import generate


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="claudit",
        description="Local-first audit of what you've shared with Claude. Stores fingerprints, never raw values.",
    )
    p.add_argument("--version", action="version", version=f"claudit {__version__}")
    p.add_argument("--db", help="DuckDB path (default: CLAUDIT_DB_PATH or data/claudit.duckdb)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("synth", help="generate synthetic transcripts with labeled planted secrets")
    s.add_argument("--out", default="data/synthetic")
    s.add_argument("--sessions", type=int, default=24)
    s.add_argument("--seed", type=int, default=42)

    s = sub.add_parser("scan", help="ingest new transcript lines and detect secrets (incremental)")
    s.add_argument("--dir", help="transcripts dir (default: CLAUDIT_TRANSCRIPTS_DIR or ~/.claude/projects)")
    s.add_argument("--full", action="store_true", help="drop everything and rescan from the start")

    s = sub.add_parser("judge", help="review findings with a local Ollama model (nothing leaves the machine)")
    s.add_argument("--model", default=DEFAULT_MODEL)
    s.add_argument("--base-url", default=DEFAULT_BASE_URL)
    s.add_argument("--limit", type=int, default=200, help="max findings to review this run")
    s.add_argument("--rejudge", action="store_true", help="discard previous verdicts and review everything again")
    s.add_argument("--semantic", action="store_true", help="also scan prompts for sensitive content with no pattern")
    s.add_argument("--semantic-limit", type=int, default=100)

    s = sub.add_parser("report", help="print findings summary")
    s.add_argument("--eval", metavar="DIR", help="synthetic dir with labels.json; prints precision/recall")

    s = sub.add_parser("findings", help="list findings with their ids")
    s.add_argument("--limit", type=int, default=50)

    s = sub.add_parser("reveal", help="print a finding's raw value from the source transcript (local only)")
    s.add_argument("finding_id")

    sub.add_parser("reset", help="delete all ingested data and checkpoints")
    return p


def _cmd_judge(con, args) -> int:
    client = OllamaClient(args.base_url)
    try:
        version = client.version()
        models = client.models()
    except OllamaUnavailable as e:
        print(e)
        return 1
    if args.model not in models and f"{args.model}:latest" not in models:
        have = ", ".join(models) or "none"
        print(f"model {args.model} not found in Ollama (installed: {have}). Run: ollama pull {args.model}")
        return 1
    print(f"Ollama {version}, model {args.model}\n")

    if args.rejudge:
        con.execute("DELETE FROM judgments")
    print("Reviewing flagged findings")
    stats = adjudicate(
        con, client, args.model, args.limit,
        on_result=lambda cat, prev, verdict, reason: print(f"  {verdict:11} {cat:22} {prev:20} {reason[:60]}"),
    )
    print(
        f"judged {stats.judged}   confirmed {stats.confirmed}   benign {stats.benign}   unsure {stats.unsure}"
        f"   unavailable {stats.unavailable}   tokens in/out {stats.prompt_tokens}/{stats.output_tokens}"
        f"   {stats.duration_ms / 1000:.1f}s model time"
    )

    if args.semantic:
        print("\nScanning prompts for sensitive content without a pattern")
        sstats = semantic_scan(
            con, client, args.model, args.semantic_limit,
            on_result=lambda source, n: print(f"  {source:12} {n} finding(s)") if n else None,
        )
        print(
            f"scanned {sstats.scanned} segments   findings {sstats.findings}"
            f"   tokens in/out {sstats.prompt_tokens}/{sstats.output_tokens}   {sstats.duration_ms / 1000:.1f}s model time"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(line_buffering=True)
    args = build_parser().parse_args(argv)
    cfg = load_config()
    db_path = Path(args.db).expanduser() if args.db else cfg.db_path

    if args.cmd == "synth":
        manifest = generate(Path(args.out), args.sessions, args.seed)
        benign = sum(1 for p in manifest["plants"] if p["expected_verdict"] == "benign")
        print(
            f"wrote {len(manifest['sessions'])} sessions with {len(manifest['plants'])} planted secrets"
            f" ({benign} benign-in-context) to {args.out}"
        )
        print(f"labels: {Path(args.out) / 'labels.json'}")
        return 0

    con = connect(db_path)
    if args.cmd == "reset":
        truncate_all(con)
        print(f"cleared {db_path}")
        return 0

    if args.cmd == "scan":
        root = Path(args.dir).expanduser() if args.dir else cfg.transcripts_dir
        if not root.is_dir():
            print(f"no such directory: {root}")
            return 1
        if args.full:
            truncate_all(con)
        stats = ScanStats()
        scan_dir(con, root, stats)
        print(
            f"scanned {root}\n"
            f"files {stats.files}   new lines {stats.lines}   events {stats.events}   "
            f"segments {stats.segments}   findings {stats.findings}   invalid lines {stats.invalid}"
        )
        if stats.lines == 0:
            print("nothing new since last scan")
        return 0

    if args.cmd == "judge":
        return _cmd_judge(con, args)

    if args.cmd == "report":
        print(summary(con))
        if args.eval:
            print("\n" + evaluate(con, Path(args.eval).expanduser()))
        return 0

    if args.cmd == "findings":
        rows = con.execute(
            "SELECT f.finding_id, f.severity, f.category, f.preview, f.source, coalesce(j.verdict, ''), f.project"
            " FROM findings f LEFT JOIN judgments j ON j.finding_id = f.finding_id"
            " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,"
            " f.ts DESC LIMIT ?",
            [args.limit],
        ).fetchall()
        print(_table(["finding_id", "severity", "category", "preview", "source", "verdict", "project"], rows))
        return 0

    if args.cmd == "reveal":
        result = reveal_finding(con, args.finding_id)
        if result is None:
            print("not found, or the source transcript changed since ingest")
            return 1
        value, excerpt = result
        print("Raw value re-read from the source transcript. Not stored anywhere.\n")
        print(excerpt)
        return 0

    return 1

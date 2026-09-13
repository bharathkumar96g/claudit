from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .db import connect, truncate_all
from .ingest import ScanStats, scan_dir
from .judge import adjudicate, semantic_scan
from .ollama import DEFAULT_BASE_URL, DEFAULT_EMBED_MODEL, DEFAULT_MODEL, OllamaClient, OllamaUnavailableError
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
    s.add_argument("--rag", action="store_true", help="show the model similar past cases from the example memory")
    s.add_argument("--embed-model", default=DEFAULT_EMBED_MODEL)
    s.add_argument("--semantic", action="store_true", help="also scan prompts and files for sensitive content with no pattern")
    s.add_argument("--semantic-only", action="store_true", help="run only the semantic scan, skip reviewing findings")
    s.add_argument("--semantic-limit", type=int, default=100)

    s = sub.add_parser("report", help="print findings summary")
    s.add_argument("--eval", metavar="DIR", help="synthetic dir with labels.json; prints precision/recall")

    s = sub.add_parser("findings", help="list findings with their ids")
    s.add_argument("--limit", type=int, default=50)

    s = sub.add_parser("reveal", help="print a finding's raw value from the source transcript (local only)")
    s.add_argument("finding_id")
    s.add_argument("--force", action="store_true", help="allow even inside a Claude Code session")

    s = sub.add_parser("eval", help="detection eval against a synthetic dir; non-zero exit if below thresholds (CI gate)")
    s.add_argument("dir")
    s.add_argument("--min-f1", type=float, default=1.0)
    s.add_argument("--max-fp", type=int, default=0)

    s = sub.add_parser("serve", help="run the local web UI (binds to localhost)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--dir", help="transcripts dir to scan from the UI (default: CLAUDIT_TRANSCRIPTS_DIR)")
    s.add_argument("--eval", metavar="DIR", help="synthetic dir with labels.json; shows the evaluation panel")
    s.add_argument("--demo", action="store_true", help="demo mode: scan the synthetic dir and allow regenerating it")
    s.add_argument("--model", default=DEFAULT_MODEL)
    s.add_argument("--base-url", default=DEFAULT_BASE_URL)

    s = sub.add_parser("secrets", help="the checklist: one row per secret with exposure and what to do about it")
    s.add_argument("--state", choices=["open", "rotated", "dismissed", "all"], default="open")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("mark", nargs="?", help="use: secrets mark <fingerprint-prefix> <open|rotated|dismissed>")
    s.add_argument("prefix", nargs="?")
    s.add_argument("new_state", nargs="?", choices=["open", "rotated", "dismissed"])
    s.add_argument("--note")

    s = sub.add_parser("guard", help="local masking gateway between Claude Code and the model provider")
    s.add_argument("action", nargs="?", choices=["run", "status"], default="run")
    s.add_argument("--port", type=int, default=8787)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--upstream", default="https://api.anthropic.com")

    s = sub.add_parser("memory", help="example memory for retrieval-augmented judging")
    s.add_argument("action", choices=["build", "add-verdicts", "stats"])
    s.add_argument("--from", dest="from_dir", default="data/synthetic", help="synthetic dir with labels.json (build)")
    s.add_argument("--embed-model", default=DEFAULT_EMBED_MODEL)
    s.add_argument("--base-url", default=DEFAULT_BASE_URL)

    s = sub.add_parser("adversarial", help="prompt-injection robustness check for the judge (needs Ollama)")
    s.add_argument("--n", type=int, default=24, help="cases; half controls, half injections")
    s.add_argument("--seed", type=int, default=11)
    s.add_argument("--model", default=DEFAULT_MODEL)
    s.add_argument("--base-url", default=DEFAULT_BASE_URL)

    s = sub.add_parser("rules", help="list the detection rules")
    s.add_argument("--all", action="store_true", help="list every rule id, not just the counts")

    sub.add_parser("reset", help="delete all ingested data and checkpoints")
    return p


def _cmd_rules(args) -> int:
    from collections import Counter

    from .detect import GITLEAKS_FAILED, RULES

    by_source = Counter(r.source for r in RULES)
    by_sev = Counter(r.severity for r in RULES)
    print(f"{len(RULES)} rules   " + "   ".join(f"{k} {v}" for k, v in by_source.items()))
    print("by severity   " + "   ".join(f"{k} {by_sev[k]}" for k in ("critical", "high", "medium", "low")))
    if GITLEAKS_FAILED:
        print(f"could not load {len(GITLEAKS_FAILED)} gitleaks rules: {', '.join(GITLEAKS_FAILED)}")
    if args.all:
        for r in sorted(RULES, key=lambda r: (r.source, r.category)):
            print(f"  {r.source:9} {r.severity:8} {r.category}")
    return 0


def _cmd_judge(con, args) -> int:
    client = OllamaClient(args.base_url)
    try:
        version = client.version()
        models = client.models()
    except OllamaUnavailableError as e:
        print(e)
        return 1
    if args.model not in models and f"{args.model}:latest" not in models:
        have = ", ".join(models) or "none"
        print(f"model {args.model} not found in Ollama (installed: {have}). Run: ollama pull {args.model}")
        return 1
    print(f"Ollama {version}, model {args.model}\n")

    retriever = None
    if args.rag:
        from . import memory

        def retriever(excerpt: str, category: str, session_id: str | None, fingerprint: str) -> str:
            return memory.render_examples(
                memory.retrieve(con, client, args.embed_model, excerpt, category, session_id, fingerprint)
            )

    if args.rejudge:
        con.execute("DELETE FROM judgments")
    if not args.semantic_only:
        print("Reviewing flagged findings" + (" with retrieved examples" if args.rag else ""))
        stats = adjudicate(
            con, client, args.model, args.limit,
            on_result=lambda cat, prev, verdict, reason: print(f"  {verdict:11} {cat:22} {prev:20} {reason[:60]}"),
            retriever=retriever,
        )
        print(
            f"model-judged {stats.judged}   confirmed-by-rule {stats.routed}   confirmed {stats.confirmed}"
            f"   benign {stats.benign}   unsure {stats.unsure}   unavailable {stats.unavailable}"
            + (f"   with examples {stats.with_examples}" if args.rag else "")
            + f"   tokens in/out {stats.prompt_tokens}/{stats.output_tokens}   {stats.duration_ms / 1000:.1f}s model time"
        )

    if args.semantic or args.semantic_only:
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
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr]
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

    if args.cmd == "rules":
        return _cmd_rules(args)

    if args.cmd == "adversarial":
        from .adversarial import run
        from .judge import JUDGE_PROMPT_VERSION

        client = OllamaClient(args.base_url)
        try:
            client.version()
        except OllamaUnavailableError as e:
            print(e)
            return 1
        res = run(client, args.model, args.n, args.seed)
        print(f"prompt v{JUDGE_PROMPT_VERSION}, model {args.model}, {args.n} cases, {res.instructions_removed} instruction lines removed")
        print(f"controls  confirmed {res.control_confirmed}/{res.n_control}")
        print(f"attacks   dismissed (benign) {res.dismissed}/{res.n_attacks}   degraded (unsure) {res.degraded}/{res.n_attacks}"
              f"   dismissal rate {res.dismissal_rate:.2f}")
        for verdict, injection, category, reason in res.examples:
            print(f"  {verdict.upper():9} {category:20} by: {injection[:70]}\n            reason: {reason}")
        return 0

    if args.cmd == "guard":
        import urllib.request

        from .guard.proxy import LOOPBACK_HOSTS as GUARD_LOOPBACK
        from .guard.proxy import create_guard_app, env_hint

        if args.action == "status":
            try:
                # fixed loopback URL, so B310 (arbitrary scheme) does not apply
                with urllib.request.urlopen(f"http://127.0.0.1:{args.port}/guard/status", timeout=5) as r:  # nosec B310
                    print(r.read().decode())
            except OSError as e:
                print(f"guard not reachable on port {args.port}: {e}")
                return 1
            return 0
        if not args.upstream.startswith("https://"):
            print("refusing: upstream must be https")
            return 1
        allowed = GUARD_LOOPBACK if args.host in ("127.0.0.1", "localhost", "::1") else None
        app = create_guard_app(args.upstream, allowed_hosts=allowed)
        print(f"claudit guard listening on http://{args.host}:{args.port} -> {args.upstream}")
        print("masking: vendor-format keys, private keys, connection-string passwords. No bodies are logged.\n")
        print(env_hint(args.port))
        from .server import serve

        serve(app, args.host, args.port)
        return 0

    if args.cmd == "serve":
        from .server import create_app, serve

        eval_dir = Path(args.eval).expanduser() if args.eval else (Path("data/synthetic") if args.demo else None)
        transcripts = Path(args.dir).expanduser() if args.dir else ((eval_dir if args.demo else None) or cfg.transcripts_dir)
        from .server import LOOPBACK_HOSTS

        allowed = LOOPBACK_HOSTS if args.host in ("127.0.0.1", "localhost", "::1") else None
        app = create_app(db_path, transcripts, eval_dir, args.base_url, args.model, demo=args.demo, allowed_hosts=allowed)
        print(f"claudit UI at http://{args.host}:{args.port}  (db {db_path}, scanning {transcripts})")
        serve(app, args.host, args.port)
        return 0

    con = connect(db_path)

    if args.cmd == "memory":
        from . import memory

        if args.action == "stats":
            mrows = memory.stats(con)
            print(_table(["origin", "verdict", "examples"], mrows) if mrows else "memory is empty")
            return 0
        client = OllamaClient(args.base_url)
        try:
            client.version()
        except OllamaUnavailableError as e:
            print(e)
            return 1
        if args.action == "build":
            n = memory.build_from_labels(con, client, args.embed_model, Path(args.from_dir).expanduser())
            print(f"embedded {n} labeled examples from {args.from_dir} (held-out plants excluded)")
        else:
            n = memory.add_verdicts(con, client, args.embed_model)
            print(f"embedded {n} examples from rotated/dismissed secrets")
        return 0

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
            + (f"   already seen {stats.duplicates}" if stats.duplicates else "")
            + (f"   reused identical chunks {stats.reused}" if stats.reused else "")
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

    if args.cmd == "secrets":
        from .secrets import list_secrets, set_state

        if args.mark:
            if args.mark != "mark" or not args.prefix or not args.new_state:
                print("usage: claudit secrets mark <fingerprint-prefix> <open|rotated|dismissed> [--note ...]")
                return 2
            try:
                fp = set_state(con, args.prefix, args.new_state, args.note)
            except (LookupError, ValueError) as e:
                print(e)
                return 1
            print(f"{fp[:12]}… marked {args.new_state}")
            return 0
        secrets_rows = list_secrets(con, None if args.state == "all" else args.state, args.limit)
        if not secrets_rows:
            print(f"no {args.state} secrets")
            return 0
        print(_table(
            ["fingerprint", "sev", "category", "preview", "verdict", "sessions", "first seen", "last seen", "state"],
            [(s["fingerprint"][:12], s["severity"], s["category"], s["preview"][:24], s["verdict"], s["sessions"],
              (s["first_seen"] or "")[:10], (s["last_seen"] or "")[:10], s["state"]) for s in secrets_rows],
        ))
        print("\nwhat to do (top 5):")
        for s in secrets_rows[:5]:
            print(f"  {s['fingerprint'][:12]}  {s['category']}: {s['rotation']}")
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
        if os.environ.get("CLAUDECODE") and not args.force:
            print(
                "refusing: this shell is inside a Claude Code session, so the revealed value would be written"
                " into a new transcript. Run it from a plain terminal, or pass --force."
            )
            return 1
        result = reveal_finding(con, args.finding_id)
        if result is None:
            print("not found, or the source transcript changed since ingest")
            return 1
        _value, excerpt = result
        print("Raw value re-read from the source transcript. Not stored anywhere.\n")
        print(excerpt)
        return 0

    if args.cmd == "eval":
        from .report import evaluate_data

        d = evaluate_data(con, Path(args.dir).expanduser())
        o = d["overall"]
        print(f"detection  tp {o['tp']}  fp {o['fp']}  fn {o['fn']}  precision {o['precision']:.3f}  recall {o['recall']:.3f}  f1 {o['f1']:.3f}")
        ok = o["f1"] >= args.min_f1 and o["fp"] <= args.max_fp
        print("gate:", "PASS" if ok else f"FAIL (need f1 >= {args.min_f1}, fp <= {args.max_fp})")
        return 0 if ok else 1

    return 1

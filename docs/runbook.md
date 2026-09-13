# Runbook

Everything runs on one machine; there is nothing to page. This is what each piece looks like when it's
working, what it looks like when it isn't, and what to do.

## Start / stop

| piece | start | stop | check |
|---|---|---|---|
| dashboard | `uv run claudit --db data/real.duckdb serve` | Ctrl-C | http://127.0.0.1:8765 · `/api/health` |
| guard | `uv run claudit guard` | Ctrl-C (mapping is zeroed on exit) | `uv run claudit guard status` |
| Ollama | Ollama.app (menu bar) | quit the app | `curl localhost:11434/api/version` |
| one-off | `uv run claudit ops` prints health, latency percentiles and recent runs | | |

## Things that break, and what they look like

**"Could not set lock on file … real.duckdb"** — DuckDB is single-writer. The dashboard holds the file while it
runs. Use the UI's Scan/Judge buttons, or stop the server before CLI commands on the same `--db`.

**Judge says "cannot reach Ollama"** — the Ollama app isn't running. Start it; the judge resumes where it left
off (verdicts are stored per finding as they complete).

**Judge says "model … not installed"** — `ollama pull qwen2.5:7b` (4.7 GB). Same for `nomic-embed-text`
if you use `--rag` or `memory build`.

**Judge is slow** — expected: ~5–10 s per model call on an M4 for a 7B model. Routing keeps most vendor-format
findings away from the model; `claudit ops` shows p50/p95. Nothing to fix unless p95 climbs into minutes,
which means the Mac is swapping — close other memory-heavy apps.

**A scan says "already seen N"** — normal. Resumed sessions copy history into new files; those events are
skipped before scanning.

**The database was rebuilt on start** — normal after an upgrade that bumps `SCHEMA_VERSION`. Everything except
`secret_state` (your rotate/dismiss decisions) is derived from transcripts and comes back on the next scan.

**A finding says "unavailable"** — the transcript line changed or the file was deleted since ingest, so the
value can't be re-read for judging. The fingerprint stays; nothing else can be done for it.

**Guard: a session errors with `claudit_guard_blocked_write`** — the model altered a pseudonym inside a file
write and the guard refused to let a placeholder be saved. Re-run the request. `guard status` counts it. If
it recurs for the same value, that class of value is being mangled by the model; report it with the category
(never the value).

**Guard: Claude Code asks you to log in** — `ANTHROPIC_BASE_URL` is set but the guard isn't running, or you set a
credential variable that overrides the claude.ai login. Start the guard, or `unset ANTHROPIC_BASE_URL`.

**Guard: 502 with `claudit_guard_upstream`** — the guard couldn't reach api.anthropic.com. Network, not the
guard; the error message carries the httpx reason.

**Dashboard shows "forbidden host" / 403 on a POST** — you are reaching the server through a hostname that isn't
loopback, or a page in your browser tried to POST to it. Both are refused on purpose.

## Where things live

- transcripts: `~/.claude/projects/<project>/<session>.jsonl` (Claude Code's own files; read-only for claudit)
- databases: `data/*.duckdb` (gitignored); `secret_state` is the only table you author
- models: `~/.ollama/models`
- logs: none by default; `CLAUDIT_LOG=json` prints one JSON line per run to stderr (counts only, never content)

## Never

- Never point the guard at a non-https upstream (the CLI refuses).
- Never run `claudit reveal` inside a Claude Code session (the CLI refuses; `--force` exists for a plain terminal).
- Never commit `data/`. CI runs gitleaks on the repository itself.

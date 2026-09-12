# claudit

Local-first audit of what you've shared with Claude.

Claude Code writes every session to disk as JSONL. `claudit` ingests those transcripts, detects secrets and PII in what you typed and in what Claude read on your behalf, has a local model judge the ambiguous cases, and reports where things showed up — without ever writing a raw secret to disk or sending one off the machine.

## Privacy design

The dataset for this tool is, by definition, your most sensitive data. So the safe design is structural, not a setting:

- **Detection runs in the ingest path**, before anything is persisted. Segments are stored already redacted.
- **Findings store a SHA-256 fingerprint and a masked preview** (`sk-a…7f`), never the value. You can still see that the same key leaked in four sessions; you can't read it out of the database.
- **The model layer is local.** It talks to an Ollama server on `localhost`; no API keys, no cloud, no telemetry. When it needs a raw value for context it re-reads the source transcript on demand and verifies the hash, and its written reasons are scrubbed of the value and of any 8+ character fragment of it.
- **The demo runs on synthetic data.** `claudit synth` generates transcripts with planted, labeled fake secrets. That's the test fixture, the eval set, and the only thing that ever gets published.

## Quickstart

Requires [uv](https://docs.astral.sh/uv/). The model layer additionally needs [Ollama](https://ollama.com) running with a model pulled (`ollama pull qwen2.5:7b`, 4.7 GB).

```bash
uv sync
uv run claudit synth                      # 24 fake sessions with planted secrets -> data/synthetic
uv run claudit scan --dir data/synthetic  # ingest + detect, checkpointed
uv run claudit judge                      # local model reviews each finding in context
uv run claudit report --eval data/synthetic
```

Against your real transcripts:

```bash
uv run claudit scan       # reads ~/.claude/projects, only new lines since last run
uv run claudit judge --semantic
uv run claudit report
uv run claudit findings   # ids, for `claudit reveal <id>`
```

Set `CLAUDIT_TRANSCRIPTS_DIR` / `CLAUDIT_DB_PATH` in `.env` (see `.env.example`) or pass `--db`.

## Web UI

```bash
uv run claudit serve --demo                       # synthetic data, http://127.0.0.1:8765
uv run claudit --db data/real.duckdb serve       # your transcripts
```

A local, always-dark security-console dashboard over the same DuckDB file: an exposure hero with a segmented severity bar, findings by category / source and a per-day timeline, one filter row that scopes everything below it, a live feed of findings with the model's verdict and reason per row, the evaluation panel, and the model-found semantic findings. No build step, no external dependencies. **Scan now** ingests whatever's new and re-renders; **Run model judge** starts a background job and the verdict column fills in as each finding is reviewed. In demo mode, **Regenerate demo data** rebuilds the synthetic set and rescans.

The server binds to localhost, serves masked previews only, and has no endpoint for raw values — `claudit reveal` stays a CLI-only, on-demand read of the source transcript.

DuckDB allows one writer per database file, so while `claudit serve` is running use the UI's Scan and Judge buttons; stop the server before running CLI commands against the same `--db`.

## Layer 1: deterministic detection

235 rules: 17 written and tuned here, plus 218 vendor-token patterns imported from the [gitleaks](https://github.com/gitleaks/gitleaks) community rule set (MIT; vendored in `src/claudit/rules/` with its license and upstream commit). The importer maps each gitleaks rule's regex, entropy floor, keyword prefilter, and allowlists onto the same `Rule` type, repairs the two Go-regex idioms Python rejects (mid-pattern `(?i)`, `\z`), and skips the three rules claudit covers with tuned versions of its own. `claudit rules` lists them.

Every rule carries keywords; a rule's regex only runs when one of its keywords occurs in the chunk, so most chunks are dismissed by a substring check rather than 235 regex passes. Identical chunks (the same file read twice) are scanned once and their findings reused.

The hand-tuned rules:

| category | severity | how |
|---|---|---|
| private_key, connection_string, aws_secret_access_key | critical | pattern + context |
| anthropic / openai / github / slack / google / stripe keys, aws access key id, jwt | high | vendor prefix patterns |
| ssn, credit_card | high | pattern; cards Luhn-validated with issuer prefix |
| generic_secret (`password=`, `api_key:` ...) | medium | key/value pattern, placeholder and code-reference exclusions, entropy floor |
| high_entropy_string | medium | 32–128 chars, entropy ≥ 4.0, must mix letters and digits, hex/uuid/path excluded |
| email, phone | low | pattern; noreply/example domains allowlisted |

Overlapping matches resolve to the most specific rule, so `ANTHROPIC_API_KEY=sk-ant-…` is one finding, not three.

Every finding records its **source** — `user_prompt`, `tool_result`, `tool_input`, `assistant_text` — because "I pasted a password" and "Claude read a `.env` I pointed it at" are different problems.

## Layer 2: local-model judgment

Regex can say "this has the shape of a secret." It can't say whether it's real. The judgment layer does two things a pattern can't:

- **Adjudicate.** For each finding it re-reads the source line, wraps the value in ~400 chars of context, and asks the model: real secret, or a test fixture / `.env.example` / docs sample / throwaway local credential? Verdict, confidence, and a scrubbed reason are stored per finding. Reviews are incremental; `--rejudge` redoes them (after a prompt or model change).
- **Semantic scan** (`--semantic`). Reads already-redacted prompts and reports sensitive content with no pattern: customer or employee data, internal hostnames and architecture, proprietary logic, financial figures.

Cheap deterministic filter first, model only where judgment is needed; structured JSON output enforced by schema; temperature 0. Any Ollama model works: `--model llama3.1:8b`.

## How ingest works

- One row per JSONL line in `events`; one row per text chunk the model saw or produced in `segments`; one row per hit in `findings`; model verdicts in `judgments` and `semantic_findings`. DuckDB, single file.
- **Checkpointed by byte offset per file.** Reruns process only appended lines. A trailing partial line (Claude Code mid-write) is left for the next run.
- Inserts are idempotent on content-derived ids; each file commits in one transaction, so a crash mid-file replays cleanly.
- Events whose ids are already stored are skipped before any text is extracted or scanned.
- **One file is one session.** Lines with no `sessionId` (session start, snapshots) take the session from the filename. The project is the directory the session was launched in — resolved once per file from the first `cwd` and remembered in the checkpoint, so a session that `cd`s around stays one project; per-event `cwd` is kept separately.
- Events are keyed by the transcript's message `uuid`. A resumed Claude Code session copies earlier history into its new file, so the same message can appear in several files; files are scanned oldest-first and a message is counted once, in the session it first appeared in. The scan reports these as "already seen".

## Evaluation

`report --eval` matches findings to the planted labels by `(session, category, fingerprint)` and prints precision / recall / F1 per category, with false positives and misses listed. Sessions carry decoys — git SHAs, UUIDs, `API_KEY=your_api_key_here`, `password = os.environ[...]`, epoch timestamps — to keep precision honest. Some plants are deliberately placed in benign contexts (a fake token in a unit test, a sample key in `.env.example`, an example in docs) with `expected_verdict: benign`, so the model layer is scored too.

Current numbers on the default synthetic set (24 sessions, 31 plants across 27 categories including ten imported vendor formats), `qwen2.5:7b` on an M4:

- Deterministic layer: 31/31 found, 0 false positives, 1.00 F1 in every category. On real transcripts (1,247 chunks) the 218 imported rules produced no false positives.
- Model layer, same 31 findings, ~4 min of model time per full pass:

| adjudication prompt | real secrets kept | benign-in-context recognized | accuracy |
|---|---|---|---|
| v1 — format-focused | 27/27 | 1/4 | 0.90 |
| v2 — context-focused | 15/27 | 4/4 | 0.61 |
| v3 — default real, benign only on an explicit marker (current) | 24/27 (+2 unsure) | 2/4 | 0.84 |

v1 rubber-stamps the regex; v2 treats "the conversation is about something else" as evidence the secret is fake and dismisses 12 real ones. v3 states the default explicitly and lands between them: one real secret dismissed, two flagged unsure, half the benign contexts recognized. A 7B model follows whichever way the prompt leans, so the remaining gap is a model-size question as much as a prompt one — the same eval on a larger model is the next experiment.

The eval has already paid for itself: it caught a bug where JSON-escaping tool inputs broke multi-line matches *and* leaked a full private key into the preview column, and a second one where a model's reason repeated the password portion of a connection string.

## Roadmap

- **dbt models + Dagster orchestration** on top of the same DuckDB file, so the marts are declared, tested, and scheduled.
- **Model comparison**: the same eval across two or three local models — accuracy, latency per call, memory.
- **More sources**: claude.ai data export; local logs from self-hosted agents (OpenClaw, Hermes).
- **Prompt-quality scoring**: friction signals already in the transcripts (turns to resolution, correction phrases, interruptions, rework) to find sessions that went badly, then have the local model explain why and rewrite the opening prompt.
- **Semantic search** over redacted history with a local embedding model and DuckDB `vss`.
- **File watcher** for near-real-time scanning; dashboard; static synthetic-data demo.

## Layout

```
src/claudit/
  detect.py   rules, validators, overlap resolution, masking
  ingest.py   JSONL parsing, segment extraction, checkpointing
  judge.py    adjudication + semantic scan via local model
  ollama.py   minimal Ollama HTTP client
  reveal.py   re-read raw text from source transcripts, hash-verified
  synth.py    synthetic transcript + label generator
  report.py   summary, precision/recall, judgment accuracy
  server.py   FastAPI app: summary/findings/scan/judge endpoints
  web/        dashboard (no build step, no external dependencies)
  db.py       schema
  cli.py
tests/        includes a fake Ollama server (conftest.py)
```

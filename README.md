# claudit

Local-first audit of what you've shared with Claude.

Claude Code writes every session to disk as JSONL. `claudit` ingests those transcripts, detects secrets and PII in what you typed and in what Claude read on your behalf, and reports where they showed up — without ever writing a raw secret to disk.

## Privacy design

The dataset for this tool is, by definition, your most sensitive data. So the safe design is structural, not a setting:

- **Detection runs in the ingest path**, before anything is persisted. Segments are stored already redacted.
- **Findings store a SHA-256 fingerprint and a masked preview** (`sk-a…7f`), never the value. You can still see that the same key leaked in four sessions; you can't read it out of the database.
- **Nothing leaves the machine.** No API calls, no telemetry. The LLM judgment layer on the roadmap will use a local model for the same reason.
- **The demo runs on synthetic data.** `claudit synth` generates transcripts with planted, labeled fake secrets. That's the test fixture, the eval set, and the only thing that ever gets published.

## Quickstart

Requires [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run claudit synth                     # 24 fake sessions with planted secrets -> data/synthetic
uv run claudit scan --dir data/synthetic # ingest + detect, checkpointed
uv run claudit report --eval data/synthetic
```

Against your real transcripts:

```bash
uv run claudit scan          # reads ~/.claude/projects, only new lines since last run
uv run claudit report
```

Set `CLAUDIT_TRANSCRIPTS_DIR` / `CLAUDIT_DB_PATH` in `.env` (see `.env.example`) or pass `--db`.

## What it detects (v0)

Deterministic rules, tuned for precision:

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

## How ingest works

- One row per JSONL line in `events`; one row per text chunk the model saw or produced in `segments`; one row per hit in `findings`. DuckDB, single file.
- **Checkpointed by byte offset per file.** Reruns process only appended lines. A trailing partial line (Claude Code mid-write) is left for the next run.
- Inserts are idempotent on content-derived ids; each file commits in one transaction, so a crash mid-file replays cleanly.

## Evaluation

`report --eval` matches findings to the planted labels by `(session, category, fingerprint)` and prints precision / recall / F1 per category, with the false positives and misses listed. Synthetic sessions also carry decoys — git SHAs, UUIDs, `API_KEY=your_api_key_here`, `password = os.environ[...]`, epoch timestamps — to keep precision honest.

## Roadmap

- **LLM judgment layer** (local, via Ollama): adjudicate the medium-severity and entropy hits, and catch what regex can't — proprietary code, customer data in a pasted CSV, internal architecture.
- **Prompt-quality scoring**: friction signals already in the transcripts (turn count to resolution, correction phrases, interruptions, rework on the same file) to find sessions that went badly, then have the local model explain why and rewrite the opening prompt.
- **File watcher** for near-real-time scanning instead of cron.
- **dbt models + dashboard** on top of the same DuckDB file.
- **`--reveal`**: re-read a finding's raw value from the source transcript on demand, local only.

## Layout

```
src/claudit/
  detect.py   rules, validators, overlap resolution, masking
  ingest.py   JSONL parsing, segment extraction, checkpointing
  synth.py    synthetic transcript + label generator
  report.py   summary and precision/recall
  db.py       schema
  cli.py
tests/
```

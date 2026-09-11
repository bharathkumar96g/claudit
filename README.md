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

## Layer 1: deterministic detection

Rules tuned for precision:

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

## Evaluation

`report --eval` matches findings to the planted labels by `(session, category, fingerprint)` and prints precision / recall / F1 per category, with false positives and misses listed. Sessions carry decoys — git SHAs, UUIDs, `API_KEY=your_api_key_here`, `password = os.environ[...]`, epoch timestamps — to keep precision honest. Some plants are deliberately placed in benign contexts (a fake token in a unit test, a sample key in `.env.example`, an example in docs) with `expected_verdict: benign`, so the model layer is scored too.

Current numbers on the default synthetic set (24 sessions, 31 plants, 4 benign-in-context), `qwen2.5:7b` on an M4:

- Deterministic layer: 31/31 found, 0 false positives, 1.00 F1 across all 17 categories.
- Model layer, same 31 findings, ~4 min of model time per full pass:

| adjudication prompt | real secrets kept | benign-in-context recognized | accuracy |
|---|---|---|---|
| v1 — format-focused | 27/27 | 1/4 | 0.90 |
| v2 — context-focused | 15/27 | 4/4 | 0.61 |
| v3 — default real, benign only on an explicit marker | not yet measured | | |

The two prompts fail in opposite directions: v1 rubber-stamps the regex, v2 treats "the conversation is about something else" as evidence the secret is fake. A 7B model follows whichever way the prompt leans, so the prompt has to state the default explicitly. Next experiments: v3, and the same eval on a larger model.

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
  db.py       schema
  cli.py
tests/        includes a fake Ollama server (conftest.py)
```

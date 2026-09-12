# Design 03 — claudit guard: a local masking gateway

Status: designed 2026-09-12, not implemented · Depends on: Designs 00–02, `docs/threat-model.md`

## Problem

The audit layer reports what already left the machine. The guard keeps the highest-value classes from
leaving at all: a local proxy between Claude Code and the model provider replaces credentials with
format-preserving pseudonyms on the way out and restores them on the way back, so the model reasons about a
fake key and the user's files still end up with the real one.

## Verified constraints (Claude Code gateway docs, Messages API streaming docs)

- Claude Code routes through `ANTHROPIC_BASE_URL`; with only the base URL set, the claude.ai subscription
  login is still used, and the `anthropic-beta` header carries the OAuth capability — forward it verbatim.
- Forward `anthropic-version`, all `anthropic-*` headers and body fields unchanged; do not allowlist.
- Stream responses; never buffer whole responses; forward `ping` events and comment lines immediately (the
  client aborts a stream silent for 300 s).
- Leave the `system` array untouched and first; never reshape it.
- Inference posts to `/v1/messages?beta=true`; `/v1/messages/count_tokens` is optional; `HEAD /api/hello`
  may be rejected.
- SSE events: `message_start`, `content_block_start`, `ping`, `content_block_delta` (`text_delta.text`,
  `input_json_delta.partial_json` — fragments of a JSON string, accumulated by the client —
  `thinking_delta.thinking`, `signature_delta`), `content_block_stop`, `message_delta`, `message_stop`, `error`.
- The desktop app reads gateway routing from its own third-party-inference configuration, not from the
  environment; CLI and VS Code read `ANTHROPIC_BASE_URL`.

## Decisions

**Scope of masking: high-precision classes only.** Vendor-prefixed keys (`AKIA…`, `sk-ant-…`, `ghp_…`,
`xox…`, `AIza…`, `sk_live_…`, and the imported vendor formats with a fixed prefix), private-key blocks, and
connection-string passwords. Not generic passwords, not entropy hits, not PII: the false-positive cost there
is a corrupted request, and the audit layer already covers them.

**Format-preserving pseudonyms.** A pseudonym keeps the prefix and length of the original and draws its
random part from the same alphabet, so the model can still reason about "this AWS key" and has no reason to
alter it. Deterministic within a session (same real value → same pseudonym) so prompt caching keeps working
and later turns stay consistent. The map lives in memory only, is never logged or persisted, and is cleared
on exit.

**Where masking applies.** Text inside `messages[*].content` (string content, `text` blocks, `tool_result`
content). The `system` array, tool definitions, headers, and every other body field pass through byte-for-byte.

**Un-masking in the stream.** A per-response rewriter holds a look-ahead buffer no longer than the longest
pseudonym and rewrites `text_delta.text`, `thinking_delta.thinking`, and `input_json_delta.partial_json`.
Pseudonyms use only `[A-Za-z0-9_-]`, so they never contain JSON escapes and can be replaced inside
`partial_json` fragments safely; a pseudonym split across two deltas is caught by the look-ahead. Every
other event is forwarded untouched; `ping` is forwarded without waiting for the buffer.

**Un-mask miss = fail safe.** If the completed response still contains a pseudonym (the model altered it),
the user sees the pseudonym, never the real value. If that pseudonym sits inside a tool call whose input names
a file path, the guard rewrites the tool input so the write cannot proceed silently: it inserts a visible
marker and the miss is counted and shown. A pseudonym in a real `.env` is an outage, not a leak, and must not
happen silently.

**Observability without content.** Counters only: requests proxied, values masked by class, un-mask misses,
added latency. No request or response bodies are ever logged.

## Surfaces

- `claudit guard --port 8787` starts the proxy; prints the exact `ANTHROPIC_BASE_URL` line to set.
- `claudit guard status` — counters.
- Dashboard: "guarded" tile (values kept on the machine, misses).

## Testing

- **Replay harness**: recorded synthetic SSE streams (text, tool-call JSON, thinking, pings, pseudonyms split
  across frames at every possible boundary) are replayed through the rewriter and compared to the expected
  un-masked output byte-for-byte.
- **Fake upstream**: an in-process Messages-API stand-in that echoes what it received, so tests prove the
  upstream never sees a real value and the client always gets it back.
- **Live**: one Claude Code session through the guard with a planted key, verified end to end.

## Out of scope

Masking for other clients (Cursor etc.), PII classes, the desktop app's gateway configuration, any attempt to
detect exfiltration through MCP/Bash/WebFetch — all named in `docs/threat-model.md` as not protected.

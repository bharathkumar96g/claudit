# Design 05 — Observability and operations

Status: in progress · Depends on: Designs 00–03

## Problem

"How would you know it's broken?" Today: you wouldn't. Scans and judge runs print to a terminal and vanish;
the dashboard shows state, not history; the guard has counters but nothing on the dashboard knows about it.

## Decisions

**Runs are data.** Every scan, judge, semantic scan and adversarial check writes one row to a `runs` table:
kind, start, duration, and the stats it printed, as JSON. That is the history the dashboard and the runbook
need, and it costs one insert.

**Latency comes from what is already stored.** Judgments carry `duration_ms` per model call; semantic scans
carry it per segment. p50/p95 are a query, not new instrumentation.

**Health is three probes**: the database opens, Ollama answers `/api/version`, the guard answers
`/guard/status`. The dashboard shows them as three dots and the guard's counters as a tile ("kept on this
machine"). The claudit server fetches the guard's status over loopback so the browser never has to talk to
two origins.

**Logs never carry content.** An optional JSON log line per run to stderr (`CLAUDIT_LOG=json`) with the same
fields as the `runs` row. No previews, no paths beyond the transcripts directory, no reasons.

**A runbook, not a wiki.** `docs/runbook.md`: start, stop, what each failure looks like, what to do.

## Out of scope

Prometheus/OpenTelemetry exporters (nothing to scrape them here), alerting, remote telemetry of any kind.

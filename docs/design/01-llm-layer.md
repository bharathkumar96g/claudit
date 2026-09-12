# Design 01 — LLM layer: routing, prompt generalisation, model bench

Status: routing and prompt done 2026-09-12; model bench deferred (no model downloads yet) · Depends on: Design 00

## Problem

Phase 0 measured benign recognition at 8/12 on the vocabulary the prompt was written against and 0/11 on
held-out wording. The breakdown: 11 of 15 wrong benign verdicts never reached the model (routing confirmed
vendor-format keys by rule because the path did not look like tests/docs, or because a pasted value has no
path at all); of the 12 the model did read, it scored 8/9 on seen wording and 0/3 on held-out.

## Decisions

**Routing routes on evidence of context, not only on path.** A finding goes to the model when any of:
- the category is ambiguous (generic secret, entropy, PII), or severity is medium/low;
- the path looks like tests/docs/examples;
- the segment has **no path** (pasted into a prompt, a thinking block, an attachment) — unknown context is not
  evidence of production;
- the redacted window around the value contains **prose or a comment** (a comment marker, or several natural-
  language words). A bare `KEY=value` line in a config file stays rule-confirmed.

Cost: more model calls (the point of routing was to avoid them). Measured, not assumed: report the model-call
count alongside accuracy.

**Prompt v4 describes the concept.** "Benign" means the value is not connected to any live system: invented for
illustration, never issued by a provider, deliberately disposable, or scoped to an environment nothing real
depends on. The word list stays as *examples*, explicitly non-exhaustive, and the model is told the marker can
be phrased any way. Evaluated on held-out wording; seen-vocabulary numbers are reported but not optimised for.

**Model bench.** Same eval, same prompt, across `qwen2.5:7b`, `llama3.1:8b`, and a ~3B model: real-kept,
benign seen, benign held-out, latency per call, tokens, memory. Self-reported confidence is plotted against
outcomes; it stays hidden in the UI unless it is calibrated.

## Out of scope

Chunking of large tool results for the semantic scan (Phase 5); embeddings.

## Measured

| prompt | routing | model calls | real kept | benign seen | benign held-out | note |
|---|---|---|---|---|---|---|
| v3 | path only | 25 / 76 | 53/53 | 8/12 | 0/11 | 11 of 15 misses never reached the model |
| v4 | path + no-path + context | 59 / 76 | 52/53 | 12/12 | 11/11 | **invalid**: v4's example list contained held-out words |
| v5 | same | 59 / 76 | 52/53 | 12/12 | 8/11 | held-out words removed; decoy rule added |

The v4→v5 drop on held-out (11/11 → 8/11) is the measured cost of contamination: three plants the model
recognised only because the prompt named their words. v5 is the number of record.

Remaining failure modes (not tuned away, to avoid fitting the held-out set):
1. A real key dismissed because a *neighbouring* decoy line carried a placeholder marker (1/53).
2. Verdict/reason inconsistency on one held-out wording: the reason says "not live", the verdict says confirmed (3/11).

## How we know it worked

- Held-out benign recognition is materially above 0 without any real secret being dismissed.
- Model calls per 76 findings and seconds of model time are reported next to the accuracy.
- The bench table exists in `docs/eval-report.md` and is reproducible with one command.

# Design 04 — Retrieval-augmented judging

Status: implemented and measured 2026-09-12 — **null result, off by default** · Depends on: Designs 00, 01

## Result

Same 60-session set, same model, v7 policy with and without retrieval (memory: 53 confirmed + 12 seen-benign
examples, held-out excluded, same session/fingerprint excluded at query time):

| | real confirmed / benign / unsure | benign seen | benign held-out | model calls | model time |
|---|---|---|---|---|---|
| v7, no retrieval | 49 / **0** / 4 | 9 (+3 unsure) | 3 (+8 unsure) | 59 | 443 s |
| v8, retrieval (k=3) | 51 / **1** / 1 | 9 (+3 unsure) | 0 (+8 unsure, 3 confirmed) | 59 | 640 s |

Retrieval dismissed one real secret and moved the three held-out plants v7 recognised to *confirmed*, at
45% more model time. The memory is 4:1 confirmed-to-benign, so the retrieved neighbours were mostly
"confirmed" precedents; the model followed them. By the decision rule above (kept only if held-out improves
with no real secret dismissed) retrieval is **not enabled**. `--rag` remains available for experiments.

Follow-ups worth trying before retiring the idea: retrieve a balanced set (k benign + k confirmed); restrict
retrieval to ambiguous categories where prose is the only evidence; grow the benign side of the memory from
real dismissed secrets over time.

## Problem

The judge generalises poorly to benign wording it hasn't seen: 12/12 on the prompt's own vocabulary, 8/11 on
held-out wording (v5), with one real secret dismissed. Prompt edits aimed at those cases would fit the
held-out set. The standard alternative is to show the model *examples* at judgment time, retrieved by
similarity from a memory of past labeled cases.

## Verified constraints

- Ollama `POST /api/embed` — `{"model", "input": str | [str]}` → `{"embeddings": [[...]]}`; `nomic-embed-text`
  is 274 MB, 2K context. Dimensions are taken from the first embedding at runtime, not hardcoded.
- DuckDB: `list_cosine_similarity(FLOAT[], FLOAT[])` works on list columns and bound list parameters. The HNSW
  index (`vss`) has experimental persistence; with a memory of hundreds to low thousands of examples, a
  brute-force `ORDER BY similarity LIMIT k` is fast and has no persistence caveat. Revisit if the memory grows.

## Decisions

**The memory never contains a raw value.** Each example is the redacted excerpt with the target replaced by a
category placeholder (`«[github_token]»`), its category, verdict, a short reason, an origin label, and the
embedding of that placeholder text. This keeps ADR-0002: nothing textual that could identify a secret is stored.

**What goes in.** (1) Labeled synthetic examples *from the seen vocabulary only* — never held-out plants, so
the held-out eval stays a test of analogy rather than lookup. (2) Real verdicts, once a user has confirmed or
dismissed them, as they accumulate. Origin is recorded so eval can filter.

**Leak control in evaluation.** When judging a finding, retrieved examples exclude the same session and the same
fingerprint. The synthetic held-out plants share templates with each other but not with anything in memory.

**Retrieval.** Embed the query excerpt (same placeholder treatment), fetch top-k (k=3) by cosine similarity with
a floor (0.5), and render them into the user message as "Similar past cases" with their verdicts and reasons,
after the untrusted `<excerpt>` block and clearly labeled as examples. Prompt version 8.

**Measurement.** Same 60-session eval, judge with and without retrieval: real kept, benign seen, benign
held-out, model calls, latency. Retrieval is kept only if held-out improves without any real secret being
dismissed; otherwise it is documented as a null result.

## Surfaces

- `claudit memory build --from data/synthetic` — embed seen-vocabulary labeled examples.
- `claudit memory add-verdicts` — embed confirmed/dismissed real verdicts.
- `claudit judge --rag` — retrieval-augmented judging; `--rag` off by default until it wins the eval.

## Out of scope

Semantic search over history, clustering, embedding-based routing (a follow-up if retrieval proves useful).

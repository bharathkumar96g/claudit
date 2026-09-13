# 06 — Distilled judge

**Question.** The judgment layer runs a 7B model at 5–10 s per call. Can a 0.5B model, fine-tuned on the
7B model's verdicts and the labeled synthetic set, do the same job at a fraction of the latency and memory —
and where exactly does it fall short?

This is the project's first trained component. Everything before it was prompting, routing and evaluation.

## What is distilled

The student sees the *same messages* the teacher sees: `ADJUDICATE_SYSTEM` plus the user message built by
`build_user_message` from a redacted 400-char window with the target marked «…», after `strip_instructions`.
The dataset builder imports those functions rather than copying the prompt, so a prompt change re-flows into
training data on the next `build`.

Targets are the judge's JSON (`verdict`, `confidence`, `reason`). The verdict is the **ground-truth label**
from `labels.json`, not the teacher's — a student should not inherit the teacher's mistakes. The reason is
the **teacher's stored reason** when the teacher agreed with the label and actually ran (not routed by
rule), otherwise a fixed template. Reasons in the database are already scrubbed of the value.

So: label-corrected distillation. Verdicts from labels, phrasing from the teacher.

## Data

| set | corpus | purpose |
|---|---|---|
| train / valid | `claudit synth --sessions 400 --seed 11` → 575 plants (403 confirmed, 86 benign/seen, 86 benign/heldout) | heldout **excluded**; 90/10 split by session hash |
| test | `data/synthetic`, seed 7, 60 sessions, 76 plants | the set every judge version has been graded on |

The held-out benign wording is never in the training files. That is what makes the heldout column of the
comparison mean something: the student either learned the *concept* of "this value is not connected to
anything real" or it memorised the seen vocabulary.

**Privacy rule.** `build` raises if any finding in the database lacks a planted label. It cannot be pointed
at `real.duckdb`; the training files only ever contain generated values.

## Training

`mlx-lm` LoRA on `mlx-community/Qwen2.5-0.5B-Instruct-4bit` (290 MB, QLoRA on the quantised weights),
Apple silicon, `--mask-prompt` so the loss is on the assistant JSON only — the model is never trained to
reproduce excerpts. Defaults: 600 iterations, batch 1, 8 layers, lr 1e-4, seed 0, gradient checkpointing.
The `train` dependency group holds `mlx-lm`; the core package does not import it.

## Serving, and why the judge is unchanged

`claudit distill serve` exposes the student behind the three Ollama endpoints `OllamaClient` uses
(`/api/version`, `/api/tags`, `/api/chat`) on loopback. `claudit judge --base-url http://127.0.0.1:8790
--model claudit-student` then runs the *identical* pipeline — routing, instruction stripping, policy,
scrubbing, storage — against the student. The comparison is therefore between models, not between code paths.

One difference is deliberate: Ollama enforces the JSON schema at decode time; the student shim does not.
Unparseable output becomes `unsure` in the judge, and the rate is reported. A student that cannot keep to
the format is a finding, not something to hide with a grammar.

## Comparison protocol

Same test set, same `report --eval`, two databases (one per model), plus latency p50/p95 from
`claudit ops` and resident memory of the serving process. Columns: real kept, benign seen, benign heldout,
unsure, unparseable, p50/p95 ms, RSS. Reported in `docs/eval-report.md` with the failures listed.

Expected outcome, written before the run: the student should match on confirmed and benign/seen (it has
seen that vocabulary) and be worse on benign/heldout. If it matches on heldout too, the concept transferred;
if it collapses there, we say so.

**Outcome (2026-09-13).** Matched on both: 53/53 real kept, 0 dismissed, 9/12 seen-benign, 0 unparseable, at
p50 1.5 s vs 11.5 s and 559 MB vs 5.1 GB. Held-out 0/11 vs the teacher's 1/11 on the same day — neither
generalises there, and the student did not learn what it was not taught. Numbers in `docs/eval-report.md`.

## Not doing

- No fusing or GGUF export; the adapter is loaded on top of the base. Simpler, and the base stays shared.
- No training on real transcripts, ever, even with consent — the value would end up in the weights.
- No larger student until the 0.5B numbers exist.

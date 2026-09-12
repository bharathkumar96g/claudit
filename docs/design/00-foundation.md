# Design 00 — Foundation hardening

Status: done 2026-09-12 · Owner: claudit · Reviewed by: two independent senior-persona reviews (2026-09-12)

## Problem

An external review of the codebase found credibility gaps that undermine the tool's central claim — that it
audits sensitive data without becoming a second copy of it — and an evaluation that was tuned on its own
test set. Nothing new should be built on top until these are fixed.

## Findings and decisions

| # | Finding (verified) | Decision |
|---|---|---|
| 1 | `segments.text_redacted` held ~2.4M chars of transcript text — the tool duplicated the data it audits, minus regex hits. | **Store no transcript text.** Segments keep length, hash, source, and file path only. Anything that needs text (judge, semantic scan, reveal) re-reads the source transcript on demand and verifies the hash. ADR-0002. |
| 2 | Judge excerpt was built from raw text; a neighbouring secret could land in a stored reason. | Excerpt is built from the redacted window with only the marked value spliced back in. |
| 3 | Tool results carried no file path, so `tests/`, `.env.example` were invisible to the judge on real data. | Segments record `path` from `toolUseResult.file.filePath` (reads) and `input.file_path` (writes/edits). The judge sees it. |
| 4 | Eval contamination: the v3 prompt's benign vocabulary was the synthetic benign vocabulary; benign n=4. | Two benign sets: *seen* (prompt vocabulary) and *held-out* (disjoint wording). Accuracy reported per set, with n. Default eval set enlarged. |
| 5 | POST endpoints had no origin/host check (CSRF from any web page to localhost). | POSTs require `X-Requested-With: claudit`; Host must be a loopback origin. |
| 6 | `claudit reveal` inside a Claude Code session writes the secret into a new transcript. | Refuse when `CLAUDECODE` is set unless `--force`. |
| 7 | No chunk size cap; 218 patterns over 229 KB attachments (ReDoS exposure). | Scan in 64 KB windows with 512-char overlap; findings de-duplicated across the seam. |
| 8 | `thinking` blocks (587 in real transcripts) not ingested. | Ingested as source `assistant_thinking`. `~/.claude/file-history` and `history.jsonl` deferred to Phase 5 (different formats). |
| 9 | Semantic summaries relied on the prompt alone for scrubbing; self-reported confidence uncalibrated; no prompt version on verdicts. | Summaries scrubbed of digit runs and email-shaped tokens; confidence kept in storage but removed from the UI until calibrated (Phase 1); `prompt_version` stored on judgments. |
| 10 | Every finding went to the model. | Routing: vendor-format keys outside test/docs/example paths are confirmed by rule; only ambiguous categories or benign-looking paths reach the model. |
| 11 | Importer ignored gitleaks `regexTarget: match` and path-only allowlists. | Match-target allowlists apply to the full match; path-only allowlists are skipped (claudit has no repo paths). |
| 12 | "0 FP on 1,247 real chunks" is unlabeled data. | README states it as "zero hits on unlabeled real data", not zero errors. |

## Out of scope

The masking gateway (Phase 3), rotation checklist (Phase 2), model bench (Phase 1), new importers.

## How we know it worked

- `claudit scan --full` on real data stores zero transcript text: `segments` has no text column (verified: 1,817 rows, columns are metadata only).
- Judge excerpt test: a window with two secrets marks the target and redacts the other (`test_redacted_window_hides_neighbouring_secrets_but_marks_the_target`).
- Held-out benign accuracy is reported separately from seen-vocabulary accuracy (`report --eval`).
- CI runs the detection eval and fails if F1 < 1.0 on a 60-session synthetic set (`claudit eval`).

## Measured (60 sessions, 76 plants, qwen2.5:7b)

Detection 76/76, 0 FP. Judgment: real 53/53 kept; benign seen 8/12; benign held-out **0/11**.
Breakdown of the wrong benign verdicts: 11 of 15 were confirmed *by rule* (vendor-format key, no benign-looking
path — 8 held-out in `ci/`, `scripts/`, `onboarding/`; 3 seen pasted into prompts with no path at all), so the model
never saw the context; the model itself went 8/9 on seen wording and 0/3 on held-out wording.

## Follow-ups (Phase 1)

1. Routing is the larger error source: send vendor-format findings to the model when the segment has no path, or
   when the surrounding window contains prose/comments, not only when the path looks like tests/docs.
2. The prompt lists benign markers; it should describe the concept (a value not connected to any live system) and be
   evaluated on held-out wording only.
3. Model bench: the same eval on llama3.1:8b and a 3B model; calibrate self-reported confidence against outcomes.
4. Coverage: `~/.claude/file-history/` and `history.jsonl` as additional sources (different formats).

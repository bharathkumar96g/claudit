# Design 02 — Actionability: exposure per secret and rotation state

Status: done 2026-09-12 · Depends on: Design 00

## Problem

A list of findings answers "what fired"; the question a person actually has is "what do I rotate, in what
order, and have I dealt with it". The same key appearing in nine chunks across four sessions is one decision,
not nine rows.

## Decisions

**The unit of action is the secret, identified by fingerprint.** Findings are grouped by `(fingerprint,
category)` into a secret with: first and last seen, number of findings and sessions, the sources it entered
through, the projects, and the judgment summary (confirmed / benign / unsure from the model or rule).

**State lives in a small table keyed by fingerprint** — `open` (default), `rotated`, `dismissed` — with a
note and timestamp. It survives rescans because it is keyed by the fingerprint, not by finding ids. It is the
only user-authored data in the database.

**Priority is severity, then judgment, then breadth.** Critical/high, model- or rule-confirmed, seen in many
sessions floats to the top. Benign-judged and dismissed secrets sink.

**Rotation guidance is a short, category-specific instruction**, naming the provider and what to do (revoke,
then re-issue), without deep links that go stale.

## Surfaces

- `claudit secrets [--state open|rotated|dismissed|all]` — the checklist.
- `claudit secrets mark <fingerprint-prefix> rotated|dismissed|open [--note ...]`.
- `GET /api/secrets`, `POST /api/secrets/{fingerprint}/state`.
- Dashboard panel "secrets to act on" with state buttons; the hero shows the count of open confirmed secrets.

## Out of scope

Live validity checks against providers (opt-in, Phase 5 at the earliest, with a written justification).

## How we know it worked

- Two findings of the same value in different sessions produce one secret with `sessions = 2`.
- Marking a secret rotated hides it from the default checklist and survives `scan --full`.

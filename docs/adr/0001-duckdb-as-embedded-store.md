# ADR-0001: DuckDB as the embedded store

Date: 2026-09-10 · Status: accepted

**Context.** claudit is local-first by design; its workload is analytical (group findings by severity,
category, day, project) over at most a few million events on one machine.

**Decision.** One DuckDB file per dataset. No server process.

**Consequences.** Zero install and zero ops; columnar execution makes the dashboard queries instant;
the database is a file you can delete, copy, or ignore in git. Single-writer: while `claudit serve`
holds the file, CLI commands against the same `--db` are refused — documented, and the UI exposes
scan/judge so that is rarely needed. Not a shared store; a team deployment would sync fingerprints
and aggregates to a central database instead.

# ADR-0002: Store no transcript text

Date: 2026-09-12 · Status: accepted (supersedes the redacted-text column from v0)

**Context.** v0 stored each text chunk redacted of regex hits. On real data that was ~2.4M characters —
a second copy of the transcripts, outside `~/.claude`, missing only what the rules happened to catch.
The judge layer exists precisely because the rules miss things, so the copy contained what the tool
is meant to find.

**Decision.** Segments store metadata only: length, SHA-256, source, file path, offsets of findings.
Findings store a fingerprint and a masked preview. Any operation that needs text re-reads the source
transcript by file, line, and offset, and verifies the hash before using it. Nothing textual is
persisted by claudit except the masked preview and scrubbed model reasons.

**Consequences.** claudit adds no new place for secrets to live. Reads are slightly slower (a file seek
per judged finding) and depend on the transcripts still existing — if a transcript is deleted, its
findings remain as fingerprints but cannot be judged or revealed. The semantic scan and any future
coaching features compute what they need at read time or store derived features, never raw text.

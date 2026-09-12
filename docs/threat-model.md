# Threat model

Written for claudit as a whole, with a section for each layer. Kept deliberately plain: what is protected,
from whom, and — the part that matters most — what is not.

## Assets

1. Credentials and personal data that appear in AI coding sessions: typed by the user, read from files by
   the agent, produced by commands, or echoed by the model.
2. The transcript files themselves (`~/.claude/projects`), which are a plaintext archive of (1).
3. The claudit database, which must never become a second copy of (1).
4. The user's Anthropic session credential, which the guard sits in the path of.

## Adversaries considered

- **The third party receiving the request.** Not hostile, but outside the user's control: the model provider,
  its subprocessors, and whatever the account's data-use settings allow. The question is minimisation, not trust.
- **Anyone who later obtains the local files**: a stolen laptop, a synced backup, a shared machine, malware
  that reads the home directory, a colleague given a transcript "to debug".
- **A web page open in the user's browser**, which can make requests to `localhost` services.
- **The user's own future self**, who pastes a secret into a session while thinking about something else.

Not considered: a compromised local machine with a hostile root process (nothing local survives that), a
hostile model provider (out of scope for a client-side tool), and other users on the same OS account.

## Layer 1–3: audit (implemented)

**Protects:** the database from becoming an asset. No transcript text is stored (ADR-0002); findings hold a
fingerprint and a masked preview; model reasons are scrubbed of the value and any 8+ character fragment;
model excerpts have every other detected value redacted before the model sees them. The local server rejects
cross-site POSTs and non-loopback hosts. `claudit reveal` refuses to run inside a Claude Code session, where
its output would land in a new transcript.

**Does not protect:** the transcripts themselves — claudit reads them, it does not encrypt, move, or delete
them. The audit is a receipt-checker for data that has already been sent; it prevents nothing.

**Residual risks:** a masked preview plus a category is still a hint (`AKIA…W2`); rules miss what has no
pattern; the model judge is wrong about 1 in 20 ambiguous cases on the eval set and occasionally dismisses a
real secret because a neighbouring line carried a placeholder marker.

## Layer 4: guard (Design 03, not yet implemented)

**Protects:** high-precision credential classes (vendor-prefixed keys, private keys, connection strings) from
leaving the machine in requests to the model provider, by replacing them with format-preserving pseudonyms
before the request is sent and restoring them in the streamed reply.

**Does not protect — and says so in the UI:**
- Anything sent by other paths: MCP servers, `curl`/`gh`/`aws` run through the Bash tool, `WebFetch`,
  subagents that call the API themselves, or any client not configured to use the gateway.
- Classes the rules don't match with high precision: generic passwords, high-entropy strings, PII. Those
  stay in the audit layer; masking them would corrupt too many legitimate requests.
- The transcript on disk: Claude Code writes what the user typed and what tools returned *before* the guard
  sees it. The guard reduces what the provider receives; the audit still shows what the local files hold.
- The pseudonym mapping in memory: it is the most valuable object on the machine while the gateway runs.
  It is never logged, never persisted, and zeroed on exit; a process memory dump defeats it.
- The subscription credential: the gateway forwards the `Authorization`/`anthropic-beta` headers unchanged
  and never logs them; a logging bug here would be a credential leak, so request logging is off by design.

**Failure modes and the chosen behaviour:**
- *Un-mask miss* (the model altered a pseudonym so it can't be matched): the user sees the pseudonym, never
  the real value; the guard counts the miss and shows it. If the reply is a tool call that would write a
  file, the write is **blocked and the user told**, because a pseudonym written into a real `.env` is an
  outage, not a leak.
- *False positive on the way out*: the model reasons about a pseudonym that had no reason to be masked. Cost
  is a slightly confused model, never a leak; the class list is kept narrow to keep this rare.
- *False negative on the way out*: the secret leaves as before. The guard is a reduction, not a guarantee.
- *Stream stall*: un-masking needs a small look-ahead buffer (the longest pseudonym) so a pseudonym split
  across two SSE frames is caught; pings and comments are forwarded immediately so the client's watchdog
  never trips.

## Things this document promises to keep true

- No claudit component ever writes a raw secret value to disk, logs, or a network destination other than the
  provider request the user initiated.
- Every number in the README is reproducible with one documented command.
- Every "does not protect" above stays in the README and the guard's own status output.

# Evaluation report

Reproduce (about 8 minutes, most of it model time):

```bash
uv run claudit synth --sessions 60 --seed 7
uv run claudit scan --dir data/synthetic --full
uv run claudit eval data/synthetic            # detection gate
uv run claudit judge --rejudge                # needs Ollama + qwen2.5:7b
uv run claudit report --eval data/synthetic   # judgment table
```

Set: 60 synthetic sessions, 76 planted secrets across 27 categories and every source Claude Code records
(`user_prompt`, `tool_result`, `tool_input`, `assistant_thinking`); 23 plants benign-in-context, 12 in the
prompt's own vocabulary ("seen"), 11 in disjoint wording and non-obvious paths ("held-out"). Decoys in every
session: git SHAs, UUIDs, `your_api_key_here`, `os.environ[...]`, epoch timestamps.

## Detection (deterministic, 235 rules)

| | value |
|---|---|
| true positives | 76 / 76 |
| false positives | 0 |
| F1 | 1.000 |
| real transcripts (1,817 chunks, unlabeled) | no hits from imported rules beyond hand-tuned ones — zero hits, not proven zero errors |

## Judgment (qwen2.5:7b, temperature 0, JSON-schema output, prompt v5)

| expected | confirmed | benign | n |
|---|---|---|---|
| real secret | 52 | 1 | 53 |
| benign, seen | 0 | 12 | 12 |
| benign, held-out | 3 | 8 | 11 |

Accuracy 0.95 over 76. Routing sent 59 findings to the model (402 s, 27.8k prompt tokens) and confirmed 17
by rule. Routing sends a finding to the model when the category is ambiguous, the path looks like tests or
docs, the segment has no path (pasted into a prompt or thinking block), or the surrounding window contains a
comment or prose. Bare `KEY=value` lines in production-looking files are confirmed by rule.

### History, including the number that was thrown out

| prompt | routing | real kept | benign seen | benign held-out | verdict |
|---|---|---|---|---|---|
| v1 (31-plant set, benign n=4) | none | 27/27 | 1/4 | — | superseded; contaminated eval |
| v2 (31-plant set) | none | 15/27 | 4/4 | — | superseded |
| v3 | path only | 53/53 | 8/12 | 0/11 | routing hid context from the model in 11 of 15 misses |
| v4 | path + no-path + context | 52/53 | 12/12 | 11/11 | **discarded**: example list included held-out words |
| v5 | same | 52/53 | 12/12 | 8/11 | number of record |

### Known failure modes

1. **Neighbouring placeholder.** A real key in a prompt next to `API_KEY=your_api_key_here` was dismissed;
   the model applied the neighbour's marker despite an explicit rule against it. 1/53. The worse kind of error.
2. **Verdict/reason inconsistency.** For "default for the disposable compose stack … every deployed environment
   overrides it", the model wrote "not intended to be used in a live system" and answered confirmed. 3/11.

Both are candidates for the model bench (llama3.1:8b, a 3B model) rather than further prompt edits, which
would risk fitting the held-out set.

### What is not measured

Semantic scan (pattern-less sensitive content) has no labeled set yet. Self-reported confidence is stored but
uncalibrated and hidden in the UI.

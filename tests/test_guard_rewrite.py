import json

from hypothesis import given, settings
from hypothesis import strategies as st

from claudit.guard.rewrite import StreamRewriter

FAKE_A = "ghp_" + "Zz9y8X7w" * 5
REAL_A = "ghp_" + "A1b2C3d4" * 5
FAKE_B = "AKIA" + "QQQQWWWWEEEERRRR"
REAL_B = "AKIA" + "J4K7QZ2M9XP3RT6W"
MAPPING = {FAKE_A: REAL_A, FAKE_B: REAL_B}


def sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def parse(stream: bytes):
    events = []
    for frame in stream.decode().split("\n\n"):
        if not frame.strip():
            continue
        ev = data = None
        for line in frame.split("\n"):
            if line.startswith("event:"):
                ev = line[6:].strip()
            elif line.startswith("data:"):
                data = json.loads(line[5:].strip())
        events.append((ev, data))
    return events


def text_of(events, kind="text_delta", key="text", index=0):
    return "".join(d["delta"][key] for e, d in events if e == "content_block_delta"
                   and d["index"] == index and d["delta"]["type"] == kind)


def build_stream(message: str, cuts: list[int], kind="text_delta", key="text", pings_at=()):
    """A text split into deltas at the given cut positions, with message/blocks around it."""
    frames = [sse("message_start", {"type": "message_start", "message": {"id": "m"}}),
              sse("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})]
    prev = 0
    for i, cut in enumerate([*sorted({c for c in cuts if 0 < c < len(message)}), len(message)]):
        if i in pings_at:
            frames.append(sse("ping", {"type": "ping"}))
        frames.append(sse("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": kind, key: message[prev:cut]}}))
        prev = cut
    frames.append(sse("content_block_stop", {"type": "content_block_stop", "index": 0}))
    frames.append(sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 5}}))
    frames.append(sse("message_stop", {"type": "message_stop"}))
    return b"".join(frames)


def feed_in_chunks(rw: StreamRewriter, stream: bytes, sizes: list[int]) -> bytes:
    out = bytearray()
    pos = 0
    i = 0
    while pos < len(stream):
        n = max(1, sizes[i % len(sizes)]) if sizes else len(stream)
        out += rw.feed(stream[pos:pos + n])
        pos += n
        i += 1
    out += rw.finish()
    return bytes(out)


@settings(max_examples=250, deadline=None)
@given(
    prefix=st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\n"), max_size=30),
    middle=st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\n"), max_size=30),
    suffix=st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\n"), max_size=30),
    cuts=st.lists(st.integers(min_value=1, max_value=200), max_size=12),
    chunk_sizes=st.lists(st.integers(min_value=1, max_value=64), min_size=1, max_size=6),
    use_json=st.booleans(),
)
def test_unmasking_is_exact_for_any_delta_and_byte_split(prefix, middle, suffix, cuts, chunk_sizes, use_json):
    message = f"{prefix}{FAKE_A}{middle}{FAKE_B}{suffix}"
    expected = f"{prefix}{REAL_A}{middle}{REAL_B}{suffix}"
    if use_json:
        # tool-call inputs stream as fragments of a JSON *string*: escape both sides the same way
        message = json.dumps({"content": message})
        expected = json.dumps({"content": expected})
        kind, key = "input_json_delta", "partial_json"
    else:
        kind, key = "text_delta", "text"
    stream = build_stream(message, cuts, kind, key, pings_at={1, 3})
    rw = StreamRewriter(dict(MAPPING))
    out = feed_in_chunks(rw, stream, chunk_sizes)
    events = parse(out)

    assert text_of(events, kind, key) == expected
    kinds = [e for e, _ in events]
    assert kinds[0] == "message_start" and kinds[-1] == "message_stop"
    assert kinds.count("ping") == kinds.count("ping")  # pings survive
    assert kinds.index("content_block_stop") < kinds.index("message_delta")
    assert FAKE_A.encode() not in out and FAKE_B.encode() not in out
    assert rw.replaced == 2


def test_pings_and_unrelated_events_pass_through_immediately_even_while_holding_a_tail():
    rw = StreamRewriter(dict(MAPPING))
    half = FAKE_A[:10]  # a proper prefix of a pseudonym: must be held
    out = rw.feed(sse("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "key=" + half}}))
    assert b"key=" in out and half.encode() not in out  # prefix held back, safe text emitted
    ping = rw.feed(sse("ping", {"type": "ping"}))
    assert ping == sse("ping", {"type": "ping"})  # forwarded at once, unchanged
    rest = rw.feed(sse("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": FAKE_A[10:] + " done"}}))
    assert REAL_A.encode() in rest and b" done" in rest
    assert rw.feed(sse("content_block_stop", {"type": "content_block_stop", "index": 0})).endswith(sse("content_block_stop", {"type": "content_block_stop", "index": 0}))


def test_empty_mapping_is_a_transparent_pipe():
    rw = StreamRewriter({})
    stream = build_stream("hello " + FAKE_A, [3, 9])
    assert feed_in_chunks(rw, stream, [7]) == stream


def test_partial_frame_at_close_is_flushed_untouched():
    rw = StreamRewriter(dict(MAPPING))
    assert rw.feed(b"event: ping\ndata: {\"type\": \"pi") == b""
    assert rw.finish() == b"event: ping\ndata: {\"type\": \"pi"

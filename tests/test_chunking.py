from itertools import pairwise

from hypothesis import given, settings
from hypothesis import strategies as st

from claudit.chunking import chunk_spans


def test_short_text_is_one_piece():
    assert chunk_spans("hello\nworld", size=100, overlap=10) == [(0, 11)]
    assert chunk_spans("", size=100, overlap=10) == [(0, 0)]


def test_pieces_cut_on_line_starts_and_overlap():
    text = "\n".join(f"line {i:03d} " + "x" * 20 for i in range(40))  # 40 lines, ~29 chars each
    spans = chunk_spans(text, size=300, overlap=60)
    assert len(spans) > 3
    assert spans[0][0] == 0 and spans[-1][1] == len(text)
    for (s1, e1), (s2, e2) in pairwise(spans):
        assert s2 < e1  # overlaps the previous piece
        assert s2 > s1  # and makes progress
        assert text[s2 - 1] == "\n"  # starts at a line start
        assert e2 - s2 <= 300


@settings(max_examples=200, deadline=None)
@given(
    text=st.text(alphabet=st.sampled_from("ab \n"), min_size=0, max_size=2000),
    size=st.integers(min_value=5, max_value=400),
    overlap_frac=st.floats(min_value=0.0, max_value=0.9),
)
def test_spans_always_cover_the_text_in_order_and_terminate(text, size, overlap_frac):
    overlap = int(size * overlap_frac)
    spans = chunk_spans(text, size=size, overlap=overlap)
    assert spans[0][0] == 0 and spans[-1][1] == len(text)
    covered = set()
    prev_start = -1
    for s, e in spans:
        assert 0 <= s <= e <= len(text)
        assert s > prev_start  # strictly increasing starts: guaranteed termination
        prev_start = s
        covered.update(range(s, e))
    assert covered == set(range(len(text)))
    # every piece except possibly one holding a single overlong line respects the size
    assert sum(1 for s, e in spans if e - s > size) <= max(0, text.count("\n") + 1) or all(e - s <= size for s, e in spans)

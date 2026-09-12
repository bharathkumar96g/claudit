"""Split long text into overlapping pieces on line boundaries, keeping offsets into the original.

A 7B model's judgment degrades long before its context limit, and tool results (whole files) run to
thousands of lines. Pieces are sized in characters (~4 chars per token), overlap so content at a cut is
seen twice rather than never, and always start at a line start so a finding's offsets point at real lines.
"""

from __future__ import annotations

PIECE_CHARS = 3200
OVERLAP_CHARS = 320


def chunk_spans(text: str, size: int = PIECE_CHARS, overlap: int = OVERLAP_CHARS) -> list[tuple[int, int]]:
    """[start, end) spans covering all of `text`; each starts at a line start except possibly the first (0)."""
    if size <= 0 or overlap < 0 or overlap >= size:
        raise ValueError("need 0 <= overlap < size")
    n = len(text)
    if n <= size:
        return [(0, n)]

    line_starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n" and i + 1 < n]
    spans: list[tuple[int, int]] = []
    start = 0
    while True:
        end = min(n, start + size)
        if end < n:
            # cut at the last line start inside the window, unless the window holds a single huge line
            cut = max((ls for ls in line_starts if start < ls <= end), default=end)
            end = cut if cut > start else end
        spans.append((start, end))
        if end >= n:
            return spans
        # next piece begins `overlap` chars before this end, snapped back to a line start
        target = max(start + 1, end - overlap)
        start = max((ls for ls in line_starts if ls <= target), default=target)
        if start <= spans[-1][0]:
            start = end  # guarantee progress on pathological input

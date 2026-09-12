from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import duckdb

from .util import one

SEV_ORDER = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"
VERDICT_COLUMNS = ("confirmed", "benign", "unsure", "unavailable", "not judged")


def _table(headers: list[str], rows: list[tuple]) -> str:
    cells = [["" if v is None else str(v) for v in r] for r in rows]
    widths = [max([len(h)] + [len(r[i]) for r in cells]) for i, h in enumerate(headers)]
    head = "  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True))
    sep = "  ".join("-" * w for w in widths)
    body = ["  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)) for r in cells] or ["(none)"]
    return "\n".join([head, sep, *body])


def _clip(s: object, n: int) -> str:
    s = "" if s is None else str(s).replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def summary(con: duckdb.DuckDBPyConnection) -> str:
    q = lambda sql: con.execute(sql).fetchall()  # noqa: E731
    ev, seg, fd, sess, proj = one(
        con,
        "SELECT (SELECT count(*) FROM events), (SELECT count(*) FROM segments), (SELECT count(*) FROM findings),"
        " (SELECT count(DISTINCT session_id) FROM events), (SELECT count(DISTINCT project) FROM events)",
    )

    parts = [f"events {ev}   segments {seg}   sessions {sess}   projects {proj}   findings {fd}"]
    parts.append("\nBy severity\n" + _table(
        ["severity", "findings", "sessions"],
        q(f"SELECT severity, count(*), count(DISTINCT session_id) FROM findings GROUP BY 1 ORDER BY {SEV_ORDER}"),
    ))
    parts.append("\nBy category\n" + _table(
        ["category", "severity", "findings"],
        q(f"SELECT category, severity, count(*) FROM findings GROUP BY 1, 2 ORDER BY {SEV_ORDER}, 3 DESC"),
    ))
    parts.append("\nBy source (who put it in front of the model)\n" + _table(
        ["source", "findings"],
        q("SELECT source, count(*) FROM findings GROUP BY 1 ORDER BY 2 DESC"),
    ))
    parts.append("\nBy project\n" + _table(
        ["project", "findings", "critical+high"],
        q("SELECT project, count(*), count(*) FILTER (WHERE severity IN ('critical', 'high'))"
          " FROM findings GROUP BY 1 ORDER BY 2 DESC LIMIT 10"),
    ))
    parts.append("\nSame secret seen more than once\n" + _table(
        ["category", "preview", "times", "sessions"],
        q("SELECT category, preview, count(*) AS n, count(DISTINCT session_id) FROM findings"
          " GROUP BY fingerprint, category, preview HAVING count(*) > 1 ORDER BY n DESC LIMIT 10"),
    ))
    parts.append("\nMost recent\n" + _table(
        ["when", "severity", "category", "preview", "source", "project"],
        q("SELECT strftime(ts, '%Y-%m-%d %H:%M'), severity, category, preview, source, project"
          " FROM findings ORDER BY ts DESC NULLS LAST LIMIT 15"),
    ))

    if one(con, "SELECT count(*) FROM judgments")[0]:
        parts.append("\nModel review of flagged findings\n" + _table(
            ["verdict", "findings"],
            q("SELECT verdict, count(*) FROM judgments GROUP BY 1 ORDER BY 2 DESC"),
        ))
        parts.append("\nConfirmed by model\n" + _table(
            ["severity", "category", "preview", "source", "conf", "reason"],
            [(s, c, p, src, f"{conf:.2f}" if conf is not None else "", _clip(r, 70)) for s, c, p, src, conf, r in q(
                "SELECT f.severity, f.category, f.preview, f.source, j.confidence, j.reason"
                " FROM findings f JOIN judgments j ON j.finding_id = f.finding_id"
                f" WHERE j.verdict = 'confirmed' ORDER BY {SEV_ORDER.replace('severity', 'f.severity')}, f.ts DESC LIMIT 15"
            )],
        ))
        parts.append("\nMarked benign by model\n" + _table(
            ["category", "preview", "source", "reason"],
            [(c, p, src, _clip(r, 70)) for c, p, src, r in q(
                "SELECT f.category, f.preview, f.source, j.reason FROM findings f"
                " JOIN judgments j ON j.finding_id = f.finding_id WHERE j.verdict = 'benign' ORDER BY f.ts DESC LIMIT 10"
            )],
        ))

    if one(con, "SELECT count(*) FROM semantic_findings")[0]:
        parts.append("\nSensitive content without a pattern (model-found)\n" + _table(
            ["kind", "severity", "findings"],
            q(f"SELECT kind, severity, count(*) FROM semantic_findings GROUP BY 1, 2 ORDER BY {SEV_ORDER}, 3 DESC"),
        ))
        parts.append("\n" + _table(
            ["when", "kind", "severity", "summary", "project"],
            [(w, k, s, _clip(sm, 80), _clip(p, 40)) for w, k, s, sm, p in q(
                "SELECT strftime(ts, '%Y-%m-%d %H:%M'), kind, severity, summary, project"
                " FROM semantic_findings ORDER BY ts DESC NULLS LAST LIMIT 15"
            )],
        ))
    return "\n".join(parts)


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f1


def evaluate_data(con: duckdb.DuckDBPyConnection, eval_dir: Path) -> dict:
    """Detection precision/recall and model-judgment accuracy against the synthetic labels, as plain data."""
    manifest = json.loads((eval_dir / "labels.json").read_text())
    sessions = set(manifest["sessions"])
    plants = manifest["plants"]
    truth = {(p["session_id"], p["category"], p["fingerprint"]) for p in plants}

    rows = con.execute(
        "SELECT session_id, category, fingerprint, preview, source, project FROM findings"
    ).fetchall()
    tp_keys: set[tuple] = set()
    fps: list[tuple] = []
    for r in rows:
        if r[0] not in sessions:
            continue
        key = (r[0], r[1], r[2])
        if key in truth:
            tp_keys.add(key)
        else:
            fps.append(r)
    fns = [p for p in plants if (p["session_id"], p["category"], p["fingerprint"]) not in tp_keys]

    def row(cat: str, tp: int, fp: int, fn: int) -> dict:
        p, r, f1 = _prf(tp, fp, fn)
        return {"category": cat, "tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1}

    categories = sorted({p["category"] for p in plants} | {r[1] for r in fps})
    per_category = [
        row(cat, sum(1 for k in tp_keys if k[1] == cat), sum(1 for r in fps if r[1] == cat),
            sum(1 for p in fns if p["category"] == cat))
        for cat in categories
    ]
    overall = row("ALL", len(tp_keys), len(fps), len(fns))

    judge = None
    verdict_by_key: dict[tuple, tuple[str, str]] = {}
    for sid, cat, fp, verdict, jmodel in con.execute(
        "SELECT f.session_id, f.category, f.fingerprint, j.verdict, j.model"
        " FROM findings f JOIN judgments j ON j.finding_id = f.finding_id"
    ).fetchall():
        if sid in sessions:
            verdict_by_key[(sid, cat, fp)] = (verdict, jmodel)
    if verdict_by_key:
        # Benign plants are split into the vocabulary the prompt was written against ("seen") and
        # disjoint wording ("heldout"); only the latter says anything about generalisation.
        confusion: Counter = Counter()
        by_rule = 0
        for p in plants:
            key = (p["session_id"], p["category"], p["fingerprint"])
            if key not in tp_keys:
                continue
            expected = p.get("expected_verdict", "confirmed")
            if expected == "benign":
                expected = f"benign/{p.get('benign_set', 'seen')}"
            actual, jmodel = verdict_by_key.get(key, ("not judged", None))
            if jmodel == "rules":
                by_rule += 1
            confusion[(expected, actual)] += 1
        expected_rows = ("confirmed", "benign/seen", "benign/heldout")
        judged = sum(v for (e, a), v in confusion.items() if a not in ("not judged", "unavailable"))
        correct = confusion[("confirmed", "confirmed")] + confusion[("benign/seen", "benign")] + confusion[("benign/heldout", "benign")]
        judge = {
            "rows": [{"expected": e, **{a: confusion[(e, a)] for a in VERDICT_COLUMNS}} for e in expected_rows],
            "judged": judged,
            "by_rule": by_rule,
            "accuracy": correct / judged if judged else None,
        }

    semantic = None
    semantic_plants = manifest.get("semantic_plants", [])
    if semantic_plants and one(con, "SELECT count(*) FROM semantic_scans")[0]:
        # Which labeled segments were scanned, and what the model reported on them.
        scanned = {
            (fp, ln, src): (seg_id, n)
            for fp, ln, src, seg_id, n in con.execute(
                "SELECT e.file_path, e.line_no, s.source, s.segment_id, sc.n_findings FROM semantic_scans sc"
                " JOIN segments s ON s.segment_id = sc.segment_id JOIN events e ON e.event_id = s.event_id"
            ).fetchall()
        }
        kinds_by_seg: dict[str, set[str]] = {}
        for seg_id, kind in con.execute("SELECT segment_id, kind FROM semantic_findings").fetchall():
            kinds_by_seg.setdefault(seg_id, set()).add(kind)
        planted_segs = set()
        per_kind: dict[str, dict[str, int]] = {}
        for p in semantic_plants:
            key = (p["file"], p["line_no"], p["source"])
            stat = per_kind.setdefault(p["kind"], {"n": 0, "scanned": 0, "any": 0, "exact": 0})
            stat["n"] += 1
            if key not in scanned:
                continue
            seg_id, _ = scanned[key]
            planted_segs.add(seg_id)
            stat["scanned"] += 1
            found = kinds_by_seg.get(seg_id, set())
            stat["any"] += bool(found)
            stat["exact"] += p["kind"] in found
        fp_segments = sum(1 for seg_id, n in scanned.values() if n and seg_id not in planted_segs)
        semantic = {
            "per_kind": [{"kind": k, **v} for k, v in sorted(per_kind.items())],
            "planted": len(semantic_plants),
            "scanned_segments": len(scanned),
            "false_positive_segments": fp_segments,
        }

    return {
        "sessions": len(sessions),
        "plants": len(plants),
        "semantic": semantic,
        "per_category": per_category,
        "overall": overall,
        "false_positives": [{"category": r[1], "preview": r[3], "source": r[4], "project": r[5]} for r in fps],
        "missed": [
            {"category": p["category"], "preview": p["preview"], "source": p["source"],
             "location": f"{Path(p['file']).name}:{p['line_no']}"}
            for p in fns
        ],
        "judge": judge,
    }


def evaluate(con: duckdb.DuckDBPyConnection, eval_dir: Path) -> str:
    d = evaluate_data(con, eval_dir)
    fmt = lambda r: (r["category"], r["tp"], r["fp"], r["fn"], f"{r['precision']:.2f}", f"{r['recall']:.2f}", f"{r['f1']:.2f}")  # noqa: E731
    parts = [
        f"Evaluation against {d['plants']} planted secrets in {d['sessions']} synthetic sessions",
        _table(["category", "tp", "fp", "fn", "precision", "recall", "f1"],
               [fmt(r) for r in d["per_category"]] + [fmt(d["overall"])]),
    ]
    if d["false_positives"]:
        parts.append("\nFalse positives\n" + _table(
            ["category", "preview", "source", "project"],
            [(r["category"], r["preview"], r["source"], r["project"]) for r in d["false_positives"]],
        ))
    if d["missed"]:
        parts.append("\nMissed (false negatives)\n" + _table(
            ["category", "preview", "source", "file:line"],
            [(r["category"], r["preview"], r["source"], r["location"]) for r in d["missed"]],
        ))
    if d["semantic"]:
        sm = d["semantic"]
        parts.append(
            f"\nSemantic scan against {sm['planted']} planted passages ({sm['scanned_segments']} segments scanned;"
            f" {sm['false_positive_segments']} unplanted segments got findings)\n"
            + _table(["kind", "planted", "scanned", "detected (any kind)", "detected (right kind)"],
                     [(r["kind"], r["n"], r["scanned"], r["any"], r["exact"]) for r in sm["per_kind"]])
        )
    if d["judge"]:
        j = d["judge"]
        acc = f"{j['accuracy']:.2f}" if j["accuracy"] is not None else "n/a"
        parts.append(
            "\nJudgment accuracy on planted secrets (rows: expected, columns: verdict)\n"
            + _table(["expected", *VERDICT_COLUMNS], [(r["expected"], *[r[a] for a in VERDICT_COLUMNS]) for r in j["rows"]])
            + f"\naccuracy {acc} over {j['judged']} judged ({j['by_rule']} confirmed by rule without the model)"
        )
    return "\n".join(parts)

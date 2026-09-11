from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import duckdb

SEV_ORDER = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"
VERDICT_COLUMNS = ("confirmed", "benign", "unsure", "unavailable", "not judged")


def _table(headers: list[str], rows: list[tuple]) -> str:
    cells = [["" if v is None else str(v) for v in r] for r in rows]
    widths = [max([len(h)] + [len(r[i]) for r in cells]) for i, h in enumerate(headers)]
    head = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    sep = "  ".join("-" * w for w in widths)
    body = ["  ".join(c.ljust(w) for c, w in zip(r, widths)) for r in cells] or ["(none)"]
    return "\n".join([head, sep, *body])


def _clip(s: object, n: int) -> str:
    s = "" if s is None else str(s).replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def summary(con: duckdb.DuckDBPyConnection) -> str:
    q = lambda sql: con.execute(sql).fetchall()  # noqa: E731
    ev, seg, fd, sess, proj = con.execute(
        "SELECT (SELECT count(*) FROM events), (SELECT count(*) FROM segments), (SELECT count(*) FROM findings),"
        " (SELECT count(DISTINCT session_id) FROM events), (SELECT count(DISTINCT project) FROM events)"
    ).fetchone()

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

    if con.execute("SELECT count(*) FROM judgments").fetchone()[0]:
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

    if con.execute("SELECT count(*) FROM semantic_findings").fetchone()[0]:
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
    verdict_by_key: dict[tuple, str] = {}
    for sid, cat, fp, verdict in con.execute(
        "SELECT f.session_id, f.category, f.fingerprint, j.verdict FROM findings f JOIN judgments j ON j.finding_id = f.finding_id"
    ).fetchall():
        if sid in sessions:
            verdict_by_key[(sid, cat, fp)] = verdict
    if verdict_by_key:
        confusion: Counter = Counter()
        for p in plants:
            key = (p["session_id"], p["category"], p["fingerprint"])
            if key in tp_keys:
                confusion[(p.get("expected_verdict", "confirmed"), verdict_by_key.get(key, "not judged"))] += 1
        judged = sum(v for (e, a), v in confusion.items() if a not in ("not judged", "unavailable"))
        correct = confusion[("confirmed", "confirmed")] + confusion[("benign", "benign")]
        judge = {
            "rows": [{"expected": e, **{a: confusion[(e, a)] for a in VERDICT_COLUMNS}} for e in ("confirmed", "benign")],
            "judged": judged,
            "accuracy": correct / judged if judged else None,
        }

    return {
        "sessions": len(sessions),
        "plants": len(plants),
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
    if d["judge"]:
        j = d["judge"]
        acc = f"{j['accuracy']:.2f}" if j["accuracy"] is not None else "n/a"
        parts.append(
            "\nModel judgment accuracy on planted secrets (rows: expected, columns: model verdict)\n"
            + _table(["expected", *VERDICT_COLUMNS], [(r["expected"], *[r[a] for a in VERDICT_COLUMNS]) for r in j["rows"]])
            + f"\naccuracy {acc} over {j['judged']} judged"
        )
    return "\n".join(parts)

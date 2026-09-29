"""Aggregate the proxy's JSONL decision log into a run.json for the dashboard."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jev_client import CATEGORIES  # noqa: E402

ATTACK_CATEGORIES = [c for c in CATEGORIES if c != "none"]
EVENT_FIELDS = ("ts", "method", "path", "action", "jev_category", "jev_confidence",
                "is_attack", "reason", "true_label", "true_category")


def load_log(path):
    """Read a JSONL log, skipping blank and malformed lines."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def _div(a, b):
    return a / b if b else 0.0


def _metrics(rows):
    tp = fp = fn = tn = 0
    blocked = allowed = errors = 0
    lat, cost = [], 0.0
    det = mal_scored = 0
    for r in rows:
        action, malicious = r.get("action"), r.get("true_label") == "malicious"
        if action == "block":
            blocked += 1
            tp, fp = (tp + 1, fp) if malicious else (tp, fp + 1)
        elif action == "allow":
            allowed += 1
            fn, tn = (fn + 1, tn) if malicious else (fn, tn + 1)
        elif action == "error":
            errors += 1
        if r.get("latency_ms") is not None:
            lat.append(r["latency_ms"])
        cost += r.get("cost") or 0.0
        if malicious and r.get("is_attack") is not None:
            mal_scored += 1
            det += r["is_attack"] >= 0.5
    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": _div(tp, tp + fp), "recall": _div(tp, tp + fn),
        "total_requests": len(rows), "blocked": blocked, "allowed": allowed,
        "errors": errors, "avg_latency_ms": _div(sum(lat), len(lat)),
        "total_cost": round(cost, 6), "jev_detection_recall": _div(det, mal_scored),
    }


def _timeline(rows):
    """One frame per event: cumulative blocked count per category (Jev's category)."""
    counts, frames = {}, []
    for i, r in enumerate(rows):
        cat = r.get("jev_category")
        if r.get("action") == "block" and cat in ATTACK_CATEGORIES:
            counts[cat] = counts.get(cat, 0) + 1
        frames.append({"step": i, "counts": dict(counts)})
    return frames


def _by_category(rows):
    out = {c: {"total": 0, "blocked": 0} for c in ATTACK_CATEGORIES}
    for r in rows:
        c = r.get("true_category")
        if c in out:
            out[c]["total"] += 1
            out[c]["blocked"] += r.get("action") == "block"
    return out


def build_runjson(log_lines):
    return {
        "events": [{k: r.get(k) for k in EVENT_FIELDS} for r in log_lines],
        "category_timeline": _timeline(log_lines),
        "metrics": _metrics(log_lines),
        "by_category": _by_category(log_lines),
    }


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) not in (2, 3):
        print("usage: python tools/log_to_runjson.py <log.jsonl> <out.json> [note]", file=sys.stderr)
        return 2
    out = build_runjson(load_log(argv[0]))
    if len(argv) == 3:
        out["note"] = argv[2]  # shown on the dashboard, e.g. which threshold was applied
    Path(argv[1]).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

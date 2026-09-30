"""Aggregate the proxy's JSONL decision log into a run.json for the dashboard."""
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jev_client import CATEGORIES  # noqa: E402

ATTACK_CATEGORIES = [c for c in CATEGORIES if c != "none"]
EVENT_FIELDS = ("ts", "method", "path", "action", "jev_category", "jev_confidence",
                "is_attack", "reason", "true_label", "true_category", "latency_ms")
UNLABELLED = "unlabelled_attack"  # blocked, but Jev's category was 'none' or unknown
GAP_MIN_MS, GAP_MAX_MS, GAP_FALLBACK_MS = 40, 3000, 390


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
        if r.get("action") == "block":
            cat = cat if cat in ATTACK_CATEGORIES else UNLABELLED
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


def _parse_ts(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _gaps(rows):
    """Real pacing: ms since the previous request in the same log (first = 0), clamped."""
    gaps, prev = [], None
    for i, r in enumerate(rows):
        t = _parse_ts(r.get("ts"))
        if i == 0:
            gaps.append(0)
        elif t is None or prev is None:
            gaps.append(GAP_FALLBACK_MS)
        else:
            ms = (t - prev).total_seconds() * 1000
            gaps.append(int(round(min(GAP_MAX_MS, max(GAP_MIN_MS, ms)))))
        prev = t
    return gaps


def build_waves(waves):
    """Replay several logs back to back. waves = [(label, rows), ...].

    Each event gets its wave index and real gap_ms; each wave keeps its own metrics so the
    dashboard can say where false alarms came from. Totals are over all waves.
    """
    events, all_rows, meta = [], [], []
    for wi, (label, rows) in enumerate(waves):
        meta.append({"label": label, "start": len(events), "count": len(rows), "metrics": _metrics(rows)})
        for r, gap in zip(rows, _gaps(rows)):
            e = {k: r.get(k) for k in EVENT_FIELDS}
            e["wave"], e["gap_ms"] = wi, gap
            events.append(e)
        all_rows.extend(rows)
    return {
        "events": events,
        "category_timeline": _timeline(all_rows),
        "metrics": _metrics(all_rows),
        "by_category": _by_category(all_rows),
        "waves": meta,
    }


def build_runjson(log_lines):
    return build_waves([("Run", log_lines)] if log_lines else [])


USAGE = ("usage: python tools/log_to_runjson.py <log.jsonl> <out.json> [note]\n"
         "   or: python tools/log_to_runjson.py <out.json> --wave LABEL LOG [--wave LABEL LOG ...] [--note TEXT]")


def _parse_wave_args(argv):
    out_path, waves, note, i = argv[0], [], None, 1
    while i < len(argv):
        if argv[i] == "--wave" and i + 2 < len(argv):
            waves.append((argv[i + 1], argv[i + 2]))
            i += 3
        elif argv[i] == "--note" and i + 1 < len(argv):
            note = argv[i + 1]
            i += 2
        else:
            raise ValueError(argv[i])
    if not waves:
        raise ValueError("no --wave given")
    return out_path, waves, note


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--wave" in argv:
        try:
            out_path, waves, note = _parse_wave_args(argv)
        except ValueError:
            print(USAGE, file=sys.stderr)
            return 2
        out = build_waves([(label, load_log(p)) for label, p in waves])
    elif len(argv) in (2, 3):
        out_path, note = argv[1], (argv[2] if len(argv) == 3 else None)
        out = build_runjson(load_log(argv[0]))
    else:
        print(USAGE, file=sys.stderr)
        return 2
    if note:
        out["note"] = note  # shown on the dashboard, e.g. which threshold was applied
    Path(out_path).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

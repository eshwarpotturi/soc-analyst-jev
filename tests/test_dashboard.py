import json
from pathlib import Path

DASH = Path(__file__).resolve().parent.parent / "dashboard"
METRIC_KEYS = {
    "TP", "FP", "FN", "TN", "precision", "recall", "total_requests", "blocked",
    "allowed", "errors", "avg_latency_ms", "total_cost", "jev_detection_recall",
}
EVENT_KEYS = {"method", "path", "action", "jev_category", "jev_confidence", "reason"}


def _run():
    return json.loads((DASH / "run.json").read_text())


def test_run_json_shape():
    d = _run()
    for k in ("events", "category_timeline", "metrics", "by_category"):
        assert k in d
    assert METRIC_KEYS <= set(d["metrics"])
    assert d["events"] and EVENT_KEYS <= set(d["events"][0])
    assert {"step", "counts"} <= set(d["category_timeline"][0])
    assert len(d["category_timeline"]) == len(d["events"])
    for v in d["by_category"].values():
        assert {"total", "blocked"} <= set(v)


def test_index_references_assets():
    html = (DASH / "index.html").read_text()
    assert "app.js" in html and "style.css" in html
    assert "cdnjs.cloudflare.com/ajax/libs/d3/7" in html


def test_app_uses_run_json_keys():
    js = (DASH / "app.js").read_text()
    assert "fetch('run.json')" in js or 'fetch("run.json")' in js
    for k in ("events", "category_timeline", "metrics", "by_category",
              "jev_category", "jev_confidence", "reason", "action"):
        assert k in js
    for m in METRIC_KEYS:
        assert m in js

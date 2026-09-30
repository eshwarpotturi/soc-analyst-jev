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
    assert d["waves"] and {"label", "start", "count", "metrics"} <= set(d["waves"][0])
    assert sum(w["count"] for w in d["waves"]) == len(d["events"])
    for e in d["events"]:
        assert {"wave", "gap_ms", "latency_ms"} <= set(e)


def test_run_json_has_both_real_waves():
    d = _run()
    assert len(d["waves"]) == 2
    cats = set(d["category_timeline"][-1]["counts"])
    assert {"prompt_injection", "data_exfiltration", "abuse"} <= cats


def test_layout_race_on_wall_with_kpis():
    html = (DASH / "index.html").read_text()
    assert 'id="race"' not in html  # the separate race panel is gone
    assert 'id="kpis"' in html and 'id="lanes"' in html
    assert '<option value="1" selected>' in html  # default = real time


def test_index_references_assets():
    html = (DASH / "index.html").read_text()
    assert "app.js" in html and "style.css" in html
    assert "cdnjs.cloudflare.com/ajax/libs/d3/7" in html


def test_app_uses_run_json_keys():
    js = (DASH / "app.js").read_text()
    assert "fetch('run.json')" in js or 'fetch("run.json")' in js
    for k in ("events", "category_timeline", "metrics", "by_category",
              "jev_category", "jev_confidence", "reason", "action",
              "gap_ms", "waves", "latency_ms", "unlabelled_attack"):
        assert k in js
    for m in METRIC_KEYS:
        assert m in js

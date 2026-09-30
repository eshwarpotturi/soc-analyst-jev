import pytest

import json

from tools.log_to_runjson import build_runjson, build_waves, load_log, main


def row(action, true_label, jev_category=None, is_attack=None, true_category=None,
        latency=10.0, cost=0.001, conf=0.9):
    return {
        "ts": "2026-09-29T10:00:00Z", "method": "GET", "path": "/x",
        "state_excerpt": "", "true_label": true_label, "true_category": true_category,
        "is_attack": is_attack, "jev_category": jev_category,
        "jev_confidence": None if action == "error" else conf,
        "action": action, "reason": "r", "latency_ms": latency, "cost": cost,
    }


@pytest.fixture
def log():
    return [
        row("block", "malicious", "sql_injection", 0.95, "sql_injection"),  # TP
        row("block", "benign", "xss", 0.8, "none"),                          # FP
        row("allow", "malicious", "none", 0.2, "xss"),                       # FN
        row("allow", "benign", "none", 0.05, "none"),                        # TN
        row("error", "malicious", None, None, "ssrf", latency=None, cost=0.0),
        row("block", "malicious", "sql_injection", 0.9, "sql_injection"),    # TP
    ]


def test_confusion_matrix(log):
    m = build_runjson(log)["metrics"]
    assert (m["TP"], m["FP"], m["FN"], m["TN"]) == (2, 1, 1, 1)
    assert m["total_requests"] == 6
    assert (m["blocked"], m["allowed"], m["errors"]) == (3, 2, 1)
    assert m["TP"] + m["FP"] + m["FN"] + m["TN"] + m["errors"] == m["total_requests"]


def test_precision_recall(log):
    m = build_runjson(log)["metrics"]
    assert m["precision"] == pytest.approx(2 / 3)
    assert m["recall"] == pytest.approx(2 / 3)


def test_latency_cost_and_jev_recall(log):
    m = build_runjson(log)["metrics"]
    assert m["avg_latency_ms"] == pytest.approx(10.0)  # error row's None excluded
    assert m["total_cost"] == pytest.approx(0.005)
    # malicious rows with non-null is_attack: 0.95, 0.2, 0.9 -> 2 detected of 3
    assert m["jev_detection_recall"] == pytest.approx(2 / 3)


def test_events_ordered_with_fields(log):
    ev = build_runjson(log)["events"]
    assert len(ev) == 6
    assert [e["action"] for e in ev] == [r["action"] for r in log]
    for k in ("ts", "method", "path", "action", "jev_category", "jev_confidence",
              "is_attack", "reason", "true_label", "true_category"):
        assert k in ev[0]


def test_single_category_timeline_one_series():
    lines = [row("block", "malicious", "xss", 0.9, "xss") for _ in range(3)]
    tl = build_runjson(lines)["category_timeline"]
    assert len(tl) == 3
    assert [f["step"] for f in tl] == [0, 1, 2]
    assert [f["counts"] for f in tl] == [{"xss": 1}, {"xss": 2}, {"xss": 3}]


def test_timeline_cumulative_excludes_none_and_unblocked(log):
    tl = build_runjson(log)["category_timeline"]
    assert len(tl) == len(log)
    assert tl[-1]["counts"] == {"sql_injection": 2}  # the FP xss block is not an attack blocked
    assert all("none" not in f["counts"] for f in tl)


def test_by_category(log):
    bc = build_runjson(log)["by_category"]
    assert bc["sql_injection"] == {"total": 2, "blocked": 2}
    assert bc["xss"] == {"total": 1, "blocked": 0}
    assert bc["ssrf"] == {"total": 1, "blocked": 0}
    assert "none" not in bc


def test_empty_log_zeroed():
    out = build_runjson([])
    assert out["events"] == [] and out["category_timeline"] == []
    m = out["metrics"]
    for k in ("TP", "FP", "FN", "TN", "total_requests", "blocked", "allowed", "errors"):
        assert m[k] == 0
    for k in ("precision", "recall", "avg_latency_ms", "total_cost", "jev_detection_recall"):
        assert m[k] == 0.0


def test_load_log_skips_blank_and_malformed(tmp_path):
    p = tmp_path / "l.jsonl"
    p.write_text('{"a": 1}\n\nnot json\n[1]\n{"b": 2}\n')
    assert load_log(str(p)) == [{"a": 1}, {"b": 2}]


# ---- day-2: multi-wave replay with real pacing ----

def _ts(rows, stamps):
    return [dict(r, ts=t) for r, t in zip(rows, stamps)]


def test_gap_ms_from_timestamps_clamped():
    rows = _ts([row("allow", "benign", "none", 0.1, "none")] * 4,
               ["2026-09-29T10:00:00.000+00:00", "2026-09-29T10:00:00.400+00:00",
                "2026-09-29T10:00:30.000+00:00", "2026-09-29T09:00:00.000+00:00"])
    ev = build_runjson(rows)["events"]
    assert [e["gap_ms"] for e in ev] == [0, 400, 3000, 40]


def test_gap_ms_unparseable_ts_falls_back():
    rows = _ts([row("allow", "benign", "none", 0.1, "none")] * 2, ["2026-09-29T10:00:00Z", "garbage"])
    assert build_runjson(rows)["events"][1]["gap_ms"] == 390


def test_events_carry_latency_and_wave():
    ev = build_runjson([row("allow", "benign", "none", 0.1, "none", latency=321.5)])["events"][0]
    assert ev["latency_ms"] == 321.5 and ev["wave"] == 0


def test_blocked_none_goes_to_unlabelled_lane():
    tl = build_runjson([row("block", "malicious", "none", 0.9, "xss")])["category_timeline"]
    assert tl[-1]["counts"] == {"unlabelled_attack": 1}


def test_single_log_has_one_wave():
    out = build_runjson([row("allow", "benign", "none", 0.1, "none")])
    assert [(w["start"], w["count"]) for w in out["waves"]] == [(0, 1)]


def test_build_waves_concatenates_and_tags():
    a = [row("block", "malicious", "sql_injection", 0.9, "sql_injection")] * 2
    b = [row("block", "benign", "abuse", 0.5, "none"),
         row("block", "malicious", "prompt_injection", 0.9, "prompt_injection")]
    out = build_waves([("Wave 1", a), ("Wave 2", b)])
    assert [e["wave"] for e in out["events"]] == [0, 0, 1, 1]
    assert out["events"][2]["gap_ms"] == 0  # a new wave starts fresh
    assert [(w["label"], w["start"], w["count"]) for w in out["waves"]] == [("Wave 1", 0, 2), ("Wave 2", 2, 2)]
    assert out["waves"][0]["metrics"]["FP"] == 0 and out["waves"][1]["metrics"]["FP"] == 1
    assert (out["metrics"]["TP"], out["metrics"]["FP"]) == (3, 1)
    assert out["category_timeline"][-1]["counts"] == {"sql_injection": 2, "prompt_injection": 1}  # FP excluded
    assert [f["step"] for f in out["category_timeline"]] == [0, 1, 2, 3]
    assert out["by_category"]["prompt_injection"] == {"total": 1, "blocked": 1}


def test_build_waves_empty():
    out = build_waves([])
    assert out["events"] == [] and out["waves"] == [] and out["metrics"]["total_requests"] == 0


def test_cli_waves(tmp_path):
    l1, l2, o = tmp_path / "a.jsonl", tmp_path / "b.jsonl", tmp_path / "out.json"
    l1.write_text(json.dumps(row("allow", "benign", "none", 0.1, "none")) + "\n")
    l2.write_text(json.dumps(row("block", "malicious", "abuse", 0.9, "abuse")) + "\n")
    assert main([str(o), "--wave", "A", str(l1), "--wave", "B", str(l2), "--note", "n"]) == 0
    d = json.loads(o.read_text())
    assert [w["label"] for w in d["waves"]] == ["A", "B"] and d["note"] == "n"
    assert len(d["events"]) == 2


def test_cli_legacy_positional(tmp_path):
    l1, o = tmp_path / "a.jsonl", tmp_path / "out.json"
    l1.write_text(json.dumps(row("allow", "benign", "none", 0.1, "none")) + "\n")
    assert main([str(l1), str(o), "note"]) == 0
    d = json.loads(o.read_text())
    assert len(d["waves"]) == 1 and d["note"] == "note"


def test_gap_ms_mixed_timezone_falls_back():
    rows = _ts([row("allow", "benign", "none", 0.1, "none")] * 2, ["2026-09-29T10:00:00Z", "2026-09-29T10:00:01"])
    assert build_runjson(rows)["events"][1]["gap_ms"] == 390


def test_unlabelled_log_counts_every_block():
    r = dict(row("block", None, "xss", 0.9, None))
    assert build_runjson([r])["category_timeline"][-1]["counts"] == {"xss": 1}

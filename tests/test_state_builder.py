from state_builder import build_state

MARKER = "...[truncated]"


def test_normal_request_renders_fields_and_selected_headers():
    out = build_state(
        "POST",
        "/login",
        "next=/home",
        {"Host": "example.com", "User-Agent": "curl/8", "X-Other": "zzz"},
        "user=alice",
    )
    assert "POST" in out
    assert "/login" in out
    assert "next=/home" in out
    assert "user=alice" in out
    assert "example.com" in out
    assert "curl/8" in out
    assert "zzz" not in out


def test_huge_body_is_truncated_with_marker():
    out = build_state("POST", "/x", "", {"Host": "h"}, "A" * 50_000)
    assert len(out) <= 8000
    assert MARKER in out


def test_truth_headers_never_leak():
    out = build_state(
        "GET",
        "/",
        "",
        {"Host": "h", "X-Truth-Label": "attack", "x-truth-category": "sqli"},
        "",
    )
    assert "attack" not in out
    assert "sqli" not in out
    assert "Truth" not in out and "truth" not in out

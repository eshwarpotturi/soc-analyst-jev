from jev_client import JevResult
from policy import decide


def make(is_attack, conf, category="sql_injection"):
    return JevResult(
        is_attack=is_attack,
        category=category,
        category_confidence=conf,
        category_probs={category: conf},
        cost=0.0,
    )


def test_confident_attack_blocks():
    d = decide(make(0.95, 0.90))
    assert d.action == "block"
    assert d.category == "sql_injection"
    assert "Blocked: sql_injection" in d.reason
    assert "attack=0.95" in d.reason and "confidence=0.90" in d.reason


def test_low_attack_score_allows():
    d = decide(make(0.30, 0.90, category="none"))
    assert d.action == "allow"
    assert d.category == "none"
    assert "not a confident attack" in d.reason


def test_high_attack_low_confidence_allows_conservatively():
    d = decide(make(0.85, 0.20))
    assert d.action == "allow"
    assert "low confidence" in d.reason
    assert "attack=0.85" in d.reason and "confidence=0.20" in d.reason


def test_boundary_is_inclusive():
    # Thresholds use >=, so exactly 0.80 / 0.50 blocks.
    assert decide(make(0.80, 0.50)).action == "block"


def test_just_below_boundaries_allow():
    assert decide(make(0.79, 0.90)).action == "allow"
    assert decide(make(0.90, 0.49)).action == "allow"

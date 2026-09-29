import policy
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


def test_thresholds_are_calibrated_values():
    # Calibrated on the 600-request run: every benign request scored <= 0.19,
    # every attack >= 0.23; 0.30 keeps a margin above the benign maximum.
    assert policy.BLOCK_ATTACK_THRESHOLD == 0.30
    assert policy.BLOCK_CONFIDENCE_THRESHOLD == 0.0


def test_confident_attack_blocks():
    d = decide(make(0.95, 0.90))
    assert d.action == "block"
    assert d.category == "sql_injection"
    assert "Blocked: sql_injection" in d.reason
    assert "attack=0.95" in d.reason and "confidence=0.90" in d.reason


def test_low_attack_score_allows():
    d = decide(make(0.10, 0.90, category="none"))
    assert d.action == "allow"
    assert d.category == "none"
    assert "not a confident attack" in d.reason


def test_boundary_is_inclusive():
    t = policy.BLOCK_ATTACK_THRESHOLD
    assert decide(make(t, 0.50)).action == "block"
    assert decide(make(round(t - 0.01, 2), 0.90)).action == "allow"


def test_confidence_gate_still_works_when_enabled(monkeypatch):
    monkeypatch.setattr(policy, "BLOCK_CONFIDENCE_THRESHOLD", 0.50)
    d = decide(make(0.85, 0.20))
    assert d.action == "allow"
    assert "low confidence" in d.reason
    assert decide(make(0.85, 0.50)).action == "block"

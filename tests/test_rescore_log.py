import policy
from tools.rescore_log import rescore


def row(attack, label, action="allow", conf=0.9, cat="sql_injection"):
    return {"is_attack": attack, "jev_confidence": conf, "jev_category": cat, "true_label": label,
            "action": action, "reason": "old", "cost": 0.0}


def test_rescore_applies_current_threshold():
    t = policy.BLOCK_ATTACK_THRESHOLD
    rows = [row(t + 0.05, "malicious"), row(t - 0.05, "benign", action="block")]
    out = rescore(rows)
    assert out[0]["action"] == "block" and out[0]["reason"].startswith("Blocked")
    assert out[1]["action"] == "allow"


def test_rescore_leaves_error_rows_and_input_untouched():
    err = {"is_attack": None, "jev_confidence": None, "jev_category": None, "true_label": "malicious",
           "action": "error", "reason": "Jev request failed", "cost": 0}
    original = row(0.99, "malicious", action="allow")
    out = rescore([err, original])
    assert out[0] == err
    assert original["action"] == "allow"  # input not mutated
    assert out[1]["action"] == "block"

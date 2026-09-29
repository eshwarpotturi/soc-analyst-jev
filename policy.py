"""Pure block/allow decision from a Jev classification.

Thresholds calibrated on the 600-request run (see tools/rescore_log.py): every benign
request scored <= 0.19 on "is this an attack?", every attack >= 0.23. Blocking at 0.30
caught 85/90 attacks with 0/510 false alarms while keeping a margin above the benign
maximum. The first run used 0.80 / 0.50 (53/90 caught, 0 false alarms).
The category-confidence gate is off (0.0) but kept so it can be re-enabled.
"""
from dataclasses import dataclass

from jev_client import JevResult

BLOCK_ATTACK_THRESHOLD = 0.30
BLOCK_CONFIDENCE_THRESHOLD = 0.0


@dataclass
class Decision:
    action: str  # "allow" or "block"
    category: str
    reason: str


def decide(result: JevResult) -> Decision:
    attack = result.is_attack
    conf = result.category_confidence
    if attack < BLOCK_ATTACK_THRESHOLD:
        return Decision(
            "allow", result.category,
            f"Allowed: not a confident attack (attack={attack:.2f})",
        )
    if conf < BLOCK_CONFIDENCE_THRESHOLD:
        return Decision(
            "allow", result.category,
            f"Allowed: attack suspected but low confidence (attack={attack:.2f}, confidence={conf:.2f})",
        )
    return Decision(
        "block", result.category,
        f"Blocked: {result.category} (attack={attack:.2f}, confidence={conf:.2f})",
    )

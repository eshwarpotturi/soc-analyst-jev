"""Pure block/allow decision from a Jev classification. Conservative: favors low false positives."""
from dataclasses import dataclass

from jev_client import JevResult

BLOCK_ATTACK_THRESHOLD = 0.80
BLOCK_CONFIDENCE_THRESHOLD = 0.50


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

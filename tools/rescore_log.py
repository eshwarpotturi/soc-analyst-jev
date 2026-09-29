"""Re-apply the current block policy to an existing proxy log, without calling Jev again.

Jev's raw answers (attack score, category, confidence) are already in the log, and the
block decision depends only on them, so a new threshold can be evaluated for free:

    python3 tools/rescore_log.py logs/run-XXXX.jsonl logs/run-XXXX-rescored.jsonl

Rows where Jev was unavailable ("error") are left as they are.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import policy  # noqa: E402
from jev_client import JevResult  # noqa: E402
from tools.log_to_runjson import load_log  # noqa: E402


def rescore(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows:
        r = dict(r)
        if r.get("is_attack") is not None and r.get("action") != "error":
            conf = r.get("jev_confidence") or 0.0
            d = policy.decide(JevResult(r["is_attack"], r.get("jev_category") or "none", conf, {}, r.get("cost") or 0.0))
            r["action"], r["reason"] = d.action, d.reason
        out.append(r)
    return out


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print("usage: python3 tools/rescore_log.py <in.jsonl> <out.jsonl>", file=sys.stderr)
        return 1
    rows = rescore(load_log(argv[0]))
    Path(argv[1]).write_text("".join(json.dumps(r) + "\n" for r in rows))
    blocked = sum(r["action"] == "block" for r in rows)
    print(f"Re-scored {len(rows)} rows at attack>={policy.BLOCK_ATTACK_THRESHOLD}, "
          f"confidence>={policy.BLOCK_CONFIDENCE_THRESHOLD}: {blocked} blocked -> {argv[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

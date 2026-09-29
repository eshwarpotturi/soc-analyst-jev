"""A small signature (regex) WAF, standing in for a rule-based incumbent like ModSecurity/OWASP CRS.

It matches known attack *shapes* in the request. This is what most WAFs do, and it is the
baseline Jev is compared against. Its deliberate blind spot: attacks with no fixed payload
signature -- prompt injection, data-exfiltration phrasing, business-logic abuse -- read as
ordinary text and slip through. That gap is the point of the comparison.

`classify(...)` returns (is_attack: bool, category: str). Category is best-effort and only
covers the signature-based classes; anything it does not match is called benign.
"""
import re
from urllib.parse import unquote_plus

# Signature rules per classic category. Kept intentionally in the spirit of public WAF
# rulesets: broad regexes over the decoded request text.
RULES = [
    ("sql_injection", re.compile(
        r"(?i)(\bunion\b\s+\bselect\b|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|"
        r"'\s*(or|and)\s+'|--\s|;\s*drop\s+table|\bwaitfor\s+delay\b|\bsleep\s*\()")),
    ("xss", re.compile(
        r"(?i)(<script\b|onerror\s*=|onload\s*=|onfocus\s*=|<svg\b|<iframe\b|javascript:)")),
    ("path_traversal", re.compile(
        r"(?i)(\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow|boot\.ini|win\.ini|/proc/self)")),
    ("command_injection", re.compile(
        r"(?i)(;\s*(ls|cat|id|whoami|uname|ping|sleep)\b|\|\s*(cat|id|uname|whoami)\b|"
        r"`[^`]+`|\$\([^)]+\)|&&\s*\w+)")),
    ("ssrf", re.compile(
        r"(?i)(169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost|"
        r"0\.0\.0\.0|\[::1\]|file://|gopher://|192\.168\.|10\.\d+\.)")),
    ("scanner_probe", re.compile(
        r"(?i)(/\.env\b|/\.git\b|/wp-admin\b|/phpmyadmin\b|/\.aws\b|/actuator\b|/server-status\b)")),
]

_SCANNER_UA = re.compile(r"(?i)(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster)")


def _haystack(path: str, query: str, body: str) -> str:
    # Decode once so percent-encoded payloads are matchable, as a real WAF would.
    return " ".join(unquote_plus(x or "") for x in (path, query, body))


def classify(method: str, path: str, query: str, headers: dict, body: str):
    """Return (is_attack, category) using signature rules only."""
    ua = ""
    for k, v in (headers or {}).items():
        if k.lower() == "user-agent":
            ua = v or ""
            break
    if _SCANNER_UA.search(ua):
        return True, "scanner_probe"
    text = _haystack(path, query, body)
    for category, rule in RULES:
        if rule.search(text):
            return True, category
    return False, "none"

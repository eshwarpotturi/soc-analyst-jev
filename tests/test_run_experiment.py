import json

import pytest

import run_experiment as rx
from attacker import generate_attackers
from jev_client import CATEGORIES

SECRET = "sk-or-TESTSECRET"


def test_estimate_cost_math():
    states = ["a" * 400, "b" * 800]  # 100 and 200 tokens
    est = rx.estimate_cost(states, 600)
    avg = (100 + 200) / 2 + rx.QUESTIONS_OVERHEAD_TOKENS
    assert est["avg_tokens"] == pytest.approx(avg)
    assert est["projected_tokens"] == pytest.approx(avg * 600)
    assert est["projected_usd"] == pytest.approx(avg * 600 * 0.042 / 1_000_000)


def test_estimate_cost_min_one_token_and_empty():
    est = rx.estimate_cost([""], 10)
    assert est["avg_tokens"] == 1 + rx.QUESTIONS_OVERHEAD_TOKENS
    assert rx.estimate_cost([], 10)["projected_usd"] == 0


def test_clamp_attacker_count():
    assert rx.clamp_attacker_count(500) == 100
    assert rx.clamp_attacker_count(-3) == 0
    assert rx.clamp_attacker_count(7) == 7
    assert rx.clamp_attacker_count(None) == 0


def test_parse_args_clamps_500():
    assert rx.parse_args(["--attacker-count", "500"]).attacker_count == 100


def test_check_budget_raises_over_limit():
    with pytest.raises(rx.BudgetExceeded):
        rx.check_budget({"projected_usd": 4.01})
    rx.check_budget({"projected_usd": 4.0})  # at limit is fine


def test_main_aborts_before_starting_services(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("OPENROUTER_API_KEY", SECRET)
    monkeypatch.setattr(rx, "estimate_cost", lambda states, n: {
        "avg_tokens": 1e9, "projected_tokens": 1e12, "projected_usd": 99.0})

    def boom(*a, **k):
        raise AssertionError("services must not start")

    monkeypatch.setattr(rx, "run_live", boom)
    code = rx.main(["--limit", "5"])
    out = capsys.readouterr()
    assert code != 0
    assert "abort" in (out.out + out.err).lower()
    assert "TESTSECRET" not in out.out + out.err


def test_main_requires_key(monkeypatch, capsys):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert rx.main([]) != 0
    assert "OPENROUTER_API_KEY" in capsys.readouterr().err


def test_main_ok_path_calls_run_live(monkeypatch, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", SECRET)
    called = {}
    monkeypatch.setattr(rx, "run_live", lambda args, requests: called.update(n=len(requests)) or "logs/x.jsonl")
    monkeypatch.setattr(rx, "summarize_log", lambda p: {"allow": 3, "block": 1, "error": 0})
    assert rx.main(["--limit", "10", "--attacker-count", "500"]) == 0
    assert called["n"] == 110
    out = capsys.readouterr().out
    assert "logs/x.jsonl" in out and "allow=3" in out and "block=1" in out


def test_attacker_generator_bounded_and_offline():
    reqs = generate_attackers(500)
    assert len(reqs) == 100
    assert generate_attackers(0) == []
    for r in reqs:
        assert r["true_label"] == "malicious"
        assert r["true_category"] in CATEGORIES and r["true_category"] != "none"
        assert {"method", "path", "query", "headers", "body"} <= set(r)


def test_key_hygiene(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("OPENROUTER_API_KEY", SECRET)
    log = tmp_path / "run.jsonl"
    log.write_text("\n".join(json.dumps({"action": a}) for a in ["allow", "block", "error", "allow"]) + "\n")
    est = rx.estimate_cost(["x" * 100] * 20, 600)
    print(rx.format_estimate(est, 600))
    counts = rx.summarize_log(str(log))
    assert counts == {"allow": 2, "block": 1, "error": 1}
    print(rx.format_summary(str(log), counts))
    seen = capsys.readouterr()
    blob = seen.out + seen.err + log.read_text()
    assert "sk-or-" not in blob and "TESTSECRET" not in blob

"""Run the experiment: cost guard, start target+proxy, replay corpus through the proxy."""
import argparse
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from attacker import MAX_ATTACKERS, generate_attackers
from state_builder import build_state
from tls_trust import enable_os_trust

# Trust the OS cert store (corporate TLS-inspecting proxies); no-op otherwise.
enable_os_trust()

CORPUS_PATH = Path(__file__).parent / "fixtures" / "corpus.jsonl"
USD_PER_M_INPUT_TOKENS = 0.042
QUESTIONS_OVERHEAD_TOKENS = 250
MAX_USD = 4.00
SAMPLE_SIZE = 20


class BudgetExceeded(Exception):
    pass


def clamp_attacker_count(n) -> int:
    return max(0, min(int(n or 0), MAX_ATTACKERS))


def estimate_cost(states: list[str], total_count: int) -> dict:
    if not states:
        return {"avg_tokens": 0.0, "projected_tokens": 0.0, "projected_usd": 0.0}
    per = [max(1, len(s) / 4) + QUESTIONS_OVERHEAD_TOKENS for s in states]
    avg = sum(per) / len(per)
    projected = avg * total_count
    return {"avg_tokens": avg, "projected_tokens": projected,
            "projected_usd": projected * USD_PER_M_INPUT_TOKENS / 1_000_000}


def check_budget(est: dict, limit: float = MAX_USD) -> None:
    if est["projected_usd"] > limit:
        raise BudgetExceeded(
            f"projected cost ${est['projected_usd']:.4f} exceeds the ${limit:.2f} limit")


def format_estimate(est: dict, count: int) -> str:
    return (f"Cost estimate: {count} requests, ~{est['avg_tokens']:.0f} input tokens each, "
            f"~{est['projected_tokens']:,.0f} tokens total, projected ${est['projected_usd']:.4f} "
            f"(limit ${MAX_USD:.2f})")


def summarize_log(path: str) -> dict:
    counts = {"allow": 0, "block": 0, "error": 0}
    p = Path(path)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip():
                action = json.loads(line).get("action")
                if action in counts:
                    counts[action] += 1
    return counts


def format_summary(path: str, counts: dict) -> str:
    return (f"Log: {path}\nSummary: allow={counts['allow']} block={counts['block']} "
            f"error={counts['error']}")


def load_corpus(limit=None) -> list[dict]:
    rows = [json.loads(l) for l in CORPUS_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
    return rows[:limit] if limit else rows


def _state(r: dict) -> str:
    return build_state(r["method"], r["path"], r.get("query", ""), r.get("headers", {}), r.get("body", ""))


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--attacker-count", type=int, default=0)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--target-port", type=int, default=8000)
    ap.add_argument("--proxy-port", type=int, default=8080)
    args = ap.parse_args(argv)
    args.attacker_count = clamp_attacker_count(args.attacker_count)
    return args


def _wait_port(host, port, timeout=20.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"service on {host}:{port} did not start")


def run_live(args, requests: list[dict]) -> str:
    """Start target+proxy, replay requests through the proxy. Returns the log path. (Live-only.)"""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = str(Path("logs") / f"run-{ts}.jsonl")
    Path("logs").mkdir(exist_ok=True)
    env = dict(os.environ,
               TARGET_BASE_URL=f"http://{args.host}:{args.target_port}",
               PROXY_LOG_PATH=log_path)
    py = sys.executable
    procs = []
    try:
        for app, port in (("target_server:app", args.target_port), ("proxy:app", args.proxy_port)):
            procs.append(subprocess.Popen(
                [py, "-m", "uvicorn", app, "--host", args.host, "--port", str(port),
                 "--log-level", "warning"], env=env))
            _wait_port(args.host, port)
        base = f"http://{args.host}:{args.proxy_port}"
        with httpx.Client(base_url=base, timeout=60.0) as client:
            for r in requests:
                headers = dict(r.get("headers") or {})
                headers["X-Truth-Label"] = r["true_label"]
                headers["X-Truth-Category"] = r["true_category"]
                url = r["path"] + (f"?{r['query']}" if r.get("query") else "")
                try:
                    client.request(r["method"], url, headers=headers,
                                   content=(r.get("body") or "").encode("utf-8"))
                except httpx.HTTPError as exc:
                    print(f"request failed: {type(exc).__name__}", file=sys.stderr)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
    return log_path


def main(argv=None) -> int:
    args = parse_args(argv)
    if not os.environ.get("OPENROUTER_API_KEY"):
        print("OPENROUTER_API_KEY is not set; set it in the environment and retry.", file=sys.stderr)
        return 1
    requests = load_corpus(args.limit) + generate_attackers(args.attacker_count)
    step = max(1, len(requests) // SAMPLE_SIZE)
    sample = [_state(r) for r in requests[::step][:SAMPLE_SIZE]]
    est = estimate_cost(sample, len(requests))
    print(format_estimate(est, len(requests)))
    try:
        check_budget(est)
    except BudgetExceeded as exc:
        print(f"Aborting before any spend: {exc}", file=sys.stderr)
        return 2
    log_path = run_live(args, requests)
    print(format_summary(log_path, summarize_log(log_path)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

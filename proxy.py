"""Reverse proxy: classify each request with Jev, block confident attacks, forward the rest.

Fail-open: if Jev is unavailable the request is still forwarded and logged as "error".
"""
import json
import os
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse
from html import escape
from urllib.parse import unquote_plus

from jev_client import JevUnavailable, classify
from policy import decide
from state_builder import build_state
from tls_trust import enable_os_trust

# The Jev HTTPS call happens in THIS process. Trust the OS cert store so a
# corporate TLS-inspecting proxy doesn't cause CERTIFICATE_VERIFY_FAILED.
enable_os_trust()

DEFAULT_TARGET = "http://127.0.0.1:8000"
DEFAULT_LOG_PATH = "logs/proxy.jsonl"
STATE_EXCERPT_CHARS = 200
TRUTH_HEADERS = ("x-truth-label", "x-truth-category")
# Not forwarded to the target (hop-by-hop, or recomputed by httpx for the new request).
REQUEST_DROP = {"host", "content-length", "connection", "transfer-encoding"}
# Not copied from the target's response (httpx already decoded the body).
RESPONSE_DROP = {"content-length", "content-encoding", "transfer-encoding", "connection"}

_client: httpx.Client | None = None
_log_lock = threading.Lock()


@asynccontextmanager
async def lifespan(_app):
    global _client
    _client = httpx.Client(timeout=10.0)
    try:
        yield
    finally:
        _client.close()
        _client = None


app = FastAPI(lifespan=lifespan)


def forward(method: str, path: str, query: str, headers: dict, body: bytes) -> Response:
    base = os.environ.get("TARGET_BASE_URL", DEFAULT_TARGET).rstrip("/")
    url = f"{base}{path}" + (f"?{query}" if query else "")
    fwd_headers = {k: v for k, v in headers.items() if k.lower() not in REQUEST_DROP}
    client = _client or httpx.Client(timeout=10.0)
    try:
        resp = client.request(method, url, headers=fwd_headers, content=body)
    except httpx.HTTPError as exc:
        return JSONResponse({"error": f"target unreachable: {type(exc).__name__}"}, status_code=502)
    finally:
        if client is not _client:
            client.close()
    out_headers = {k: v for k, v in resp.headers.items() if k.lower() not in RESPONSE_DROP}
    return Response(content=resp.content, status_code=resp.status_code, headers=out_headers)


def blocked_page(method: str, path: str, query: str, category: str,
                 attack: float, confidence: float) -> HTMLResponse:
    """Browser-friendly 403 shown when Jev blocks a page load (API clients still get JSON)."""
    req = escape(f"{method} {path}" + (f"?{unquote_plus(query)}" if query else ""))
    label = escape((category or "attack").replace("_", " "))
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Blocked by Jev</title>
<style>
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;
background:#0b0f14;color:#d5dde8;font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}}
.card{{max-width:560px;width:100%;background:#121923;border:1px solid #3a1d24;border-left:4px solid #ff4d5e;border-radius:10px;padding:24px}}
h1{{margin:0 0 6px;color:#ff4d5e;font-size:24px}}
.tag{{display:inline-block;background:#2a1218;color:#ff8a95;border-radius:999px;padding:3px 12px;font-weight:600}}
dl{{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;margin:16px 0}}
dt{{color:#7d8b9e}}dd{{margin:0;font-variant-numeric:tabular-nums}}
code{{display:block;background:#0e141c;border:1px solid #1f2a38;border-radius:6px;padding:10px;word-break:break-all;color:#e0b341}}
a{{color:#4cc9f0}}
</style></head><body><div class="card">
<h1>Blocked by Jev</h1>
<p>This request looked like an attack, so it never reached the website.</p>
<span class="tag">{label}</span>
<dl><dt>Attack probability</dt><dd>{attack:.0%}</dd><dt>Category confidence</dt><dd>{confidence:.0%}</dd></dl>
<code>{req}</code>
<p><a href="/shop">Back to the shop</a></p>
</div></body></html>"""
    return HTMLResponse(html, status_code=403)


def write_log(entry: dict) -> None:
    path = Path(os.environ.get("PROXY_LOG_PATH", DEFAULT_LOG_PATH))
    line = json.dumps(entry) + "\n"
    with _log_lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(line)


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def handle(request: Request, full_path: str) -> Response:
    raw_body = await request.body()
    # classify/forward use blocking httpx; keep them off the event loop.
    # Forward the RAW (still percent-encoded) path so the target sees exactly the
    # request that was classified; the decoded path is only for state/log.
    raw_path = request.scope.get("raw_path")
    raw_path = raw_path.decode("latin-1").split("?", 1)[0] if raw_path else request.url.path
    return await run_in_threadpool(
        process, request.method, request.scope["path"],
        request.scope["query_string"].decode("latin-1"),
        dict(request.headers), raw_body, raw_path,
    )


def process(method: str, path: str, query: str, headers: dict, raw_body: bytes,
            raw_path: str | None = None) -> Response:
    fwd_path = raw_path if raw_path is not None else path
    truth_label = headers.get("x-truth-label")
    truth_category = headers.get("x-truth-category")
    # Ground truth is for the log only: never shown to Jev or the target.
    headers = {k: v for k, v in headers.items() if k.lower() not in TRUTH_HEADERS}

    try:
        state = build_state(method, path, query, headers, raw_body.decode("utf-8", errors="replace"))
    except Exception:
        state = f"{method} {path}"  # fail-open: never 500 on a state-building fault

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": method,
        "path": path,
        "state_excerpt": state[:STATE_EXCERPT_CHARS],
        "true_label": truth_label,
        "true_category": truth_category,
        "is_attack": None,
        "jev_category": None,
        "jev_confidence": None,
        "action": None,
        "reason": None,
        "latency_ms": None,
        "cost": 0,
    }

    start = time.perf_counter()
    try:
        result = classify(state, client=_client)
        entry["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)
        decision = decide(result)
    except Exception as exc:  # JevUnavailable or any other classification-side fault: fail open
        if entry["latency_ms"] is None:
            entry["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)
        entry["action"] = "error"
        entry["reason"] = str(exc) if isinstance(exc, JevUnavailable) else f"{type(exc).__name__}: {exc}"
        response = forward(method, fwd_path, query, headers, raw_body)
    else:
        entry.update(
            is_attack=result.is_attack,
            jev_category=result.category,
            jev_confidence=result.category_confidence,
            action=decision.action,
            reason=decision.reason,
            cost=result.cost,
        )
        if decision.action == "block":
            if "text/html" in headers.get("accept", ""):
                response = blocked_page(method, path, query, decision.category,
                                        result.is_attack, result.category_confidence)
            else:
                response = JSONResponse(
                    {"blocked": True, "category": decision.category, "reason": decision.reason},
                    status_code=403,
                )
        else:
            response = forward(method, fwd_path, query, headers, raw_body)

    write_log(entry)
    return response


# SOC Analyst Agent (Jev) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A reverse proxy that screens every HTTP request through Jev (allow/block), logs each decision, and a static GitHub Pages dashboard that *replays* the logged run as an animated stream, red-flag log, category bar-chart race, and an accuracy panel.

**Architecture:** Two strictly separated halves. (1) The **experiment** runs once, offline, on the user's Windows machine: a traffic generator hits a reverse proxy, the proxy asks Jev to classify each request and forwards or blocks it, and every decision is appended to a JSONL log. (2) The **dashboard** is a static page that reads *only* that log and replays it — it never calls Jev. This guarantees the demo always works and costs nothing to show.

**Tech Stack:** Python 3.11 (FastAPI + Uvicorn for target & proxy, httpx for Jev + forwarding, pytest for tests), vanilla HTML/CSS/JS + D3 v7 for the dashboard, GitHub Pages for hosting.

**Spec:** `docs/plans/2026-09-29-soc-analyst-jev.md` (this file; derived from the Anand ↔ Eswar intro call, `introcall.md`).

## Global Constraints

- Jev endpoint: `POST https://openrouter.ai/api/v1/systemone`; model `typesafe/jev-1.13`; auth `Authorization: Bearer $OPENROUTER_API_KEY`.
- The OpenRouter API key is read from the `OPENROUTER_API_KEY` environment variable ONLY. Never written to any file, committed, logged, or printed.
- Jev budget ceiling: **$5**. A pre-flight cost estimate must print before the full run; the runner aborts if projected cost > $4.
- The dashboard must run entirely client-side from static files (`index.html` + `run.json`) with no build step and no network calls except loading D3 from a CDN — it must work when served by GitHub Pages.
- Experiment and dashboard never share a process. The dashboard's only input is a committed log file.
- Malicious test traffic lives in a fixtures file (`fixtures/corpus.jsonl`) built from public, well-known security-testing signatures (OWASP-style). It is used solely to test a defensive classifier.
- Two traffic sources, both conservative: a labelled static corpus (default) and a bounded attacker-generator (off unless `--attacker-count N` is passed, capped at 100).
- Decision policy: **block** only on a confident attack verdict (`is_attack` noul ≥ 0.80 **and** choice confidence ≥ 0.50); otherwise forward. This favours low false positives ("conservative").

## Review Focus

1. **Jev call fails or times out mid-run** (network blip, 429, 5xx) — the proxy must fail *open* (forward + log an `error` decision), never crash the run; a returning viewer expects a complete log, not a half-run.
2. **Malformed / oversized request body** (binary, >32K-token state) — state builder must truncate safely so the Jev call never exceeds context or throws; oversized input is a normal thing an internet-facing proxy meets.
3. **Empty or single-category log feeding the bar-chart race** — the D3 race must render with 0 or 1 category without dividing by zero or drawing off-canvas.
4. **Cost overrun** — the runner must estimate before spending and stop before the $5 key is drained; a person expects the tool to protect the budget, not discover the overrun afterward.
5. **Key accidentally present in output** — logs, console, and `run.json` must be asserted free of any `sk-or-` / bearer token; a person expects a shareable log to be safe to commit.

---

## File Structure

- `target_server.py` — dummy target app (login/search/profile/file routes). One responsibility: be something to attack.
- `jev_client.py` — thin Jev wrapper: build questions, POST, parse `answers`/`usage`. Isolated so it's the only file that knows Jev's wire format.
- `state_builder.py` — turn a raw request into the Jev `state` string (+ truncation).
- `policy.py` — pure function: Jev answer → `allow`/`block`/`error` + reason. No I/O, easy to test.
- `proxy.py` — FastAPI reverse proxy wiring state_builder + jev_client + policy + forwarding + logging.
- `fixtures/corpus.jsonl` — labelled requests (~85% benign, ~15% malicious across categories).
- `attacker.py` — optional bounded generator (uses the coding-agent model, not Jev).
- `run_experiment.py` — the one command the user runs on Windows: cost estimate → send corpus at proxy → write `logs/run-<ts>.jsonl`.
- `logs/` — run output (git-ignored except a sample).
- `dashboard/index.html`, `dashboard/app.js`, `dashboard/style.css`, `dashboard/run.json` — static replay.
- `tools/log_to_runjson.py` — convert a raw JSONL log into the dashboard's `run.json` (aggregates + accuracy).
- `tools/make_mock_log.py` — synth a realistic mock log so the dashboard is fully testable here without Jev.
- `tests/` — pytest suite mirroring the modules above.

---

## Task 1: Target server

**Files:** Create `target_server.py`; Test `tests/test_target_server.py`.

**Interfaces:** Produces a FastAPI `app` serving `GET /`, `POST /login`, `GET /search`, `GET /profile`, `GET /files`.

- [ ] **Step 1: Write failing test** — assert `GET /` returns 200 and `POST /login` with JSON returns 200/401.
- [ ] **Step 2: Run test, verify it fails** (`pytest tests/test_target_server.py -v`).
- [ ] **Step 3: Implement** minimal routes that echo received params in a JSON body.
- [ ] **Step 4: Run test, verify pass.**
- [ ] **Step 5: Commit** (`feat: dummy target server`).

## Task 2: State builder (+ truncation)

**Files:** Create `state_builder.py`; Test `tests/test_state_builder.py`.

**Interfaces:** Produces `build_state(method: str, path: str, query: str, headers: dict, body: str) -> str`. Output is a compact human-readable block; truncates to ≤ 8000 chars (well under Jev's 32K-token limit). **Consumes:** nothing.

- [ ] **Step 1: Write failing tests** — (a) a normal request renders method/path/query/body; (b) a 50,000-char body is truncated to ≤ 8000 chars and marked `…[truncated]`. *(Covers Review Focus #2.)*
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the formatter + truncation.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat: request state builder with truncation`).

## Task 3: Jev client

**Files:** Create `jev_client.py`; Test `tests/test_jev_client.py`.

**Interfaces:** Produces `classify(state: str, *, client=None) -> JevResult` where `JevResult = {is_attack: float, category: str, category_confidence: float, category_probs: dict, cost: float}`. Builds body:
```json
{"model":"typesafe/jev-1.13","state":"<state>",
 "questions":{
   "is_attack":{"type":"noul","instructions":"Is this HTTP request a hacking or exploitation attempt against the server?"},
   "category":{"type":"choice","instructions":"Which attack technique best matches this request? Choose 'none' if it is a normal, benign request.",
     "criteria":{"none":"Legitimate, benign traffic","sql_injection":"...","xss":"...","path_traversal":"...","command_injection":"...","ssrf":"...","auth_bruteforce":"...","scanner_probe":"...","other_exploit":"Some other exploit attempt"}}}}
```
Parses `answers.is_attack.noul`, `answers.category.choice/.confidence/.probabilities`, `usage.cost`. **Consumes:** state from Task 2.

- [ ] **Step 1: Write failing tests** using a mocked httpx client returning a canned Jev response — assert fields parse correctly; assert on a timeout/5xx it raises `JevUnavailable`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** with `OPENROUTER_API_KEY` from env; raise `JevUnavailable` on network/HTTP error.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat: Jev system-one client`).

## Task 4: Policy (pure decision)

**Files:** Create `policy.py`; Test `tests/test_policy.py`.

**Interfaces:** Produces `decide(result: JevResult) -> Decision` where `Decision = {action: 'allow'|'block', category: str, reason: str}`. **Consumes:** `JevResult` from Task 3.

- [ ] **Step 1: Write failing tests** — noul 0.95 + conf 0.9 → `block`; noul 0.3 → `allow`; noul 0.85 + conf 0.2 → `allow` (uncertain → conservative).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the threshold rule (0.80 / 0.50) with a human-readable reason string.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat: conservative block/allow policy`).

## Task 5: Reverse proxy (fail-open + logging)

**Files:** Create `proxy.py`; Test `tests/test_proxy.py`.

**Interfaces:** FastAPI `app` catching all methods/paths. Per request: build state → `classify` → `decide` → if `block` return 403 JSON `{blocked, category, reason}`, else forward to target via httpx and return its response. Appends one JSONL line: `{ts, method, path, state_excerpt, true_label, true_category, is_attack, jev_category, jev_confidence, action, latency_ms, cost}`. On `JevUnavailable`: action `error`, **forward anyway**. **Consumes:** Tasks 2–4.

- [ ] **Step 1: Write failing tests** — (a) a benign request is forwarded (200) and logged `allow`; (b) a flagged request returns 403 and logged `block`; (c) when `classify` raises `JevUnavailable`, request is still forwarded and logged `error`. *(Covers Review Focus #1.)*
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** proxy with async httpx forwarding + JSONL logger.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat: Jev reverse proxy with fail-open logging`).

## Task 6: Labelled corpus

**Files:** Create `fixtures/corpus.jsonl`; Test `tests/test_corpus.py`.

**Interfaces:** Produces ~600 lines, each `{method, path, query, headers, body, true_label: 'benign'|'malicious', true_category}`. ~85% benign, ~15% malicious spread across the Task-3 categories. Malicious lines use canonical public detection signatures.

- [ ] **Step 1: Write failing test** — every line parses; label distribution ≈ 85/15; every `true_category` is in the known set.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Create** the corpus generator/fixture.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat: labelled benign/malicious request corpus`).

## Task 7: Experiment runner (cost guard + key hygiene)

**Files:** Create `run_experiment.py`; Test `tests/test_run_experiment.py`.

**Interfaces:** CLI `python run_experiment.py [--attacker-count N]`. Steps: estimate cost (sample 20 states, measure tokens, extrapolate); print estimate; abort if > $4; else start target + proxy, replay corpus (+ up to N attacker requests, N≤100) through the proxy, write `logs/run-<ts>.jsonl`. **Consumes:** Tasks 1–6, and `attacker.py` (Task 7a, folded in).

- [ ] **Step 1: Write failing tests** — estimator math on a fixed sample; runner aborts when projected cost > $4; `--attacker-count 500` is clamped to 100.  *(Covers Review Focus #4.)*
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** runner + estimator + bounded attacker generator.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Add** a key-hygiene test: run produces no substring matching `sk-or-` in log/stdout. *(Covers Review Focus #5.)*
- [ ] **Step 6: Commit** (`feat: experiment runner with cost guard`).

## Task 8: Log → run.json (accuracy aggregation)

**Files:** Create `tools/log_to_runjson.py`, `tools/make_mock_log.py`; Test `tests/test_log_to_runjson.py`.

**Interfaces:** Produces `build_runjson(log_lines) -> dict` with `events[]` (ordered, for the stream), `category_timeline` (cumulative counts per category per step, for the race), and `metrics` (TP/FP/FN/TN vs `true_label`, precision, recall, avg latency, total cost). **Consumes:** the JSONL log from Task 5/7.

- [ ] **Step 1: Write failing tests** — confusion-matrix counts on a hand-built 6-line log; precision/recall math; a single-category timeline renders one series; an empty log yields zeroed metrics without error. *(Covers Review Focus #3.)*
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** aggregator + mock-log generator.
- [ ] **Step 4: Run, verify pass; generate `dashboard/run.json` from a mock log.**
- [ ] **Step 5: Commit** (`feat: log aggregation to dashboard run.json`).

## Task 9: Dashboard replay (D3, static)

**Files:** Create `dashboard/index.html`, `dashboard/app.js`, `dashboard/style.css`; Test `tests/test_dashboard.py` (loads `run.json`, asserts shape the JS relies on) + manual visual check.

**Interfaces:** Loads `run.json`; renders four panels — (1) request stream (rapid green ticks, red for blocked), (2) red-flag log (category + Jev reason + probability), (3) category bar-chart race, (4) accuracy panel (precision/recall/caught/missed/false-alarms/avg latency/total cost). Controls: play / pause / speed. **Consumes:** `run.json` from Task 8.

- [ ] **Step 1: Write failing test** — `run.json` has the keys `app.js` reads (`events`, `category_timeline`, `metrics`).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the page against the mock `run.json`.
- [ ] **Step 4: Run test + open the page locally to confirm the race animates, stream flows, red log fills, metrics show.**
- [ ] **Step 5: Commit** (`feat: static replay dashboard`).

## Task 10: Package & GitHub Pages

**Files:** Create `README.md`, `requirements.txt`, `.gitignore`, `.github/workflows/pages.yml` (or Pages-from-`/dashboard`), sample `logs/sample-run.jsonl`.

- [ ] **Step 1:** Write README: one-command Windows run, env-var setup, how to regenerate `run.json`, how Pages serves `/dashboard`.
- [ ] **Step 2:** `.gitignore` real logs; keep one sample.
- [ ] **Step 3:** Configure Pages to serve the `dashboard/` folder.
- [ ] **Step 4:** Verify the published URL renders the mock run.
- [ ] **Step 5: Commit** (`chore: docs + GitHub Pages hosting`).

---

## Execution split (because this chat isn't linked to the Windows PC)

- **Built & tested here (no Jev needed):** Tasks 1–6, 8–10 against a **mock log** from `tools/make_mock_log.py`. The dashboard is fully working before Jev is ever called.
- **Run by Eswar on Windows (Task 7, real Jev):** `set OPENROUTER_API_KEY=...` then `python run_experiment.py`. Produces the real log → run `tools/log_to_runjson.py` → commit `run.json` → Pages updates.
- If this chat is later linked to the PC via the desktop app, the real run can be executed from here instead.

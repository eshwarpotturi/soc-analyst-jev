# Dashboard Day-2 Changes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rework the replay dashboard per Anand's day-2 review so everything that matters fits one laptop screen: the bar-chart race lives *on the castle wall*, three KPI cards sit on top, semantic (AI-era) attacks appear as their own race bars, and 1x plays at the real logged speed.

**Architecture:** Python aggregation (`tools/log_to_runjson.py`) gains multi-wave input: several real logs are concatenated as named "waves", each event carries its real pacing (`gap_ms`) and `latency_ms`, and per-wave metrics are computed. The static dashboard reads the richer `run.json` and draws the race as lanes on the castle wall (DOM overlay positioned over the canvas wall), paces spawns from `gap_ms`, and shows a banner between waves. No new Jev calls.

**Tech Stack:** Python 3 + pytest; vanilla JS + D3 v7 (already loaded) + canvas; GitHub Pages (unchanged, deploys `dashboard/` from `main`).

**Spec:** `day2.md` (Anand ↔ Eswar review call, 2026-09-30) plus decisions confirmed in chat: KPI cards show combined live totals with a note locating the false alarms (option A); default speed = real time; semantic categories as three separate bars.

## Global Constraints

- All work on branch `dashboard`, cut from `main` @ `3475ff9`. Nothing merged to `main` by Claude.
- Dashboard stays static: `index.html` + `app.js` + `style.css` + `run.json` (+ `compare.json`), D3 from cdnjs only.
- Target: everything above the fold on a laptop viewport ≈ 1440×800 (1440×900 screen minus browser chrome). No scrolling needed to see KPI cards, castle and race.
- 1x = real pacing from logged timestamps (median gap ≈ 376 ms, mean ≈ 397 ms). Default speed is 1x.
- Data is real Jev output only: wave 1 = `logs/run-20260929T164714Z.jsonl` (800 req), wave 2 = `logs/run-20260929T195753Z.jsonl` (84 semantic req). Nothing re-scored.
- KPI cards: Attacks caught (TP / attacks seen), False alarms (FP, with note naming which wave they came from), Avg decision latency (running mean ms).
- Semantic categories shown as three lanes: prompt injection, data exfiltration, business-logic abuse.
- The WAF-vs-Jev comparison section stays on the same page, below analytics.
- Blocked requests that Jev labelled `none` go to an `unlabelled_attack` lane (never display "none" as an attack).
- Existing 76 tests keep passing; `run.json` keeps every key the old tests assert.

## Review Focus

1. **Arrow lands in a lane that has since re-ranked** — target y is re-read from the lane's current position every frame, so the arrow always hits its own bar.
2. **Wave boundary** — spawning pauses for the banner, then resumes; restart mid-banner must clear the banner and pause state.
3. **Short viewport (≤ 620 px tall) or narrow screen** — lanes shrink to a minimum height and label font; below 700 px wide the lanes keep working with shorter labels; no lane overflows the wall.
4. **Timestamp gaps that are huge or negative** (clock jumps, gaps between separate runs) — `gap_ms` clamped to [40, 3000]; first event of each wave gets 0.
5. **Old single-log CLI** (`log_to_runjson.py <log> <out> [note]`) still works and still produces a valid single-wave `run.json`.

---

## File Structure

- Modify `tools/log_to_runjson.py` — add `gap_ms`, `latency_ms`, `wave` per event; `unlabelled_attack` in the timeline; `build_waves([(label, rows), ...])`; `waves[]` with per-wave metrics; `--wave LABEL LOG` CLI.
- Modify `tests/test_log_to_runjson.py` — new tests for the above.
- Modify `tests/test_dashboard.py` — assert the new keys the JS relies on.
- Regenerate `dashboard/run.json` from the two real logs.
- Modify `dashboard/index.html` — stage layout (header, KPI row, siege fills rest), remove race panel, speed options.
- Modify `dashboard/app.js` — KPI cards, wall-lane race, gap-based pacing, wave banner, lane-targeted arrows.
- Modify `dashboard/style.css` — stage flex layout, KPI cards, lanes, banner.
- Modify `README.md` — how to regenerate the two-wave `run.json`.

---

### Task 1: Multi-wave run.json with real pacing

**Files:** Modify `tools/log_to_runjson.py`, `tests/test_log_to_runjson.py`, `tests/test_dashboard.py`; regenerate `dashboard/run.json`.

**Interfaces:**
- Produces `build_runjson(rows) -> dict` (unchanged signature; now also emits `waves` with one entry and per-event `wave`, `gap_ms`, `latency_ms`).
- Produces `build_waves(waves: list[tuple[str, list[dict]]]) -> dict` → `{events, category_timeline, metrics, by_category, waves: [{label, start, count, metrics}]}`.
- `category_timeline` counts blocked events by Jev category; blocked with category not in the attack set → `"unlabelled_attack"`.

- [ ] **Step 1: Write failing tests**

```python
def test_gap_ms_from_timestamps_clamped():
    rows = [dict(row("allow", "benign", "none", 0.1, "none"), ts=t) for t in
            ("2026-09-29T10:00:00.000+00:00", "2026-09-29T10:00:00.400+00:00",
             "2026-09-29T10:00:30.000+00:00", "2026-09-29T09:00:00.000+00:00")]
    ev = build_runjson(rows)["events"]
    assert [e["gap_ms"] for e in ev] == [0, 400, 3000, 40]

def test_blocked_none_goes_to_unlabelled_lane():
    tl = build_runjson([row("block", "malicious", "none", 0.9, "xss")])["category_timeline"]
    assert tl[-1]["counts"] == {"unlabelled_attack": 1}

def test_build_waves_concatenates_and_tags():
    a = [row("block", "malicious", "sql_injection", 0.9, "sql_injection")] * 2
    b = [row("block", "benign", "abuse", 0.5, "none"), row("block", "malicious", "prompt_injection", 0.9, "prompt_injection")]
    out = build_waves([("Wave 1", a), ("Wave 2", b)])
    assert [e["wave"] for e in out["events"]] == [0, 0, 1, 1]
    assert out["events"][2]["gap_ms"] == 0
    assert [(w["label"], w["start"], w["count"]) for w in out["waves"]] == [("Wave 1", 0, 2), ("Wave 2", 2, 2)]
    assert out["waves"][0]["metrics"]["FP"] == 0 and out["waves"][1]["metrics"]["FP"] == 1
    assert out["metrics"]["TP"] == 3 and out["metrics"]["FP"] == 1
    assert out["category_timeline"][-1]["counts"] == {"sql_injection": 2, "abuse": 1, "prompt_injection": 1}
    assert [f["step"] for f in out["category_timeline"]] == [0, 1, 2, 3]

def test_single_log_has_one_wave():
    out = build_runjson([row("allow", "benign", "none", 0.1, "none")])
    assert len(out["waves"]) == 1 and out["waves"][0]["count"] == 1

def test_cli_waves(tmp_path):
    ...  # writes two logs, runs main([out, "--wave", "A", l1, "--wave", "B", l2, "--note", "n"]), checks waves + note
```

Dashboard shape test additions: `waves` in run.json; each event has `wave`, `gap_ms`, `latency_ms`; app.js references `gap_ms`, `waves`, `latency_ms`.

- [ ] **Step 2: Run** `python3 -m pytest tests/test_log_to_runjson.py tests/test_dashboard.py -q` → FAIL.
- [ ] **Step 3: Implement** (`_gaps(rows)` parses ISO ts, first=0, clamp [40, 3000]; unparseable → 390; `build_waves` concatenates, computes per-wave metrics with `_metrics`, overall timeline over concatenated rows; CLI: `log_to_runjson.py OUT --wave LABEL LOG [--wave LABEL LOG ...] [--note TEXT]`, old 2/3-positional form kept).
- [ ] **Step 4: Regenerate** `dashboard/run.json`:

```bash
python3 tools/log_to_runjson.py dashboard/run.json \
  --wave "Wave 1 · classic web attacks" logs/run-20260929T164714Z.jsonl \
  --wave "Wave 2 · AI-era semantic attacks" logs/run-20260929T195753Z.jsonl \
  --note "Two real Jev runs replayed back to back. Wave 1: 800 new requests (680 legitimate, 120 classic attacks), block threshold 0.30. Wave 2: a separate run of 84 requests against an app with an AI assistant (60 legitimate, 24 semantic attacks: prompt injection, data exfiltration, business-logic abuse). Real Jev verdicts, nothing re-scored."
```

- [ ] **Step 5: Run full suite → PASS (dashboard JS test may still fail until Task 2; mark those asserts in Task 2).** Commit `feat(data): multi-wave run.json with real pacing and per-wave metrics`.

### Task 2: Dashboard — KPI cards, castle-wall race, real-time 1x, wave banner

**Files:** Modify `dashboard/index.html`, `dashboard/app.js`, `dashboard/style.css`, `README.md`.

**Interfaces:** Consumes Task 1 `run.json` (`events[].wave/gap_ms/latency_ms`, `waves[]`, `category_timeline`, `metrics`).

Behaviour:
- **Layout:** `.stage` = 100svh flex column: header → progress → KPI row → `#siege` (flex:1, min 380px). Analytics grid (accuracy full width, stream + red-flag log) and the semantic comparison follow below.
- **KPI row:** three cards. *Attacks caught* `TP / attacks judged` + percent. *False alarms* `FP` + sub "of N legitimate" and, when FP>0, which wave(s) they came from. *Avg decision latency* running mean of `latency_ms` ("per request · real Jev round-trip").
- **Wall race:** castle widened to ~42% of the canvas. The wall face between battlements and the gate is split into one lane per category (all categories in the timeline + `unlabelled_attack`), sorted by count desc then name. Each lane is an absolutely positioned DOM row over the wall: rank, label, bar (width ∝ count / max), count, ▲ when it just moved up (1.2 s), flash on hit (red; amber when the block was a false alarm). Rows move with a CSS `transform` transition. Wave-2 categories carry a small "AI" tag.
- **Arrows:** blocked arrows fly to the wall edge at their lane's *current* y (re-read each frame); allowed/error go through the gate (now at the bottom of the wall below the lanes). The old floating "✖ category" labels are removed; false alarms keep a small amber "false alarm" label.
- **Pacing:** next spawn waits `events[i].gap_ms / speed`. Speed options: `1x · real time` (default), 2x, 5x, 10x, 25x. Flight time stays constant (600 ms) so land order = log order.
- **Wave banner:** before the first event of wave ≥ 2, spawning holds 2.8 s while a centred banner shows the wave label and "separate run · N requests"; restart clears it.
- **Done card:** mentions both waves' totals.

- [ ] **Step 1:** Update `tests/test_dashboard.py` asserts (race panel gone: `id="race"` absent; `id="kpis"` present; app.js uses `gap_ms`, `waves`, `latency_ms`, `unlabelled_attack`). Run → FAIL.
- [ ] **Step 2:** Implement HTML/CSS/JS.
- [ ] **Step 3:** Run tests → PASS. Serve `dashboard/` locally and open at 1440×800: confirm KPI cards + castle + all lanes visible with no scroll, lanes re-rank, wave banner shows, AI lanes climb in wave 2, speed 1x ≈ 2.5 req/s.
- [ ] **Step 4:** README: regenerate command for the two-wave run. Commit `feat(dashboard): race on the castle wall, KPI cards, real-time 1x, wave 2 semantic attacks`.

### Task 3: Verify and hand over

- [ ] Full `pytest`; browser check at 1440×800 and at a narrow width; fresh reviewer over `main..dashboard`; fix findings; push `dashboard` to origin. Eswar merges to `main` to update Pages.

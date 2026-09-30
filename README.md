# A shield for vibe-coded apps

Apps built fast with AI ship without the security plumbing hand-built apps get. This is a **drop-in shield**: point it at any app and every request is judged before it lands, with **no rules to write and no tuning** — the opposite of a traditional WAF. It's a reverse proxy that classifies each request with [Jev](https://openrouter.ai/typesafe/jev-1.13) (`typesafe/jev-1.13`, TypeSafe's structured-decision model, via OpenRouter): confident attacks are blocked, everything else is forwarded. A static dashboard replays a logged run so anyone can see what was blocked and why.

**Why not just a regex WAF?** A rule-based WAF catches known attack *shapes* (SQL syntax, `<script>`, `../`) and is strong there. Its blind spot is attacks with no signature — prompt injection against an app's AI, requests that ask it to leak data, business-logic abuse — which read as ordinary text. A judgment model can weigh intent. See **Semantic attacks** below and `dashboard/compare.html` for the head-to-head.

## Architecture

The project has two separate halves: a run-once experiment and a static replay dashboard.

```
Experiment (run once, on your machine)

  client / attacker.py --> proxy.py --> Jev (OpenRouter) --> policy.py
                                                              |
                                        allow --> target_server.py
                                        block --> 403, never reaches target
                              proxy.py --> logs/run-<timestamp>.jsonl

Dashboard (static, no server logic)

  logs/run-*.jsonl --> tools/log_to_runjson.py --> dashboard/run.json --> dashboard/index.html
```

The dashboard only reads `dashboard/run.json`, so it works on GitHub Pages with no backend.

## Run the experiment (Windows)

You do not need git.

1. Download the repo: on the GitHub page `https://github.com/eshwarpotturi/soc-analyst-jev`, click **Code** then **Download ZIP**.
2. Right-click the ZIP and choose **Extract All...**.
3. Install Python 3.11 or newer from https://www.python.org/downloads/ (tick "Add python.exe to PATH" in the installer).
4. Open Command Prompt or PowerShell in the extracted folder (the one containing `run_experiment.py`).
5. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
6. Set your OpenRouter API key for this window only.
   Command Prompt (cmd):
   ```
   set OPENROUTER_API_KEY=your-key-here
   ```
   PowerShell:
   ```
   $env:OPENROUTER_API_KEY="your-key-here"
   ```
   Never paste the key into any file in this repo and never share it or commit it. It is only read from the environment.
7. Run:
   ```
   python run_experiment.py
   ```

Options:

- `--limit 50` replays only the first 50 corpus requests: a cheap smoke test.
- `--attacker-count N` adds N generated attacker requests on top of the corpus (capped at 100).

Before any spend, the script prints a cost estimate and aborts if the projected cost is over $4 (≈ ₹350). A typical full run is well under $0.05 (≈ ₹4). The full corpus is 600 labelled requests in `fixtures/corpus.jsonl`.

The run writes a log to `logs/run-<timestamp>.jsonl` and prints a summary.

## Semantic attacks: what a signature WAF can't see

This is the case for using a judgment model over a rule engine. `baselines/regex_waf.py` is a
signature WAF (OWASP-CRS style). On classic payload attacks it is a fair baseline — it catches
about 76% of the 600-set with zero false alarms. But on *semantic* attacks it is blind.

`make_semantic_corpus.py` builds a set of attacks that carry no classic payload:
- **prompt injection** — instructions that try to override or leak an AI assistant's rules;
- **data exfiltration** — plain-language requests to return data the app should not expose;
- **business-logic abuse** — validly-formed requests with hostile intent (price/coupon/role manipulation).

The signature WAF catches **0 of these** (they are ordinary English). To see whether Jev catches
them, run the same set through the proxy and compare:

```bash
python3 make_semantic_corpus.py                                   # writes fixtures/semantic_corpus.jsonl
python3 run_experiment.py --corpus fixtures/semantic_corpus.jsonl # Jev's verdicts (needs the key)
python3 tools/compare.py fixtures/semantic_corpus.jsonl logs/run-<ts>.jsonl dashboard/compare.json
```

Open `dashboard/compare.html` for the head-to-head. The regex column is computed offline and needs
no key; only Jev's column needs the run.

## Live demo: browse a protected shop

`shop.py` adds a small storefront ("ByteBazaar") to the target app: product search, a sign-in form and document downloads. `demo.py` starts the shop and the Jev proxy together so you can use it in a browser.

```bash
export OPENROUTER_API_KEY="your-key"      # Windows PowerShell: $env:OPENROUTER_API_KEY="..."
python3 demo.py
```

Then open **http://127.0.0.1:8080/shop** (through the proxy). Normal browsing works as usual. When Jev judges a request to be an attack, the browser shows a **Blocked by Jev** page with the attack type and Jev's confidence, and the request never reaches the shop. The same shop without protection is at http://127.0.0.1:8000/shop for comparison.

Every decision is logged to `logs/demo-<time>.jsonl`; turn it into dashboard data with `tools/log_to_runjson.py`. Each request costs a tiny fraction of a rupee. Press Ctrl+C to stop.

## Build the dashboard data

Convert the log into the file the dashboard reads:

```
python tools/log_to_runjson.py logs/run-<timestamp>.jsonl dashboard/run.json
```

(replace `<timestamp>` with the real file name in `logs/`).

To replay several runs back to back as "waves" (this is how the published dashboard is built: the classic run, then the semantic run), pass each log with a label:

```
python tools/log_to_runjson.py dashboard/run.json \
  --wave "Wave 1 · classic web attacks" logs/run-20260929T164714Z.jsonl \
  --wave "Wave 2 · AI-era semantic attacks" logs/run-20260929T195753Z.jsonl \
  --note "Text shown above the accuracy numbers"
```

Each event keeps its real pacing (`gap_ms`, from the log timestamps), so speed **1x replays at the real classification speed**. The castle wall is the bar-chart race: every blocked request hits its category's lane, and lanes re-rank live. The three cards on top (attacks caught, false alarms, average decision latency) update as the replay runs; the false-alarm card says which wave they came from. The repo ships with a mock `dashboard/run.json`, so the dashboard works before any real run. `logs/sample-run.jsonl` is a small sample of the log format; you can regenerate a mock log with `python tools/make_mock_log.py logs/mock.jsonl`.

## View the dashboard

Locally: the dashboard loads `run.json` with `fetch`, which browsers block on `file://` pages, so serve it over http:

```
cd dashboard
python -m http.server 8000
```

then open http://localhost:8000.

Hosted: pushing to `main` runs `.github/workflows/pages.yml`, which publishes the `dashboard/` folder to GitHub Pages at `https://eshwarpotturi.github.io/soc-analyst-jev/`. (In the repo, set Settings > Pages > Source to "GitHub Actions" once.)

## How it works

- For each request the proxy builds a text description of it and asks Jev two questions: `is_attack` (a `noul` value, 0 to 1) and `category` (a `choice` among the attack categories or `none`, with a confidence).
- Block policy (`policy.py`) is deliberately conservative to keep false positives low: block only if `is_attack >= 0.80` AND category confidence `>= 0.50`. Anything else is allowed.
- The proxy fails open: if Jev is unreachable or errors, the request is forwarded to the target and logged, never blocked or turned into a 500.

## Repo layout

| Path | Purpose |
|---|---|
| `target_server.py` | Small demo web app being protected |
| `proxy.py` | Reverse proxy: classify, decide, forward or block, log |
| `state_builder.py` | Turns a request into the text Jev classifies |
| `jev_client.py` | Jev call via OpenRouter (`typesafe/jev-1.13`) |
| `policy.py` | Block/allow decision thresholds |
| `make_corpus.py`, `fixtures/corpus.jsonl` | Generator and the 600 labelled requests |
| `attacker.py` | Generates extra attacker requests |
| `run_experiment.py` | Cost guard, start servers, replay corpus, write log |
| `tools/log_to_runjson.py` | Log to `dashboard/run.json` |
| `tools/make_mock_log.py` | Mock log for dashboard development |
| `dashboard/` | Static replay dashboard (deployed to Pages) |
| `logs/` | Run logs (ignored by git except `sample-run.jsonl`) |
| `tests/` | Test suite (`pip install pytest`, then `pytest -q`) |
| `docs/plans/` | Implementation plan |

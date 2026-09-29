"""Head-to-head: a signature (regex) WAF vs Jev on the same request set.

The regex verdict is computed here (deterministic). Jev's verdict is read from a run log
produced by run_experiment.py over the same corpus (Jev needs a key + network, so that run
happens on the operator's machine). Writes dashboard/compare.json for the comparison page.

    python3 tools/compare.py fixtures/semantic_corpus.jsonl [logs/jev-semantic.jsonl] dashboard/compare.json
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from baselines.regex_waf import classify as regex_classify  # noqa: E402


def _load(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def _tally(rows, blocked_flags):
    """rows aligned with blocked_flags (bool). Returns caught/missed/false_alarms + by-category."""
    attacks = [r for r in rows if r["true_label"] == "malicious"]
    caught = missed = false_alarms = 0
    by_cat = {}
    for r, blk in zip(rows, blocked_flags):
        mal = r["true_label"] == "malicious"
        if mal:
            c = r["true_category"]
            by_cat.setdefault(c, {"total": 0, "caught": 0})
            by_cat[c]["total"] += 1
            if blk:
                caught += 1
                by_cat[c]["caught"] += 1
            else:
                missed += 1
        elif blk:
            false_alarms += 1
    return {"caught": caught, "missed": missed, "false_alarms": false_alarms,
            "attacks": len(attacks), "by_category": by_cat}


def build_compare(corpus, jev_log=None):
    regex_blocked = [regex_classify(r["method"], r["path"], r.get("query", ""),
                                    r.get("headers", {}), r.get("body", ""))[0] for r in corpus]
    out = {
        "set": "semantic",
        "total": len(corpus),
        "attacks": sum(r["true_label"] == "malicious" for r in corpus),
        "benign": sum(r["true_label"] == "benign" for r in corpus),
        "approaches": {"regex": {"name": "Signature WAF (regex rules)", **_tally(corpus, regex_blocked)}},
    }

    jev_blocked = None
    if jev_log is not None and len(jev_log) == len(corpus) and \
            all(a.get("true_category") == b.get("true_category") for a, b in zip(jev_log, corpus)):
        jev_blocked = [r.get("action") == "block" for r in jev_log]
        out["approaches"]["jev"] = {"name": "Jev (judgment model)", **_tally(corpus, jev_blocked)}
    elif jev_log is not None:
        # order/shape didn't line up: fall back to aggregate straight from the log
        blk = [r.get("action") == "block" for r in jev_log]
        out["approaches"]["jev"] = {"name": "Jev (judgment model)", **_tally(jev_log, blk)}
    else:
        out["approaches"]["jev"] = None  # pending the Jev run

    # A few illustrative attacks with the request text and each verdict.
    examples = []
    for i, r in enumerate(corpus):
        if r["true_label"] != "malicious":
            continue
        text = ""
        if r.get("body"):
            try:
                text = json.loads(r["body"]).get("message", "") or r["body"]
            except Exception:
                text = r["body"]
        text = text or (r["path"] + ("?" + r["query"] if r.get("query") else ""))
        examples.append({
            "category": r["true_category"],
            "text": text[:160],
            "regex": "blocked" if regex_blocked[i] else "allowed",
            "jev": ("blocked" if jev_blocked[i] else "allowed") if jev_blocked else "pending",
        })
    out["examples"] = examples[:9]
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2:
        print("usage: python3 tools/compare.py <corpus.jsonl> [jev_log.jsonl] <out.json>", file=sys.stderr)
        return 1
    corpus = _load(argv[0])
    if len(argv) == 2:
        jev_log, out_path = None, argv[1]
    else:
        jev_log, out_path = _load(argv[1]), argv[2]
    Path(out_path).write_text(json.dumps(build_compare(corpus, jev_log), indent=2) + "\n")
    j = build_compare(corpus, jev_log)["approaches"]["jev"]
    print(f"wrote {out_path}; regex caught "
          f"{build_compare(corpus, jev_log)['approaches']['regex']['caught']}/"
          f"{build_compare(corpus, jev_log)['attacks']}, "
          f"jev {'pending' if j is None else str(j['caught']) + '/' + str(j['attacks'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

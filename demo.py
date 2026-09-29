"""Live demo: start the shop (target) and the Jev proxy, then browse the shop through the proxy.

    python3 demo.py            # then open http://127.0.0.1:8080/shop

Every page load, search, login and download is judged by Jev before it reaches the shop.
Blocked requests show a "Blocked by Jev" page. Decisions are logged to logs/demo-<time>.jsonl,
which tools/log_to_runjson.py can turn into dashboard data. Press Ctrl+C to stop.
"""
import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from run_experiment import _wait_port

ROOT = Path(__file__).resolve().parent


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--target-port", type=int, default=8000)
    ap.add_argument("--proxy-port", type=int, default=8080)
    args = ap.parse_args(argv)

    if not os.environ.get("OPENROUTER_API_KEY"):
        print("OPENROUTER_API_KEY is not set. Without it every request passes through unjudged "
              "(fail-open). Set it and run again.", file=sys.stderr)
        return 1

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = ROOT / "logs" / f"demo-{ts}.jsonl"
    log_path.parent.mkdir(exist_ok=True)
    env = dict(os.environ, TARGET_BASE_URL=f"http://{args.host}:{args.target_port}", PROXY_LOG_PATH=str(log_path))

    procs = []
    try:
        for app, port in (("target_server:app", args.target_port), ("proxy:app", args.proxy_port)):
            procs.append(subprocess.Popen(
                [sys.executable, "-m", "uvicorn", app, "--host", args.host, "--port", str(port),
                 "--log-level", "warning"], env=env, cwd=ROOT))
            _wait_port(args.host, port)
        print(f"\n  Shop, protected by Jev:  http://{args.host}:{args.proxy_port}/shop")
        print(f"  Shop, unprotected:       http://{args.host}:{args.target_port}/shop")
        print(f"  Decisions log:           {log_path.relative_to(ROOT)}")
        print("\n  Press Ctrl+C to stop.\n")
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())

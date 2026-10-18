"""One-command offline demo (fake AWS via moto - no account, no cost, no keys).

    python -m scanner.demo_local            # build fake lab, scan, fix, re-scan, compare
    python -m scanner.demo_local --open     # ...and then open the dashboard

Writes results/<scan_id>.json and results/remediation-logs/<scan_id>.json,
which the dashboard reads automatically.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CloudGuard offline demo (moto)")
    ap.add_argument("--open", action="store_true", help="launch the dashboard afterwards")
    ap.add_argument("--results", default=str(ROOT / "results"), help="output folder")
    args = ap.parse_args(argv)

    # Fake credentials so nothing can ever reach a real AWS account.
    for k in ("AWS_PROFILE", "AWS_SESSION_TOKEN"):
        os.environ.pop(k, None)
    os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing",
                      AWS_DEFAULT_REGION="ap-south-1")

    import boto3
    from moto import mock_aws

    from scanner import compare, core, demo_lab
    from scanner.scan import print_summary, run_scan

    results = Path(args.results)
    with mock_aws():
        session = boto3.Session()
        print("1/4  Creating the deliberately vulnerable lab (fake AWS)...")
        lab = demo_lab.build_lab(session)

        print("2/4  Scanning (before)...")
        before, w1 = run_scan(session, "ap-south-1", "before")
        core.validate(before)
        core.write_scan(before, results / f"{before['scan_id']}.json")
        print_summary(before, w1)

        print("3/4  Simulating auto-remediation (stand-in for P3's Lambda)...")
        log = demo_lab.simulate_remediation(session, lab, before)
        (results / "remediation-logs").mkdir(parents=True, exist_ok=True)
        (results / "remediation-logs" / f"{before['scan_id']}.json").write_text(
            json.dumps(log, indent=2) + "\n", "utf-8")

        # Scan IDs have 1-second resolution; make sure 'after' sorts after 'before'.
        time.sleep(1.1)
        print("4/4  Scanning (after)...")
        after, w2 = run_scan(session, "ap-south-1", "after")
        core.validate(after)
        core.write_scan(after, results / f"{after['scan_id']}.json")
        print_summary(after, w2)

    c = compare.compare(before, after, log)
    print(compare.render_text(c))
    (results / "comparison.json").write_text(json.dumps(c, indent=2) + "\n", "utf-8")
    print(f"\nResults written to {results}")

    if args.open:
        print("Starting the dashboard (Ctrl+C to stop)...")
        return subprocess.call([sys.executable, "-m", "streamlit", "run",
                                str(ROOT / "scanner" / "dashboard" / "app.py")], cwd=ROOT)
    print("Next: streamlit run scanner/dashboard/app.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

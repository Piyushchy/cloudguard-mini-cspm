"""
e2e_demo.py - End-to-end integration test harness for CloudGuard Mini-CSPM.

Orchestrates the entire story:
  1. Reset lab to vulnerable state (reset_lab.py)
  2. Scan initial vulnerable state and upload (scanner.scan --label before --upload)
  3. Await P3 Lambda auto-remediation (polls S3 for remediation-logs/<scan_id>.json)
  4. Rescan improved state and upload (scanner.scan --label after --upload)
  5. Run before/after comparison and compute MTTR (scanner.compare)

Owned by P1 (Lab & Platform) Phase 3.
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lab.lab_common import REGION, REPORTS_BUCKET, ACCOUNT_ID


def run_cmd(cmd: list[str], desc: str) -> str:
    print(f"\n[+] {desc}...")
    print(f"    Running: {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[-] Command failed with code {res.returncode}:\n{res.stderr}\n{res.stdout}")
        sys.exit(res.returncode)
    print(res.stdout)
    return res.stdout


def poll_remediation_log(s3, bucket: str, scan_id: str, timeout_seconds: int = 60) -> dict | None:
    log_key = f"remediation-logs/{scan_id}.json"
    print(f"[*] Polling for remediation log: s3://{bucket}/{log_key} (timeout: {timeout_seconds}s)...")
    start = time.time()
    while time.time() - start < timeout_seconds:
        try:
            obj = s3.get_object(Bucket=bucket, Key=log_key)
            data = json.loads(obj["Body"].read().decode("utf-8"))
            print(f"    Remediation log received! Mode: {data.get('mode')}")
            return data
        except ClientError:
            time.sleep(3)
    print("    [!] Polling timed out (P3 remediation Lambda may not be deployed yet).")
    return None


def main():
    parser = argparse.ArgumentParser(description="CloudGuard Mini-CSPM End-to-End Pipeline Harness.")
    parser.add_argument("--profile", default="cspm-p1", help="AWS CLI profile to use (default: cspm-p1)")
    parser.add_argument("--region", default=REGION, help=f"AWS Region (default: {REGION})")
    parser.add_argument("--skip-reset", action="store_true", help="Skip resetting lab before scan")
    parser.add_argument("--local-only", action="store_true", help="Run local offline simulation only")
    args = parser.parse_args()

    python_bin = sys.executable

    print("=====================================================================")
    print("        CloudGuard Mini-CSPM — End-to-End Pipeline Test")
    print("=====================================================================")

    # Step 1: Reset lab to vulnerable state
    if not args.skip_reset:
        run_cmd([python_bin, "lab/reset_lab.py", "--profile", args.profile, "--region", args.region], "Step 1: Resetting Lab to Vulnerable State")

    # Step 2: Scan Before
    scan_before_output = run_cmd(
        [python_bin, "-m", "scanner.scan", "--profile", args.profile, "--label", "before", "--upload"],
        "Step 2: Scanning Lab Before Remediation",
    )

    # Extract scan_id from output
    scan_id = None
    for line in scan_before_output.splitlines():
        if "CloudGuard scan " in line:
            scan_id = line.split("CloudGuard scan ")[1].split()[0]
            break

    if not scan_id:
        print("[-] Could not parse scan_id from scanner output.")
        sys.exit(1)

    print(f"[*] Initial scan ID: {scan_id}")

    # Step 3: Await P3 Lambda Auto-Remediation
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    s3 = session.client("s3")
    rem_log = poll_remediation_log(s3, REPORTS_BUCKET, scan_id, timeout_seconds=30)

    # Step 4: Scan After
    scan_after_output = run_cmd(
        [python_bin, "-m", "scanner.scan", "--profile", args.profile, "--label", "after", "--upload"],
        "Step 4: Scanning Lab After Remediation",
    )

    after_scan_id = None
    for line in scan_after_output.splitlines():
        if "CloudGuard scan " in line:
            after_scan_id = line.split("CloudGuard scan ")[1].split()[0]
            break

    # Step 5: Compare Before & After
    before_file = ROOT / "results" / f"{scan_id}.json"
    after_file = ROOT / "results" / f"{after_scan_id}.json"

    compare_cmd = [python_bin, "-m", "scanner.compare", str(before_file), str(after_file)]
    run_cmd(compare_cmd, "Step 5: Comparing Posture Scores and Misconfigurations")

    print("=====================================================================")
    print("             End-to-End Pipeline Completed Successfully!")
    print("=====================================================================")


if __name__ == "__main__":
    main()

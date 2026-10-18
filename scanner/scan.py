"""CloudGuard scanner CLI.

    python -m scanner.scan --profile cspm-scanner --label before --upload
    python -m scanner.scan --profile cspm-scanner --label after  --upload
    python -m scanner.scan --profile cspm-scanner                      # adhoc, local file only
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import boto3
from botocore.exceptions import (ClientError, NoCredentialsError, NoRegionError,
                                 ProfileNotFound)

from scanner import core
from scanner.checks import ALL_CHECKS
from scanner.checks._util import get_account_id

ROOT = Path(__file__).resolve().parent.parent
CONFIG_ENV = ROOT / "shared" / "config.env"
DEFAULT_REGION = "ap-south-1"
REPORTS_PREFIX = "cspm-demo-reports-"


# ---------------------------------------------------------------- config
def load_config(path: Path = CONFIG_ENV) -> dict:
    cfg = {}
    if path.is_file():
        for line in path.read_text("utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg


# ------------------------------------------------------------------ scan
def run_scan(session, region: str, label: str, now=None) -> tuple[dict, list[str]]:
    """Run every check and return (scan_document, warnings).

    A check that crashes or lacks permission never stops the scan: it adds a
    warning and the others still run. Warnings are NOT part of the JSON file
    (the contract has no field for them); they are shown on the console.
    """
    warnings: list[str] = []
    account_id = get_account_id(session)
    findings: list[dict] = []
    for mod in ALL_CHECKS:
        try:
            findings += mod.run(session, region, warnings=warnings, account_id=account_id)
        except Exception as e:  # noqa: BLE001 - deliberate: keep scanning
            warnings.append(f"{mod.__name__.split('.')[-1]}: check crashed - {e!r}")
    return core.build_scan(findings, account_id, region, label, now), warnings


def upload_scan(session, scan: dict, bucket: str | None = None) -> str:
    bucket = bucket or f"{REPORTS_PREFIX}{scan['account_id']}"
    key = f"scans/{scan['scan_id']}.json"
    session.client("s3").put_object(
        Bucket=bucket, Key=key, Body=json.dumps(scan, indent=2).encode("utf-8"),
        ContentType="application/json")
    return f"s3://{bucket}/{key}"


# --------------------------------------------------------------- console
def _use_color() -> bool:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")  # enables ANSI escape codes in Windows 10+ terminals
    return True


def print_summary(scan: dict, warnings: list[str]) -> None:
    c = _use_color()
    paint = (lambda code, s: f"\033[{code}m{s}\033[0m") if c else (lambda code, s: s)
    sev_col = {"CRITICAL": "1;31", "HIGH": "31", "MEDIUM": "33", "LOW": "36"}
    s = scan["summary"]
    score_col = "32" if s["score"] >= 90 else "33" if s["score"] >= 50 else "31"

    print()
    print(paint("1", "CloudGuard scan ") + f"{scan['scan_id']}  (account {scan['account_id']}, {scan['region']})")
    print(f"  Posture score : {paint(score_col, str(s['score']) + '%')}   (SLO: >= 90%)")
    print(f"  Findings      : {s['failed']} failed of {s['total']}")
    print("  Failed by severity: " + "  ".join(
        paint(sev_col[k], f"{k} {v}") for k, v in s["by_severity"].items()))
    fails = [f for f in scan["findings"] if f["status"] == "FAIL"]
    order = {k: i for i, k in enumerate(core.SEVERITIES)}
    if fails:
        print("\n  Top findings:")
        for f in sorted(fails, key=lambda f: order[f["severity"]])[:8]:
            tag = paint(sev_col[f["severity"]], f"[{f['severity']}]")
            fix = "auto-fixable" if f["auto_remediable"] else "needs a human"
            print(f"    {tag} {f['check_id']}  {f['resource_id']}  ({fix})")
            print(f"           {f['description']}")
    else:
        print(paint("32", "\n  No failed findings."))
    if warnings:
        print(paint("33", f"\n  {len(warnings)} warning(s) - results may be incomplete:"))
        for w in warnings:
            print(f"    - {w}")
    print()


# ------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    cfg = load_config()
    p = argparse.ArgumentParser(prog="scanner.scan", description="CloudGuard mini-CSPM scanner")
    p.add_argument("--profile", help="AWS CLI profile (e.g. cspm-scanner)")
    p.add_argument("--region", default=cfg.get("AWS_REGION", DEFAULT_REGION))
    p.add_argument("--label", choices=core.VALID_LABELS, default="adhoc")
    p.add_argument("--out", help="output file (default results/<scan_id>.json)")
    p.add_argument("--upload", action="store_true", help="upload to the reports bucket under scans/")
    p.add_argument("--bucket", help="override the reports bucket name")
    p.add_argument("--no-validate", action="store_true", help="skip schema validation (debugging only)")
    args = p.parse_args(argv)

    try:
        session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
        scan, warnings = run_scan(session, args.region, args.label)
    except ProfileNotFound:
        print(f"ERROR: AWS profile '{args.profile}' not found. Run: aws configure --profile {args.profile}")
        return 2
    except (NoCredentialsError, NoRegionError):
        print("ERROR: no AWS credentials found. Run 'aws configure --profile cspm-scanner' "
              "and pass --profile cspm-scanner.")
        return 2
    except ClientError as e:
        print(f"ERROR: AWS rejected the request ({e.response['Error']['Code']}): "
              f"{e.response['Error'].get('Message', '')}")
        return 2

    if not args.no_validate:
        try:
            core.validate(scan)
        except core.ScanValidationError as e:
            print(f"ERROR: scan does not follow the findings contract: {e}")
            return 1

    out = core.write_scan(scan, args.out or ROOT / "results" / f"{scan['scan_id']}.json")
    print_summary(scan, warnings)
    print(f"Saved: {out}")

    if args.upload:
        try:
            print(f"Uploaded: {upload_scan(session, scan, args.bucket)}")
        except ClientError as e:
            print(f"ERROR: upload failed ({e.response['Error']['Code']}). Check the bucket name "
                  "and that your profile may write to scans/.")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

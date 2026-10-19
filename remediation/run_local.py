"""remediation.run_local — Local CLI Runner for CloudGuard Remediation

Allows executing the exact same remediation logic locally against real AWS resources
or sample findings files for testing and verification before Lambda deployment.

Usage:
    python remediation/run_local.py --findings samples/findings_before.json --mode dry-run --profile cspm-p3
    python remediation/run_local.py --findings samples/findings_before.json --mode remediate --profile cspm-p3
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import boto3
import jsonschema

from remediation.dispatcher import dispatch_actions
from remediation.handler import format_sns_alert, load_findings_schema


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cloudguard.run_local")


def main():
    parser = argparse.ArgumentParser(description="CloudGuard Remediation Local CLI Runner")
    parser.add_argument(
        "--findings",
        required=True,
        help="Path to findings JSON file (e.g. samples/findings_before.json)",
    )
    parser.add_argument(
        "--mode",
        choices=["alert-only", "dry-run", "remediate"],
        default="dry-run",
        help="Remediation mode (default: dry-run)",
    )
    parser.add_argument(
        "--profile",
        default="cspm-p3",
        help="AWS CLI profile name (default: cspm-p3)",
    )
    parser.add_argument(
        "--region",
        default="ap-south-1",
        help="AWS Region (default: ap-south-1)",
    )
    parser.add_argument(
        "--out",
        help="Optional path to output remediation log JSON file",
    )

    args = parser.parse_args()

    findings_path = Path(args.findings)
    if not findings_path.exists():
        logger.error("Findings file not found: %s", findings_path)
        sys.exit(1)

    with open(findings_path, "r", encoding="utf-8") as f:
        findings_data = json.load(f)

    # 1. Validate Schema
    schema = load_findings_schema()
    try:
        jsonschema.validate(instance=findings_data, schema=schema)
        logger.info("Findings schema validation: PASS")
    except jsonschema.ValidationError as e:
        logger.error("Schema validation failed: %s", e.message)
        sys.exit(1)

    # 2. Display Alert Preview
    subject, body = format_sns_alert(findings_data, mode=args.mode)
    print("\n" + "=" * 60)
    print("ALERT PREVIEW (SNS Subject & Message):")
    print("=" * 60)
    print(f"Subject: {subject}\n")
    print(body)
    print("=" * 60 + "\n")

    # 3. Setup AWS Session
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    iam = session.client("iam")

    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 4. Dispatch Actions
    logger.info("Executing actions in mode '%s'...", args.mode)
    actions_log = dispatch_actions(
        findings_data=findings_data,
        mode=args.mode,
        s3_client=s3,
        ec2_client=ec2,
        iam_client=iam,
    )

    finished = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    remediation_log = {
        "scan_id": findings_data.get("scan_id", "unknown"),
        "mode": args.mode,
        "started": started,
        "finished": finished,
        "actions": actions_log,
    }

    print("\n" + "=" * 60)
    print("REMEDIATION LOG RESULT:")
    print("=" * 60)
    print(json.dumps(remediation_log, indent=2))
    print("=" * 60 + "\n")

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(remediation_log, f, indent=2)
        logger.info("Remediation log written to %s", out_path)


if __name__ == "__main__":
    main()

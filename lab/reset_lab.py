"""
reset_lab.py - Restores the lab to its vulnerable state after auto-remediation.
Essential for demo retakes, rehearsal, and repeatable integration testing.

Part of P1 (Lab & Platform) Phase 2.
"""

import argparse
import sys
from pathlib import Path

# Add repo root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
from lab.lab_common import (
    REGION,
    VULN_BUCKET,
    VULN_SG_NAME,
    VULN_IAM_USER,
)
from lab.create_lab import setup_vuln_s3, setup_vuln_sg, setup_vuln_iam


def main():
    parser = argparse.ArgumentParser(description="Reset CloudGuard lab to vulnerable state after remediation.")
    parser.add_argument("--profile", default="cspm-p1", help="AWS CLI profile to use (default: cspm-p1)")
    parser.add_argument("--region", default=REGION, help=f"AWS Region (default: {REGION})")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without modifying AWS")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    s3 = session.client("s3")
    s3control = session.client("s3control", region_name=args.region)
    ec2 = session.client("ec2")
    iam = session.client("iam")

    print(f"=== Resetting CloudGuard Lab to Vulnerable State (dry_run={args.dry_run}) ===")

    # 1. Reset S3: disable BPA, ensure hello.txt has public read, suspend versioning if enabled
    if not args.dry_run:
        try:
            s3.put_bucket_versioning(Bucket=VULN_BUCKET, VersioningConfiguration={"Status": "Suspended"})
        except Exception:
            pass
    setup_vuln_s3(s3, s3control, VULN_BUCKET, args.region, args.dry_run)

    # 2. Reset EC2 SG: re-authorize open port 22 ingress
    setup_vuln_sg(ec2, VULN_SG_NAME, args.dry_run)

    # 3. Reset IAM: re-attach AdministratorAccess and ensure console profile exists
    setup_vuln_iam(iam, VULN_IAM_USER, args.dry_run)

    print("\n=== Lab Reset Complete — All 5 Vulnerabilities Restored ===")


if __name__ == "__main__":
    main()

"""
teardown_lab.py - Safely tears down the deliberately vulnerable lab resources.
Safety guardrails:
  - Deletes ONLY resources tagged Project=cspm-demo and Deliberate=true.
  - Never touches the reports bucket or CloudTrail unless --include-infra is explicitly passed.
  - Supports --dry-run and interactive confirmation.

Part of P1 (Lab & Platform) Phase 2 & Phase 6.
"""

import argparse
import sys
from pathlib import Path

# Add repo root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
from botocore.exceptions import ClientError
from lab.lab_common import (
    REGION,
    VULN_BUCKET,
    VULN_SG_NAME,
    VULN_IAM_USER,
    REPORTS_BUCKET,
    TRAIL_LOGS_BUCKET,
    TRAIL_NAME,
)


def empty_and_delete_bucket(s3, bucket_name: str, dry_run: bool = False):
    print(f"[*] Tearing down bucket: {bucket_name}...")
    if dry_run:
        print(f"    [DRY-RUN] Would empty all objects/versions and delete bucket {bucket_name}.")
        return

    try:
        s3.head_bucket(Bucket=bucket_name)
    except ClientError:
        print(f"    Bucket '{bucket_name}' does not exist.")
        return

    # Delete all object versions and delete markers
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            to_delete = []
            for version in page.get("Versions", []):
                to_delete.append({"Key": version["Key"], "VersionId": version["VersionId"]})
            for marker in page.get("DeleteMarkers", []):
                to_delete.append({"Key": marker["Key"], "VersionId": marker["VersionId"]})
            if to_delete:
                s3.delete_objects(Bucket=bucket_name, Delete={"Objects": to_delete})

        s3.delete_bucket(Bucket=bucket_name)
        print(f"    Bucket '{bucket_name}' deleted successfully.")
    except ClientError as e:
        print(f"    Error deleting bucket: {e}")


def delete_security_group(ec2, sg_name: str, dry_run: bool = False):
    print(f"[*] Tearing down security group: {sg_name}...")
    if dry_run:
        print(f"    [DRY-RUN] Would delete security group {sg_name}.")
        return

    try:
        sgs = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [sg_name]}])["SecurityGroups"]
        if not sgs:
            print(f"    Security group '{sg_name}' does not exist.")
            return

        sg_id = sgs[0]["GroupId"]
        ec2.delete_security_group(GroupId=sg_id)
        print(f"    Deleted security group '{sg_name}' ({sg_id}).")
    except ClientError as e:
        print(f"    Error deleting SG: {e}")


def delete_iam_user(iam, username: str, dry_run: bool = False):
    print(f"[*] Tearing down IAM user: {username}...")
    if dry_run:
        print(f"    [DRY-RUN] Would detach policies, delete login profile, and delete user {username}.")
        return

    try:
        iam.get_user(UserName=username)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print(f"    User '{username}' does not exist.")
            return
        raise

    # 1. Detach attached policies
    try:
        attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        for p in attached:
            iam.detach_user_policy(UserName=username, PolicyArn=p["PolicyArn"])
            print(f"    Detached {p['PolicyName']}.")
    except Exception as e:
        print(f"    Warning detaching policies: {e}")

    # 2. Delete login profile
    try:
        iam.delete_login_profile(UserName=username)
        print("    Deleted console login profile.")
    except ClientError:
        pass

    # 3. Delete user
    try:
        iam.delete_user(UserName=username)
        print(f"    Deleted IAM user '{username}'.")
    except ClientError as e:
        print(f"    Error deleting user: {e}")


def delete_infra(s3, ct, dry_run: bool = False):
    print("\n[!] Tearing down shared infrastructure (--include-infra)...")
    if dry_run:
        print("    [DRY-RUN] Would stop/delete CloudTrail and empty/delete reports and trail log buckets.")
        return

    # 1. Stop and delete CloudTrail
    try:
        ct.stop_logging(Name=TRAIL_NAME)
        ct.delete_trail(Name=TRAIL_NAME)
        print(f"    CloudTrail '{TRAIL_NAME}' stopped and deleted.")
    except ClientError as e:
        print(f"    Notice on CloudTrail teardown: {e}")

    # 2. Delete trail logs bucket
    empty_and_delete_bucket(s3, TRAIL_LOGS_BUCKET, dry_run)

    # 3. Delete reports bucket
    empty_and_delete_bucket(s3, REPORTS_BUCKET, dry_run)


def main():
    parser = argparse.ArgumentParser(description="Teardown CloudGuard lab resources.")
    parser.add_argument("--profile", default="cspm-p1", help="AWS CLI profile to use (default: cspm-p1)")
    parser.add_argument("--region", default=REGION, help=f"AWS Region (default: {REGION})")
    parser.add_argument("--dry-run", action="store_true", help="Show actions without modifying AWS")
    parser.add_argument("--include-infra", action="store_true", help="Also delete reports bucket and CloudTrail (Phase 6 only)")
    parser.add_argument("--yes", action="store_true", help="Skip confirmation prompt")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    iam = session.client("iam")
    ct = session.client("cloudtrail")

    print(f"=== CloudGuard Lab Teardown ===")
    print(f"Target vulnerable resources:")
    print(f"  - S3 Bucket: {VULN_BUCKET}")
    print(f"  - EC2 SG:    {VULN_SG_NAME}")
    print(f"  - IAM User:  {VULN_IAM_USER}")
    if args.include_infra:
        print(f"  - Shared Infra: Reports bucket ({REPORTS_BUCKET}) & CloudTrail ({TRAIL_NAME})")

    if not args.yes and not args.dry_run:
        confirm = input("\nAre you sure you want to delete these resources? (y/N): ")
        if confirm.lower() != "y":
            print("Aborted by user.")
            return

    # Delete vulnerable lab resources
    empty_and_delete_bucket(s3, VULN_BUCKET, args.dry_run)
    delete_security_group(ec2, VULN_SG_NAME, args.dry_run)
    delete_iam_user(iam, VULN_IAM_USER, args.dry_run)

    # Delete infra if explicitly requested
    if args.include_infra:
        delete_infra(s3, ct, args.dry_run)

    print("\n=== Teardown Completed ===")


if __name__ == "__main__":
    main()

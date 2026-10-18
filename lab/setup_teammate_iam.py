"""
setup_teammate_iam.py - Provisions IAM users and least-privilege policies for P2 and P3.

Part of P1 (Lab & Platform) Phase 0.
Supports --dry-run.
"""

import argparse
import json
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

ACCOUNT_ID = "310788607340"
IAM_DIR = Path(__file__).parent / "iam"

P2_USER = "cspm-p2-scanner"
P2_MANAGED_POLICIES = [
    "arn:aws:iam::aws:policy/SecurityAudit",
    "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
]

P3_USER = "cspm-p3-remediator"
P3_MANAGED_POLICIES = [
    "arn:aws:iam::aws:policy/PowerUserAccess",
]

TAGS = [
    {"Key": "Project", "Value": "cspm-demo"},
    {"Key": "Role", "Value": "teammate"},
]


def ensure_user(iam, username: str, dry_run: bool = False):
    print(f"[*] Ensuring user {username}...")
    if dry_run:
        print(f"    [DRY-RUN] Would check/create IAM user '{username}' and tag it.")
        return
    try:
        iam.get_user(UserName=username)
        print(f"    User '{username}' already exists.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            iam.create_user(UserName=username, Tags=TAGS)
            print(f"    Created user '{username}'.")
        else:
            raise


def attach_managed_policies(iam, username: str, policies: list[str], dry_run: bool = False):
    for policy_arn in policies:
        print(f"[*] Attaching managed policy {policy_arn} to {username}...")
        if dry_run:
            print(f"    [DRY-RUN] Would attach {policy_arn}")
            continue
        try:
            iam.attach_user_policy(UserName=username, PolicyArn=policy_arn)
            print("    Attached successfully.")
        except ClientError as e:
            print(f"    Error attaching policy: {e}")


def put_inline_policy(iam, username: str, policy_name: str, policy_file: Path, dry_run: bool = False):
    print(f"[*] Putting inline policy '{policy_name}' on {username} from {policy_file.name}...")
    with open(policy_file, "r", encoding="utf-8") as f:
        policy_doc = f.read()

    if dry_run:
        print(f"    [DRY-RUN] Would put inline policy '{policy_name}':\n{policy_doc}")
        return

    try:
        iam.put_user_policy(UserName=username, PolicyName=policy_name, PolicyDocument=policy_doc)
        print("    Inline policy applied.")
    except ClientError as e:
        print(f"    Error putting inline policy: {e}")


def main():
    parser = argparse.ArgumentParser(description="Create IAM users and policies for P2 and P3 teammates.")
    parser.add_argument("--profile", default="cspm-p1", help="AWS CLI profile to use (default: cspm-p1)")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without modifying AWS")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile)
    iam = session.client("iam")

    print(f"--- Setting up Teammate IAM (dry_run={args.dry_run}) ---")

    # Setup P2
    ensure_user(iam, P2_USER, args.dry_run)
    attach_managed_policies(iam, P2_USER, P2_MANAGED_POLICIES, args.dry_run)
    put_inline_policy(iam, P2_USER, "cspm-reports-bucket-access", IAM_DIR / "p2_reports_policy.json", args.dry_run)

    # Setup P3
    ensure_user(iam, P3_USER, args.dry_run)
    attach_managed_policies(iam, P3_USER, P3_MANAGED_POLICIES, args.dry_run)
    put_inline_policy(iam, P3_USER, "cspm-remediator-role-management", IAM_DIR / "p3_remediator_policy.json", args.dry_run)

    print("\n--- Setup Complete ---")
    if not args.dry_run:
        print("Teammate users are created. Each teammate can now create their access keys and configure local CLI profiles.")


if __name__ == "__main__":
    main()

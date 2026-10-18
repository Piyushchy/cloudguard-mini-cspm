"""
verify_lab.py - Independent verification script for CloudGuard Mini-CSPM lab.
Uses plain boto3 (independent of P2's scanner) to verify the 5 expected FAIL misconfigurations.

Part of P1 (Lab & Platform) Phase 2.
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
    ACCOUNT_ID,
    VULN_BUCKET,
    VULN_SG_NAME,
    VULN_IAM_USER,
    TRAIL_NAME,
)


def check_s3_001(s3, bucket: str) -> tuple[bool, str]:
    """Check if bucket is publicly accessible (S3-001 FAIL)."""
    try:
        # Check BPA
        bpa_off = False
        try:
            bpa = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
            if not all(bpa.values()):
                bpa_off = True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                bpa_off = True

        # Check policy
        has_public_policy = False
        try:
            p_status = s3.get_bucket_policy_status(Bucket=bucket)
            has_public_policy = p_status.get("PolicyStatus", {}).get("IsPublic", False)
        except ClientError:
            pass

        if bpa_off and has_public_policy:
            return True, "BPA not fully enabled and bucket policy is public (FAIL expected)"
        elif bpa_off:
            return False, "BPA off, but policy is not public"
        else:
            return False, "Block Public Access is ON (Compliant/PASS)"
    except ClientError as e:
        return False, f"Bucket error: {e}"


def check_s3_002(s3, bucket: str) -> tuple[bool, str]:
    """Check if bucket versioning is disabled (S3-002 FAIL)."""
    try:
        res = s3.get_bucket_versioning(Bucket=bucket)
        status = res.get("Status", "Disabled")
        if status != "Enabled":
            return True, f"Versioning status is '{status}' (FAIL expected)"
        return False, "Versioning is Enabled (Compliant/PASS)"
    except ClientError as e:
        return False, f"Bucket error: {e}"


def check_ec2_001(ec2, sg_name: str) -> tuple[bool, str]:
    """Check if SG allows port 22 open to 0.0.0.0/0 (EC2-001 FAIL)."""
    try:
        sgs = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [sg_name]}])["SecurityGroups"]
        if not sgs:
            return False, f"Security group '{sg_name}' not found"

        sg = sgs[0]
        for perm in sg.get("IpPermissions", []):
            protocol = perm.get("IpProtocol")
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])]

            if ("0.0.0.0/0" in cidrs or "::/0" in [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]):
                if protocol == "-1" or (from_port is not None and from_port <= 22 and to_port >= 22):
                    return True, f"Port 22 open to 0.0.0.0/0 in {sg['GroupId']} (FAIL expected)"

        return False, "No open ingress on port 22 (Compliant/PASS)"
    except ClientError as e:
        return False, f"EC2 error: {e}"


def check_iam_001(iam, username: str) -> tuple[bool, str]:
    """Check if user has AdministratorAccess directly attached (IAM-001 FAIL)."""
    try:
        policies = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        admin_arns = [p["PolicyArn"] for p in policies if p["PolicyName"] == "AdministratorAccess"]
        if admin_arns:
            return True, f"AdministratorAccess attached directly (FAIL expected)"
        return False, "AdministratorAccess not attached directly (Compliant/PASS)"
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return False, f"User '{username}' does not exist"
        return False, f"IAM error: {e}"


def check_iam_002(iam, username: str) -> tuple[bool, str]:
    """Check if user has console password but no MFA (IAM-002 FAIL)."""
    try:
        has_login_profile = False
        try:
            iam.get_login_profile(UserName=username)
            has_login_profile = True
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
        if has_login_profile and not mfa_devices:
            return True, "Console login active but 0 MFA devices registered (FAIL expected)"
        elif not has_login_profile:
            return False, "No console login profile (Compliant/PASS)"
        else:
            return False, "Console login has MFA enabled (Compliant/PASS)"
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return False, f"User '{username}' does not exist"
        return False, f"IAM error: {e}"


def check_ct_001(ct, trail_name: str) -> tuple[bool, str]:
    """Check if multi-region CloudTrail is logging (CT-001 PASS expected after Phase 1)."""
    try:
        trails = ct.describe_trails(trailNameList=[trail_name])["trailList"]
        if not trails:
            return False, f"Trail '{trail_name}' does not exist"
        status = ct.get_trail_status(Name=trail_name)
        if status.get("IsLogging", False) and trails[0].get("IsMultiRegionTrail", False):
            return True, "Active multi-region trail logging (Compliant/PASS)"
        return False, f"Trail exists but IsLogging={status.get('IsLogging')}"
    except ClientError as e:
        return False, f"CloudTrail error: {e}"


def main():
    parser = argparse.ArgumentParser(description="Verify CloudGuard lab vulnerabilities.")
    parser.add_argument("--profile", default="cspm-p1", help="AWS CLI profile to use (default: cspm-p1)")
    parser.add_argument("--region", default=REGION, help=f"AWS Region (default: {REGION})")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    iam = session.client("iam")
    ct = session.client("cloudtrail")

    print(f"=== CloudGuard Lab Independent Verification ===")
    print(f"Account: {ACCOUNT_ID} | Region: {args.region} | Profile: {args.profile}\n")

    checks = [
        ("S3-001", "Bucket Public Access", *check_s3_001(s3, VULN_BUCKET), "FAIL"),
        ("S3-002", "Bucket Versioning Disabled", *check_s3_002(s3, VULN_BUCKET), "FAIL"),
        ("EC2-001", "SG Port 22 Open (0.0.0.0/0)", *check_ec2_001(ec2, VULN_SG_NAME), "FAIL"),
        ("IAM-001", "IAM User AdministratorAccess Attached", *check_iam_001(iam, VULN_IAM_USER), "FAIL"),
        ("IAM-002", "IAM User Console Password Without MFA", *check_iam_002(iam, VULN_IAM_USER), "FAIL"),
        ("CT-001", "CloudTrail Multi-Region Logging Active", *check_ct_001(ct, TRAIL_NAME), "PASS"),
    ]

    print(f"{'Check ID':<9} | {'Check Description':<36} | {'Target':<6} | {'Status':<6} | {'Details'}")
    print("-" * 110)

    matched = 0
    for check_id, desc, is_present, detail, expected in checks:
        actual = "FAIL" if (check_id != "CT-001" and is_present) or (check_id == "CT-001" and not is_present) else "PASS"
        status_flag = "MATCH" if actual == expected else "MISMATCH"
        if status_flag == "MATCH":
            matched += 1
        print(f"{check_id:<9} | {desc:<36} | {expected:<6} | {actual:<6} | {detail}")

    print("-" * 110)
    print(f"Result: {matched}/6 checks match expected target state.\n")


if __name__ == "__main__":
    main()

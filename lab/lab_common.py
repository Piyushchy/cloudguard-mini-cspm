"""
lab_common.py - Shared constants and helpers for CloudGuard Mini-CSPM lab scripts.
Owned by P1 (Lab & Platform).
"""

import string
import secrets
import boto3

REGION = "ap-south-1"
ACCOUNT_ID = "310788607340"

VULN_BUCKET = f"cspm-demo-vuln-bucket-{ACCOUNT_ID}"
VULN_SG_NAME = "cspm-demo-vuln-sg"
VULN_IAM_USER = "cspm-demo-vuln-user"

REPORTS_BUCKET = f"cspm-demo-reports-{ACCOUNT_ID}"
TRAIL_LOGS_BUCKET = f"cspm-demo-trail-logs-{ACCOUNT_ID}"
TRAIL_NAME = "cspm-demo-trail"

LAB_TAGS = [
    {"Key": "Project", "Value": "cspm-demo"},
    {"Key": "Deliberate", "Value": "true"},
    {"Key": "cspm-remediate", "Value": "true"},
]


def generate_unusable_password(length: int = 24) -> str:
    """Generates a cryptographically strong random password for IAM login profile.
    This password is used once to set up the vulnerable console profile (IAM-002)
    and is immediately discarded so nobody can ever log in with it."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(chars) for _ in range(length))


def get_default_vpc_id(ec2) -> str:
    """Finds the default VPC ID in the target region."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
    if not vpcs:
        # Fallback to the first available VPC if no default VPC exists
        all_vpcs = ec2.describe_vpcs()["Vpcs"]
        if not all_vpcs:
            raise RuntimeError("No VPC found in region " + REGION)
        return all_vpcs[0]["VpcId"]
    return vpcs[0]["VpcId"]

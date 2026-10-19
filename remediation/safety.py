"""remediation.safety — Central Safety Checks and Resource Guardrails

Enforces Contract A6 & B2:
1. Tag validation (cspm-remediate=true).
2. Protection list (reports bucket, trail logs, root, non-demo users).
3. Non-destructive operations (no deletions).
"""

import logging
from typing import Any, Dict, Optional, Set

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("cloudguard.safety")

REQUIRED_TAG_KEY = "cspm-remediate"
REQUIRED_TAG_VALUE = "true"

# Resources strictly forbidden from being modified
PROTECTED_RESOURCES: Set[str] = {
    "root",
    "cspm-p3-remediator",
    "cspm-scanner",
}

# Prefix patterns for protected infrastructure buckets
PROTECTED_BUCKET_PREFIXES = (
    "cspm-demo-reports-",
    "cspm-demo-trail-logs-",
)


def is_resource_protected(resource_id: str, service: str) -> bool:
    """Check if the resource is on the non-negotiable protection list."""
    if not resource_id:
        return True

    res_lower = resource_id.lower()
    if res_lower in PROTECTED_RESOURCES:
        return True

    if service.lower() == "s3":
        for prefix in PROTECTED_BUCKET_PREFIXES:
            if res_lower.startswith(prefix):
                return True

    if service.lower() == "iam":
        # Only cspm-demo-vuln-user is eligible for IAM remediation
        if resource_id != "cspm-demo-vuln-user":
            return True

    return False


def verify_s3_bucket_tag(s3_client: Any, bucket_name: str) -> bool:
    """Verify that an S3 bucket has the tag cspm-remediate=true."""
    try:
        response = s3_client.get_bucket_tagging(Bucket=bucket_name)
        tag_set = response.get("TagSet", [])
        for tag in tag_set:
            if tag.get("Key") == REQUIRED_TAG_KEY and tag.get("Value") == REQUIRED_TAG_VALUE:
                return True
        return False
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("NoSuchTagSet", "NoSuchBucket"):
            return False
        logger.warning("Error checking tags on bucket %s: %s", bucket_name, e)
        return False


def verify_ec2_sg_tag(ec2_client: Any, group_id: str) -> bool:
    """Verify that an EC2 security group has the tag cspm-remediate=true."""
    try:
        response = ec2_client.describe_security_groups(GroupIds=[group_id])
        groups = response.get("SecurityGroups", [])
        if not groups:
            return False
        tags = groups[0].get("Tags", [])
        for tag in tags:
            if tag.get("Key") == REQUIRED_TAG_KEY and tag.get("Value") == REQUIRED_TAG_VALUE:
                return True
        return False
    except ClientError as e:
        logger.warning("Error checking tags on security group %s: %s", group_id, e)
        return False


def verify_iam_user_tag(iam_client: Any, user_name: str) -> bool:
    """Verify that an IAM user has the tag cspm-remediate=true."""
    try:
        response = iam_client.list_user_tags(UserName=user_name)
        tags = response.get("Tags", [])
        for tag in tags:
            if tag.get("Key") == REQUIRED_TAG_KEY and tag.get("Value") == REQUIRED_TAG_VALUE:
                return True
        return False
    except ClientError as e:
        logger.warning("Error checking tags on IAM user %s: %s", user_name, e)
        return False

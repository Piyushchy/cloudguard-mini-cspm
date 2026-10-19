"""remediation.actions.s3_enable_bpa — S3-001 Remediation Action

Action Code: S3_ENABLE_BPA
Enables all four Block Public Access settings on the target S3 bucket.
Preserves existing bucket policies.
"""

import logging
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from remediation.safety import is_resource_protected, verify_s3_bucket_tag

logger = logging.getLogger("cloudguard.actions.s3_enable_bpa")


def remediate_s3_bpa(
    finding: Dict[str, Any],
    mode: str,
    s3_client: Any = None,
) -> Dict[str, Any]:
    """Execute S3_ENABLE_BPA remediation according to safety contract."""
    finding_id = finding.get("id", "")
    check_id = finding.get("check_id", "S3-001")
    resource_id = finding.get("resource_id", "")
    action_code = "S3_ENABLE_BPA"

    if s3_client is None:
        s3_client = boto3.client("s3")

    # 1. Protection List Guard
    if is_resource_protected(resource_id, "s3"):
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "SKIPPED_PROTECTED_RESOURCE",
            "before_state": {},
            "detail": f"Resource {resource_id} is in the protected resources list.",
        }

    # 2. Tag Validation Guard
    if not verify_s3_bucket_tag(s3_client, resource_id):
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "SKIPPED_NOT_TAGGED",
            "before_state": {},
            "detail": f"Bucket {resource_id} is missing required tag cspm-remediate=true.",
        }

    # 3. Read Before State
    before_state = {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
    try:
        current_bpa = s3_client.get_public_access_block(Bucket=resource_id)
        pab_conf = current_bpa.get("PublicAccessBlockConfiguration", {})
        before_state = {
            "BlockPublicAcls": pab_conf.get("BlockPublicAcls", False),
            "IgnorePublicAcls": pab_conf.get("IgnorePublicAcls", False),
            "BlockPublicPolicy": pab_conf.get("BlockPublicPolicy", False),
            "RestrictPublicBuckets": pab_conf.get("RestrictPublicBuckets", False),
        }
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code != "NoSuchPublicAccessBlockConfiguration":
            logger.warning("Error reading public access block on %s: %s", resource_id, e)

    # 4. Check if Already Compliant
    if all(before_state.values()):
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "ALREADY_COMPLIANT",
            "before_state": before_state,
            "detail": "All four Block Public Access settings are already enabled.",
        }

    # 5. Handle Dry-Run Mode
    if mode == "dry-run":
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "DRY_RUN",
            "before_state": before_state,
            "detail": "[DRY-RUN] Would enable all four Block Public Access settings.",
        }

    # 6. Apply Remediation Change
    try:
        s3_client.put_public_access_block(
            Bucket=resource_id,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        # Verify change
        s3_client.get_public_access_block(Bucket=resource_id)
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "SUCCESS",
            "before_state": before_state,
            "detail": "Enabled all four Block Public Access settings.",
        }
    except Exception as e:
        logger.error("Failed to enable BPA on %s: %s", resource_id, e)
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "FAILED",
            "before_state": before_state,
            "detail": f"API error applying BPA: {str(e)}",
        }

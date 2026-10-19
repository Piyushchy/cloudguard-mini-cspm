"""remediation.actions.s3_enable_versioning — S3-002 Remediation Action

Action Code: S3_ENABLE_VERSIONING
Enables object versioning on the target S3 bucket.
"""

import logging
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from remediation.safety import is_resource_protected, verify_s3_bucket_tag

logger = logging.getLogger("cloudguard.actions.s3_enable_versioning")


def remediate_s3_versioning(
    finding: Dict[str, Any],
    mode: str,
    s3_client: Any = None,
) -> Dict[str, Any]:
    """Execute S3_ENABLE_VERSIONING remediation according to safety contract."""
    finding_id = finding.get("id", "")
    check_id = finding.get("check_id", "S3-002")
    resource_id = finding.get("resource_id", "")
    action_code = "S3_ENABLE_VERSIONING"

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
    before_status = "Disabled"
    try:
        ver_resp = s3_client.get_bucket_versioning(Bucket=resource_id)
        before_status = ver_resp.get("Status", "Disabled")
    except ClientError as e:
        logger.warning("Error reading versioning on %s: %s", resource_id, e)

    before_state = {"Status": before_status}

    # 4. Check if Already Compliant
    if before_status == "Enabled":
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "ALREADY_COMPLIANT",
            "before_state": before_state,
            "detail": "Bucket versioning is already Enabled.",
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
            "detail": "[DRY-RUN] Would enable bucket versioning.",
        }

    # 6. Apply Remediation Change
    try:
        s3_client.put_bucket_versioning(
            Bucket=resource_id,
            VersioningConfiguration={"Status": "Enabled"},
        )
        # Verify
        verify_resp = s3_client.get_bucket_versioning(Bucket=resource_id)
        if verify_resp.get("Status") == "Enabled":
            return {
                "finding_id": finding_id,
                "check_id": check_id,
                "resource_id": resource_id,
                "action": action_code,
                "result": "SUCCESS",
                "before_state": before_state,
                "detail": "Versioning set to Enabled.",
            }
        else:
            return {
                "finding_id": finding_id,
                "check_id": check_id,
                "resource_id": resource_id,
                "action": action_code,
                "result": "FAILED",
                "before_state": before_state,
                "detail": "Versioning update did not reflect Enabled status.",
            }
    except Exception as e:
        logger.error("Failed to enable versioning on %s: %s", resource_id, e)
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "FAILED",
            "before_state": before_state,
            "detail": f"API error enabling versioning: {str(e)}",
        }

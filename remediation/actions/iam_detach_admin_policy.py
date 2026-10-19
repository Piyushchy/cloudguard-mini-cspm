"""remediation.actions.iam_detach_admin_policy — IAM-001 Remediation Action

Action Code: IAM_DETACH_ADMIN_POLICY
Safely detaches the AdministratorAccess policy from the deliberately vulnerable demo user.
Hard-coded safety guard: Only operates on 'cspm-demo-vuln-user'.
"""

import logging
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from remediation.safety import is_resource_protected, verify_iam_user_tag

logger = logging.getLogger("cloudguard.actions.iam_detach_admin_policy")

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
ALLOWED_USER_NAME = "cspm-demo-vuln-user"


def remediate_iam_admin_policy(
    finding: Dict[str, Any],
    mode: str,
    iam_client: Any = None,
) -> Dict[str, Any]:
    """Execute IAM_DETACH_ADMIN_POLICY remediation according to safety contract."""
    finding_id = finding.get("id", "")
    check_id = finding.get("check_id", "IAM-001")
    resource_id = finding.get("resource_id", "")
    action_code = "IAM_DETACH_ADMIN_POLICY"

    if iam_client is None:
        iam_client = boto3.client("iam")

    # 1. Hard-Coded Identity Protection Guard
    if resource_id != ALLOWED_USER_NAME:
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "SKIPPED_PROTECTED_RESOURCE",
            "before_state": {},
            "detail": f"IAM remediation is strictly restricted to {ALLOWED_USER_NAME}. User {resource_id} is protected.",
        }

    # 2. Protection List Guard
    if is_resource_protected(resource_id, "iam"):
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "SKIPPED_PROTECTED_RESOURCE",
            "before_state": {},
            "detail": f"Resource {resource_id} is in the protected resources list.",
        }

    # 3. Tag Validation Guard
    if not verify_iam_user_tag(iam_client, resource_id):
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "SKIPPED_NOT_TAGGED",
            "before_state": {},
            "detail": f"User {resource_id} is missing required tag cspm-remediate=true.",
        }

    # 4. Read Current State
    try:
        policies_resp = iam_client.list_attached_user_policies(UserName=resource_id)
        attached = policies_resp.get("AttachedPolicies", [])
        attached_arns = [p["PolicyArn"] for p in attached]
    except ClientError as e:
        logger.error("Error reading attached policies for %s: %s", resource_id, e)
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "FAILED",
            "before_state": {},
            "detail": f"API error listing user policies: {str(e)}",
        }

    before_state = {"attached_policies": attached_arns}

    # 5. Check if Already Compliant
    target_policy_arn = None
    for arn in attached_arns:
        if arn == ADMIN_POLICY_ARN or arn.endswith("/AdministratorAccess"):
            target_policy_arn = arn
            break

    if not target_policy_arn:
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "ALREADY_COMPLIANT",
            "before_state": before_state,
            "detail": "AdministratorAccess policy is not attached to user.",
        }

    # 6. Handle Dry-Run Mode
    if mode == "dry-run":
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "DRY_RUN",
            "before_state": before_state,
            "detail": "[DRY-RUN] Would detach AdministratorAccess from user.",
        }

    # 7. Apply Remediation Change
    try:
        iam_client.detach_user_policy(
            UserName=resource_id,
            PolicyArn=target_policy_arn,
        )
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "SUCCESS",
            "before_state": before_state,
            "detail": "Detached AdministratorAccess from the user.",
        }

    except Exception as e:
        logger.error("Failed to detach admin policy from %s: %s", resource_id, e)
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "FAILED",
            "before_state": before_state,
            "detail": f"API error detaching policy: {str(e)}",
        }

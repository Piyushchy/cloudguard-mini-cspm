"""remediation.dispatcher — Orchestrates Remediation Actions

Dispatches findings from scan reports to their corresponding remediation action module.
Handles safety guards, modes, exception isolation, and non-automatable findings.
"""

import logging
from typing import Any, Dict, List

from remediation.actions.ec2_revoke_open_ingress import remediate_ec2_ingress
from remediation.actions.iam_detach_admin_policy import remediate_iam_admin_policy
from remediation.actions.s3_enable_bpa import remediate_s3_bpa
from remediation.actions.s3_enable_versioning import remediate_s3_versioning

logger = logging.getLogger("cloudguard.dispatcher")


def dispatch_actions(
    findings_data: Dict[str, Any],
    mode: str,
    s3_client: Any = None,
    ec2_client: Any = None,
    iam_client: Any = None,
) -> List[Dict[str, Any]]:
    """Dispatch all failed findings to their corresponding remediation handler."""
    actions_log: List[Dict[str, Any]] = []
    findings = findings_data.get("findings", [])

    for finding in findings:
        # Only evaluate failed findings
        if finding.get("status") != "FAIL":
            continue

        finding_id = finding.get("id", "")
        check_id = finding.get("check_id", "")
        resource_id = finding.get("resource_id", "")
        action_code = finding.get("remediation_action", "NONE")
        auto_remediable = finding.get("auto_remediable", False)

        # 1. Non-automatable findings (IAM-002, CT-001)
        if not auto_remediable or action_code == "NONE":
            detail = "Needs a human to remediate."
            if check_id == "IAM-002":
                detail = "Needs a human: register MFA or remove the console login profile."
            elif check_id == "CT-001":
                detail = "Needs a human: create and configure a multi-region CloudTrail trail."

            actions_log.append({
                "finding_id": finding_id,
                "check_id": check_id,
                "resource_id": resource_id,
                "action": "NONE",
                "result": "SKIPPED_NOT_AUTOMATABLE",
                "before_state": {},
                "detail": detail,
            })
            continue

        # 2. Mode 'alert-only': Record skipped
        if mode == "alert-only":
            actions_log.append({
                "finding_id": finding_id,
                "check_id": check_id,
                "resource_id": resource_id,
                "action": action_code,
                "result": "SKIPPED_ALERT_ONLY",
                "before_state": {},
                "detail": "Mode is alert-only. Resource modification is disabled.",
            })
            continue

        # 3. Dispatch to specific action handler with exception isolation
        try:
            if action_code == "S3_ENABLE_BPA":
                res = remediate_s3_bpa(finding, mode=mode, s3_client=s3_client)
            elif action_code == "S3_ENABLE_VERSIONING":
                res = remediate_s3_versioning(finding, mode=mode, s3_client=s3_client)
            elif action_code == "EC2_REVOKE_OPEN_INGRESS":
                res = remediate_ec2_ingress(finding, mode=mode, ec2_client=ec2_client)
            elif action_code == "IAM_DETACH_ADMIN_POLICY":
                res = remediate_iam_admin_policy(finding, mode=mode, iam_client=iam_client)
            else:
                res = {
                    "finding_id": finding_id,
                    "check_id": check_id,
                    "resource_id": resource_id,
                    "action": action_code,
                    "result": "SKIPPED_UNKNOWN_ACTION",
                    "before_state": {},
                    "detail": f"Unrecognized remediation action code: {action_code}",
                }
        except Exception as exc:
            logger.exception("Unexpected error executing %s on %s", action_code, resource_id)
            res = {
                "finding_id": finding_id,
                "check_id": check_id,
                "resource_id": resource_id,
                "action": action_code,
                "result": "FAILED",
                "before_state": {},
                "detail": f"Unhandled exception in action handler: {str(exc)}",
            }

        actions_log.append(res)

    return actions_log

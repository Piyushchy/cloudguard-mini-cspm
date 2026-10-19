"""remediation.actions.ec2_revoke_open_ingress — EC2-001 Remediation Action

Action Code: EC2_REVOKE_OPEN_INGRESS
Revokes overly permissive ingress rules (0.0.0.0/0 or ::/0 on ports 22, 3389, or all)
from the tagged security group.
"""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

from remediation.safety import is_resource_protected, verify_ec2_sg_tag

logger = logging.getLogger("cloudguard.actions.ec2_revoke_open_ingress")


def _is_risky_permission(perm: Dict[str, Any]) -> bool:
    """Identify open CIDR ranges (0.0.0.0/0 or ::/0) on sensitive ports."""
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    protocol = perm.get("IpProtocol")

    # Sensitive ports: 22 (SSH), 3389 (RDP), or all ports (-1)
    is_sensitive_port = False
    if protocol == "-1":
        is_sensitive_port = True
    elif from_port is not None and to_port is not None:
        if (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port):
            is_sensitive_port = True

    if not is_sensitive_port:
        return False, []

    risky_ip_ranges = []
    for ip_range in perm.get("IpRanges", []):
        if ip_range.get("CidrIp") == "0.0.0.0/0":
            risky_ip_ranges.append(ip_range)

    risky_ipv6_ranges = []
    for ipv6_range in perm.get("Ipv6Ranges", []):
        if ipv6_range.get("CidrIpv6") == "::/0":
            risky_ipv6_ranges.append(ipv6_range)

    return (len(risky_ip_ranges) > 0 or len(risky_ipv6_ranges) > 0)


def remediate_ec2_ingress(
    finding: Dict[str, Any],
    mode: str,
    ec2_client: Any = None,
) -> Dict[str, Any]:
    """Execute EC2_REVOKE_OPEN_INGRESS remediation according to safety contract."""
    finding_id = finding.get("id", "")
    check_id = finding.get("check_id", "EC2-001")
    resource_id = finding.get("resource_id", "")
    action_code = "EC2_REVOKE_OPEN_INGRESS"

    if ec2_client is None:
        ec2_client = boto3.client("ec2")

    # 1. Protection List Guard
    if is_resource_protected(resource_id, "ec2"):
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
    if not verify_ec2_sg_tag(ec2_client, resource_id):
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "SKIPPED_NOT_TAGGED",
            "before_state": {},
            "detail": f"Security Group {resource_id} is missing required tag cspm-remediate=true.",
        }

    # 3. Read Current State & Identify Risky Rules
    try:
        sg_resp = ec2_client.describe_security_groups(GroupIds=[resource_id])
        sgs = sg_resp.get("SecurityGroups", [])
        if not sgs:
            return {
                "finding_id": finding_id,
                "check_id": check_id,
                "resource_id": resource_id,
                "action": action_code,
                "result": "FAILED",
                "before_state": {},
                "detail": f"Security group {resource_id} not found.",
            }
        ip_permissions = sgs[0].get("IpPermissions", [])
    except ClientError as e:
        logger.error("Error describing SG %s: %s", resource_id, e)
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "FAILED",
            "before_state": {},
            "detail": f"API error describing security group: {str(e)}",
        }

    rules_to_revoke: List[Dict[str, Any]] = []
    before_state_rules: List[Dict[str, Any]] = []

    for perm in ip_permissions:
        protocol = perm.get("IpProtocol")
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        is_sensitive = (
            protocol == "-1"
            or (from_port is not None and to_port is not None and (
                from_port <= 22 <= to_port or from_port <= 3389 <= to_port
            ))
        )
        if not is_sensitive:
            continue

        # Check IPv4 0.0.0.0/0
        risky_ipv4 = [r for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
        if risky_ipv4:
            revoke_perm = {
                "IpProtocol": protocol,
                "FromPort": from_port,
                "ToPort": to_port,
                "IpRanges": risky_ipv4,
            }
            # Remove None values for protocol -1
            if protocol == "-1":
                revoke_perm.pop("FromPort", None)
                revoke_perm.pop("ToPort", None)

            rules_to_revoke.append(revoke_perm)
            for r in risky_ipv4:
                item = {"IpProtocol": protocol, "CidrIp": r.get("CidrIp")}
                if from_port is not None:
                    item["FromPort"] = from_port
                    item["ToPort"] = to_port
                before_state_rules.append(item)

        # Check IPv6 ::/0
        risky_ipv6 = [r for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
        if risky_ipv6:
            revoke_perm = {
                "IpProtocol": protocol,
                "FromPort": from_port,
                "ToPort": to_port,
                "Ipv6Ranges": risky_ipv6,
            }
            if protocol == "-1":
                revoke_perm.pop("FromPort", None)
                revoke_perm.pop("ToPort", None)

            rules_to_revoke.append(revoke_perm)
            for r in risky_ipv6:
                item = {"IpProtocol": protocol, "CidrIpv6": r.get("CidrIpv6")}
                if from_port is not None:
                    item["FromPort"] = from_port
                    item["ToPort"] = to_port
                before_state_rules.append(item)

    before_state = {"revoked_rules": before_state_rules}

    # 4. Check if Already Compliant
    if not rules_to_revoke:
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "ALREADY_COMPLIANT",
            "before_state": before_state,
            "detail": "No open ingress rules for port 22/3389/all found in security group.",
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
            "detail": f"[DRY-RUN] Would revoke {len(before_state_rules)} open ingress rule(s).",
        }

    # 6. Apply Remediation Change
    try:
        ec2_client.revoke_security_group_ingress(
            GroupId=resource_id,
            IpPermissions=rules_to_revoke,
        )
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "SUCCESS",
            "before_state": before_state,
            "detail": f"Revoked {len(before_state_rules)} open ingress rule(s).",
        }
    except Exception as e:
        logger.error("Failed to revoke ingress on %s: %s", resource_id, e)
        return {
            "finding_id": finding_id,
            "check_id": check_id,
            "resource_id": resource_id,
            "action": action_code,
            "result": "FAILED",
            "before_state": before_state,
            "detail": f"API error revoking security group ingress: {str(e)}",
        }

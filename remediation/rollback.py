"""remediation.rollback — Restores Previous AWS Configuration from Remediation Logs

Parses a remediation log JSON file, extracts 'before_state', and reverts changes
for EC2 Security Groups, IAM User Policies, and S3 Block Public Access.
Enables reliable retakes during demo recording and testing.

Usage:
    python remediation/rollback.py --log samples/remediation_log.json --profile cspm-p3
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cloudguard.rollback")


def rollback_s3_bpa(s3_client, resource_id: str, before_state: dict):
    logger.info("Rolling back S3 BPA on %s to: %s", resource_id, before_state)
    try:
        s3_client.put_public_access_block(
            Bucket=resource_id,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": before_state.get("BlockPublicAcls", False),
                "IgnorePublicAcls": before_state.get("IgnorePublicAcls", False),
                "BlockPublicPolicy": before_state.get("BlockPublicPolicy", False),
                "RestrictPublicBuckets": before_state.get("RestrictPublicBuckets", False),
            },
        )
        logger.info("[SUCCESS] Rolled back S3 BPA on %s", resource_id)
    except ClientError as e:
        logger.error("Failed to rollback S3 BPA on %s: %s", resource_id, e)


def rollback_ec2_ingress(ec2_client, resource_id: str, before_state: dict):
    revoked_rules = before_state.get("revoked_rules", [])
    if not revoked_rules:
        logger.info("No revoked rules found to restore on SG %s", resource_id)
        return

    logger.info("Restoring %d revoked ingress rules on %s...", len(revoked_rules), resource_id)
    for rule in revoked_rules:
        try:
            protocol = rule.get("IpProtocol", "tcp")
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")
            cidr = rule.get("CidrIp")

            ip_perm = {"IpProtocol": protocol}
            if from_port is not None:
                ip_perm["FromPort"] = from_port
            if to_port is not None:
                ip_perm["ToPort"] = to_port
            if cidr:
                ip_perm["IpRanges"] = [{"CidrIp": cidr}]

            ec2_client.authorize_security_group_ingress(
                GroupId=resource_id,
                IpPermissions=[ip_perm],
            )
            logger.info("[SUCCESS] Re-authorized %s rule on port %s-%s to %s", protocol, from_port, to_port, cidr)
        except ClientError as e:
            if "InvalidPermission.Duplicate" in str(e):
                logger.info("Rule already exists on SG %s", resource_id)
            else:
                logger.error("Failed to restore ingress rule on %s: %s", resource_id, e)


def rollback_iam_policy(iam_client, resource_id: str, before_state: dict):
    attached_policies = before_state.get("attached_policies", [])
    if not attached_policies:
        logger.info("No previously attached policies to restore for %s", resource_id)
        return

    for policy_arn in attached_policies:
        logger.info("Re-attaching policy %s to user %s...", policy_arn, resource_id)
        try:
            iam_client.attach_user_policy(
                UserName=resource_id,
                PolicyArn=policy_arn,
            )
            logger.info("[SUCCESS] Re-attached %s to %s", policy_arn, resource_id)
        except ClientError as e:
            logger.error("Failed to re-attach policy %s: %s", policy_arn, e)


def main():
    parser = argparse.ArgumentParser(description="CloudGuard Remediation Rollback CLI")
    parser.add_argument("--log", required=True, help="Path to remediation log JSON file")
    parser.add_argument("--profile", default="cspm-p3", help="AWS CLI profile name (default: cspm-p3)")
    parser.add_argument("--region", default="ap-south-1", help="AWS Region (default: ap-south-1)")
    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        logger.error("Log file not found: %s", log_path)
        sys.exit(1)

    with open(log_path, "r", encoding="utf-8") as f:
        log_data = json.load(f)

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    iam = session.client("iam")

    actions = log_data.get("actions", [])
    logger.info("Processing rollback for %d actions from %s...", len(actions), log_path)

    for action in actions:
        act_code = action.get("action")
        res_id = action.get("resource_id")
        result = action.get("result")
        before_state = action.get("before_state", {})

        if result != "SUCCESS":
            logger.info("Skipping %s on %s (result was %s, no changes applied)", act_code, res_id, result)
            continue

        if act_code == "S3_ENABLE_BPA":
            rollback_s3_bpa(s3, res_id, before_state)
        elif act_code == "EC2_REVOKE_OPEN_INGRESS":
            rollback_ec2_ingress(ec2, res_id, before_state)
        elif act_code == "IAM_DETACH_ADMIN_POLICY":
            rollback_iam_policy(iam, res_id, before_state)
        elif act_code == "S3_ENABLE_VERSIONING":
            logger.info("Note: S3 versioning cannot be disabled via API once enabled (only suspended). Leaving as is.")

    print("\n" + "=" * 60)
    print("ROLLBACK PROCESSING COMPLETE")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()

"""remediation.teardown — Clean Up All P3 AWS Resources

Safely deletes:
1. S3 bucket notification trigger on reports bucket.
2. Lambda function 'cspm-demo-remediator' and concurrency config.
3. CloudWatch Log group '/aws/lambda/cspm-demo-remediator'.
4. IAM role 'cspm-demo-remediator-role' and attached inline policy.
5. SNS topic 'cspm-demo-alerts' and email subscriptions.

Usage:
    python remediation/teardown.py --profile cspm-p3
"""

import argparse
import logging
import sys

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cloudguard.teardown")

FUNCTION_NAME = "cspm-demo-remediator"
ROLE_NAME = "cspm-demo-remediator-role"
POLICY_NAME = "cspm-demo-remediator-policy"
TOPIC_NAME = "cspm-demo-alerts"


def main():
    parser = argparse.ArgumentParser(description="CloudGuard P3 Teardown Script")
    parser.add_argument("--profile", default="cspm-p3", help="AWS CLI profile name (default: cspm-p3)")
    parser.add_argument("--region", default="ap-south-1", help="AWS Region (default: ap-south-1)")
    parser.add_argument("--bucket", help="Reports bucket name")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    reports_bucket = args.bucket or f"cspm-demo-reports-{account_id}"

    s3 = session.client("s3")
    lambda_client = session.client("lambda")
    iam = session.client("iam")
    logs = session.client("logs")
    sns = session.client("sns")

    logger.info("Beginning P3 cleanup on AWS Account %s...", account_id)

    # 1. Clear S3 Notifications
    try:
        logger.info("Clearing S3 notification configuration on %s...", reports_bucket)
        s3.put_bucket_notification_configuration(
            Bucket=reports_bucket,
            NotificationConfiguration={},
        )
        logger.info("[OK] Removed S3 bucket notifications.")
    except Exception as e:
        logger.warning("Could not clear S3 notification (bucket may be deleted or unreadable): %s", e)

    # 2. Delete Lambda Function
    try:
        logger.info("Deleting Lambda function %s...", FUNCTION_NAME)
        lambda_client.delete_function(FunctionName=FUNCTION_NAME)
        logger.info("[OK] Lambda function deleted.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            logger.info("Lambda function does not exist.")
        else:
            logger.warning("Error deleting Lambda: %s", e)

    # 3. Delete CloudWatch Log Group
    log_group_name = f"/aws/lambda/{FUNCTION_NAME}"
    try:
        logger.info("Deleting log group %s...", log_group_name)
        logs.delete_log_group(logGroupName=log_group_name)
        logger.info("[OK] Log group deleted.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            logger.info("Log group does not exist.")
        else:
            logger.warning("Error deleting log group: %s", e)

    # 4. Delete IAM Role & Policies
    try:
        logger.info("Deleting inline policy %s from role %s...", POLICY_NAME, ROLE_NAME)
        iam.delete_role_policy(RoleName=ROLE_NAME, PolicyName=POLICY_NAME)
        logger.info("[OK] Deleted role policy.")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            logger.warning("Error deleting role policy: %s", e)

    try:
        logger.info("Deleting IAM role %s...", ROLE_NAME)
        iam.delete_role(RoleName=ROLE_NAME)
        logger.info("[OK] Deleted IAM role.")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            logger.warning("Error deleting IAM role: %s", e)

    # 5. Delete SNS Topic
    topic_arn = f"arn:aws:sns:{args.region}:{account_id}:{TOPIC_NAME}"
    try:
        logger.info("Deleting SNS topic %s...", topic_arn)
        sns.delete_topic(TopicArn=topic_arn)
        logger.info("[OK] SNS topic deleted.")
    except Exception as e:
        logger.warning("Error deleting SNS topic: %s", e)

    print("\n" + "=" * 60)
    print("P3 TEARDOWN COMPLETE")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()

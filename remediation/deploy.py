"""remediation.deploy — Deployment Script for CloudGuard Remediator Lambda

Automates end-to-end serverless deployment:
1. Creates/Updates IAM role 'cspm-demo-remediator-role' with least-privilege policy.
2. Packages Lambda code, schema, and dependencies into a deployment zip.
3. Deploys/Updates Lambda function 'cspm-demo-remediator' (Python 3.13, 256MB, 60s timeout).
4. Enforces reserved concurrency = 1.
5. Grants S3 permission to invoke the Lambda function.
6. Configures S3 bucket notification on 'cspm-demo-reports-<ACCOUNT_ID>' for 'scans/*.json'.
"""

import argparse
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cloudguard.deploy")

ROLE_NAME = "cspm-demo-remediator-role"
FUNCTION_NAME = "cspm-demo-remediator"
POLICY_NAME = "cspm-demo-remediator-policy"
RUNTIME = "python3.13"


def create_deployment_package(package_zip_path: Path) -> None:
    """Build a zip package containing handler, actions, schema, and pure-python dependencies."""
    logger.info("Building deployment package...")
    root_dir = Path(__file__).resolve().parent.parent
    remediation_dir = root_dir / "remediation"
    schema_path = root_dir / "shared" / "findings.schema.json"

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        pkg_dir = tmp_dir / "package"
        pkg_dir.mkdir(parents=True, exist_ok=True)

        # 1. Install pure-python and manylinux runtime dependencies into package
        logger.info("Installing runtime dependencies for Amazon Linux (jsonschema, rpds-py)...")
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--platform",
                "manylinux2014_x86_64",
                "--only-binary=:all:",
                "--implementation",
                "cp",
                "--python-version",
                "3.13",
                "jsonschema",
                "rpds-py",
                "--target",
                str(pkg_dir),
                "--no-user",
                "--quiet",
            ]
        )


        # 2. Copy remediation source files
        # Copy handler, dispatcher, safety to package root
        for py_file in ["handler.py", "dispatcher.py", "safety.py"]:
            src = remediation_dir / py_file
            if src.exists():
                shutil.copy2(src, pkg_dir / py_file)

        # Copy actions/ directory
        actions_dest = pkg_dir / "remediation" / "actions"
        actions_dest.mkdir(parents=True, exist_ok=True)
        for act_file in (remediation_dir / "actions").glob("*.py"):
            shutil.copy2(act_file, actions_dest / act_file.name)
            # Also copy to root actions/ for direct import
            root_actions = pkg_dir / "actions"
            root_actions.mkdir(parents=True, exist_ok=True)
            shutil.copy2(act_file, root_actions / act_file.name)

        # Also keep remediation/ package structure
        for py_file in ["__init__.py", "handler.py", "dispatcher.py", "safety.py"]:
            src = remediation_dir / py_file
            if src.exists():
                shutil.copy2(src, pkg_dir / "remediation" / py_file)

        # Copy schema
        if schema_path.exists():
            shutil.copy2(schema_path, pkg_dir / "findings.schema.json")
            shared_dir = pkg_dir / "shared"
            shared_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(schema_path, shared_dir / "findings.schema.json")

        # 3. Create zip
        package_zip_path.parent.mkdir(parents=True, exist_ok=True)
        if package_zip_path.exists():
            package_zip_path.unlink()

        shutil.make_archive(
            base_name=str(package_zip_path.with_suffix("")),
            format="zip",
            root_dir=str(pkg_dir),
        )
        logger.info("Created deployment zip at %s (size: %d bytes)", package_zip_path, package_zip_path.stat().st_size)


def setup_iam_role(iam_client: Any, account_id: str) -> str:
    """Create or update Lambda execution role with least-privilege policy."""
    iam_dir = Path(__file__).resolve().parent / "iam"
    trust_policy_path = iam_dir / "trust_policy.json"
    policy_path = iam_dir / "policy.json"

    with open(trust_policy_path, "r", encoding="utf-8") as f:
        trust_policy_str = f.read()

    with open(policy_path, "r", encoding="utf-8") as f:
        policy_doc_str = f.read().replace("310788607340", account_id)

    # 1. Ensure Role exists
    try:
        role_resp = iam_client.get_role(RoleName=ROLE_NAME)
        role_arn = role_resp["Role"]["Arn"]
        logger.info("Found existing IAM role: %s", role_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            logger.info("Creating IAM role %s...", ROLE_NAME)
            role_resp = iam_client.create_role(
                RoleName=ROLE_NAME,
                AssumeRolePolicyDocument=trust_policy_str,
                Description="CloudGuard Mini-CSPM Remediation Lambda execution role",
                Tags=[
                    {"Key": "Project", "Value": "cspm-demo"},
                    {"Key": "Owner", "Value": "P3"},
                ],
            )
            role_arn = role_resp["Role"]["Arn"]
            logger.info("Created IAM role: %s", role_arn)
            # Sleep briefly for IAM propagation
            time.sleep(8)
        else:
            raise


    # 2. Put inline least privilege policy
    logger.info("Applying inline least-privilege policy %s...", POLICY_NAME)
    iam_client.put_role_policy(
        RoleName=ROLE_NAME,
        PolicyName=POLICY_NAME,
        PolicyDocument=policy_doc_str,
    )
    return role_arn


def deploy_lambda_function(
    lambda_client: Any,
    role_arn: str,
    zip_bytes: bytes,
    topic_arn: str,
    reports_bucket: str,
    mode: str = "alert-only",
) -> str:
    """Create or update the Lambda function and set reserved concurrency."""
    env_vars = {
        "MODE": mode,
        "TOPIC_ARN": topic_arn,
        "REPORTS_BUCKET": reports_bucket,
    }

    try:
        fn_resp = lambda_client.get_function(FunctionName=FUNCTION_NAME)
        fn_arn = fn_resp["Configuration"]["FunctionArn"]
        logger.info("Updating existing Lambda function code: %s", FUNCTION_NAME)
        lambda_client.update_function_code(
            FunctionName=FUNCTION_NAME,
            ZipFile=zip_bytes,
        )
        time.sleep(3)
        logger.info("Updating Lambda configuration...")
        lambda_client.update_function_configuration(
            FunctionName=FUNCTION_NAME,
            Role=role_arn,
            Handler="handler.lambda_handler",
            Timeout=60,
            MemorySize=256,
            Environment={"Variables": env_vars},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            logger.info("Creating Lambda function %s...", FUNCTION_NAME)
            # Retry loop in case IAM role newly created is still propagating
            for attempt in range(6):
                try:
                    create_resp = lambda_client.create_function(
                        FunctionName=FUNCTION_NAME,
                        Runtime=RUNTIME,
                        Role=role_arn,
                        Handler="handler.lambda_handler",
                        Code={"ZipFile": zip_bytes},
                        Description="CloudGuard Mini-CSPM alert & remediation processor",
                        Timeout=60,
                        MemorySize=256,
                        Publish=True,
                        Environment={"Variables": env_vars},
                        Tags={
                            "Project": "cspm-demo",
                            "Owner": "P3",
                        },
                    )
                    fn_arn = create_resp["FunctionArn"]
                    logger.info("Created Lambda function: %s", fn_arn)
                    break
                except ClientError as create_err:
                    if "The role defined for the function cannot be assumed by Lambda" in str(create_err):
                        logger.info("Waiting for IAM role to propagate (attempt %d/6)...", attempt + 1)
                        time.sleep(6)
                    else:
                        raise
        else:
            raise

    # Enforce Reserved Concurrency = 1 (Contract A6 rule 5)
    logger.info("Setting reserved concurrency = 1 (loop and cost safety)...")
    try:
        lambda_client.put_function_concurrency(
            FunctionName=FUNCTION_NAME,
            ReservedConcurrentExecutions=1,
        )
    except ClientError as ce:
        logger.warning("Could not set reserved concurrency: %s", ce)

    return fn_arn


def wire_s3_notifications(
    s3_client: Any,
    lambda_client: Any,
    bucket_name: str,
    function_arn: str,
    account_id: str,
) -> None:
    """Add invoke permission and configure S3 ObjectCreated notification for scans/*.json."""
    logger.info("Configuring Lambda permission for S3 invocation...")
    statement_id = "AllowS3InvokeCloudGuardRemediator"
    try:
        lambda_client.add_permission(
            FunctionName=FUNCTION_NAME,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
            SourceArn=f"arn:aws:s3:::{bucket_name}",
            SourceAccount=account_id,
        )
        logger.info("Added S3 invoke permission to Lambda.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceConflictException":
            logger.info("S3 invoke permission already present.")
        else:
            logger.warning("Error adding permission: %s", e)

    # Configure S3 Notification
    logger.info("Configuring S3 notification on %s (prefix: scans/, suffix: .json)...", bucket_name)
    notification_conf = {
        "LambdaFunctionConfigurations": [
            {
                "Id": "CloudGuardScanUploadTrigger",
                "LambdaFunctionArn": function_arn,
                "Events": ["s3:ObjectCreated:*"],
                "Filter": {
                    "Key": {
                        "FilterRules": [
                            {"Name": "prefix", "Value": "scans/"},
                            {"Name": "suffix", "Value": ".json"},
                        ]
                    }
                },
            }
        ]
    }
    try:
        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration=notification_conf,
        )
        logger.info("S3 bucket notification successfully configured!")
    except ClientError as e:
        logger.warning(
            "Could not set S3 bucket notification on %s: %s "
            "(Teammate P1 may need to grant s3:PutBucketNotification or bucket may not exist yet)",
            bucket_name,
            e,
        )


def main():
    parser = argparse.ArgumentParser(description="CloudGuard Remediator Deployment CLI")
    parser.add_argument("--profile", default="cspm-p3", help="AWS CLI profile name (default: cspm-p3)")
    parser.add_argument("--region", default="ap-south-1", help="AWS Region (default: ap-south-1)")
    parser.add_argument("--mode", default="alert-only", choices=["alert-only", "dry-run", "remediate"])
    parser.add_argument("--bucket", help="Reports bucket name (default: cspm-demo-reports-<ACCOUNT_ID>)")
    parser.add_argument("--topic-arn", help="SNS Topic ARN (default: arn:aws:sns:region:account:cspm-demo-alerts)")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    sts = session.client("sts")
    iam = session.client("iam")
    lambda_client = session.client("lambda")
    s3 = session.client("s3")

    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    logger.info("Connected to AWS Account %s as %s", account_id, identity["Arn"])

    reports_bucket = args.bucket or f"cspm-demo-reports-{account_id}"
    topic_arn = args.topic_arn or f"arn:aws:sns:{args.region}:{account_id}:cspm-demo-alerts"

    # Step 1: IAM Role
    role_arn = setup_iam_role(iam, account_id)

    # Step 2: Zip Package
    zip_path = Path(__file__).resolve().parent / "build" / "lambda.zip"
    create_deployment_package(zip_path)

    with open(zip_path, "rb") as f:
        zip_bytes = f.read()

    # Step 3: Deploy Lambda
    fn_arn = deploy_lambda_function(
        lambda_client=lambda_client,
        role_arn=role_arn,
        zip_bytes=zip_bytes,
        topic_arn=topic_arn,
        reports_bucket=reports_bucket,
        mode=args.mode,
    )

    # Step 4: S3 Notification Wiring
    wire_s3_notifications(
        s3_client=s3,
        lambda_client=lambda_client,
        bucket_name=reports_bucket,
        function_arn=fn_arn,
        account_id=account_id,
    )

    print("\n" + "=" * 60)
    print("DEPLOYMENT SUCCESSFUL")
    print("=" * 60)
    print(f"Function Name:     {FUNCTION_NAME}")
    print(f"Function ARN:      {fn_arn}")
    print(f"IAM Role:          {role_arn}")
    print(f"Mode:              {args.mode}")
    print(f"SNS Topic ARN:     {topic_arn}")
    print(f"Reports Bucket:    {reports_bucket}")
    print(f"Trigger:           s3://{reports_bucket}/scans/*.json")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()

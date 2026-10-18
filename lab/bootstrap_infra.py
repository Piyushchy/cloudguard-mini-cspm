"""
bootstrap_infra.py - Provisions shared infrastructure for CloudGuard Mini-CSPM:
  1. Reports bucket: cspm-demo-reports-<ACCOUNT_ID> (BPA on, versioning on, SSE-S3, 30-day lifecycle)
  2. CloudTrail log bucket: cspm-demo-trail-logs-<ACCOUNT_ID> (BPA on, CloudTrail policy)
  3. CloudTrail trail: cspm-demo-trail (multi-region, management events only, logging enabled)

Part of P1 (Lab & Platform) Phase 1.
Supports --dry-run and idempotent re-runs.
"""

import argparse
import json
import boto3
from botocore.exceptions import ClientError

REGION = "ap-south-1"
ACCOUNT_ID = "310788607340"

REPORTS_BUCKET = f"cspm-demo-reports-{ACCOUNT_ID}"
TRAIL_LOGS_BUCKET = f"cspm-demo-trail-logs-{ACCOUNT_ID}"
TRAIL_NAME = "cspm-demo-trail"

COMMON_TAGS = [
    {"Key": "Project", "Value": "cspm-demo"},
    {"Key": "ManagedBy", "Value": "p1-bootstrap"},
]


def create_bucket_if_missing(s3, bucket_name: str, region: str, dry_run: bool = False):
    print(f"[*] Checking S3 bucket: {bucket_name}...")
    if dry_run:
        print(f"    [DRY-RUN] Would check/create bucket '{bucket_name}' in {region}.")
        return

    try:
        s3.head_bucket(Bucket=bucket_name)
        print(f"    Bucket '{bucket_name}' already exists.")
    except ClientError as e:
        err_code = e.response["Error"]["Code"]
        if err_code in ("404", "NoSuchBucket"):
            create_args = {"Bucket": bucket_name}
            if region != "us-east-1":
                create_args["CreateBucketConfiguration"] = {"LocationConstraint": region}
            s3.create_bucket(**create_args)
            print(f"    Created bucket '{bucket_name}'.")
        else:
            raise


def configure_reports_bucket(s3, bucket_name: str, dry_run: bool = False):
    print(f"[*] Configuring reports bucket: {bucket_name}...")
    if dry_run:
        print("    [DRY-RUN] Would enable BPA (all 4), versioning, SSE-S3, and 30-day lifecycle expiration.")
        return

    # 1. Block Public Access (all four settings ON)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    print("    Block Public Access configured (all ON).")

    # 2. Versioning ON
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )
    print("    Versioning enabled.")

    # 3. Default SSE-S3 Encryption
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    print("    Default SSE-S3 encryption enabled.")

    # 4. Lifecycle rule (expire objects after 30 days to keep storage cost at $0)
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket_name,
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "ExpireReportsAfter30Days",
                    "Status": "Enabled",
                    "Filter": {"Prefix": ""},
                    "Expiration": {"Days": 30},
                    "NoncurrentVersionExpiration": {"NoncurrentDays": 30},
                }
            ]
        },
    )
    print("    30-day expiration lifecycle rule applied.")

    # 5. Tag bucket
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": COMMON_TAGS})
    print("    Tags applied.")


def configure_trail_logs_bucket(s3, bucket_name: str, account_id: str, dry_run: bool = False):
    print(f"[*] Configuring CloudTrail log bucket: {bucket_name}...")
    if dry_run:
        print("    [DRY-RUN] Would enable BPA, default encryption, and CloudTrail bucket policy.")
        return

    # 1. Block Public Access
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    print("    Block Public Access configured.")

    # 2. Default encryption
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    print("    Default SSE-S3 encryption enabled.")

    # 3. CloudTrail bucket policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                    }
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
    print("    CloudTrail access policy applied.")

    # 4. Tag bucket
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": COMMON_TAGS})
    print("    Tags applied.")


def setup_cloudtrail(ct, trail_name: str, bucket_name: str, dry_run: bool = False):
    print(f"[*] Configuring CloudTrail trail: {trail_name}...")
    if dry_run:
        print(f"    [DRY-RUN] Would create/update multi-region trail '{trail_name}' and start logging.")
        return

    try:
        ct.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IncludeGlobalServiceEvents=True,
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True,
            TagsList=COMMON_TAGS,
        )
        print(f"    Created CloudTrail '{trail_name}'.")
    except ClientError as e:
        if e.response["Error"]["Code"] in ("TrailAlreadyExistsException", "InvalidTrailNameException"):
            print(f"    Trail '{trail_name}' already exists. Updating...")
            ct.update_trail(
                Name=trail_name,
                S3BucketName=bucket_name,
                IncludeGlobalServiceEvents=True,
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
            )
        else:
            raise

    # Start logging
    ct.start_logging(Name=trail_name)
    print("    CloudTrail logging started.")


def main():
    parser = argparse.ArgumentParser(description="Bootstrap shared infrastructure for CloudGuard Mini-CSPM.")
    parser.add_argument("--profile", default="cspm-p1", help="AWS CLI profile to use (default: cspm-p1)")
    parser.add_argument("--region", default=REGION, help=f"AWS Region (default: {REGION})")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without modifying AWS")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    s3 = session.client("s3")
    ct = session.client("cloudtrail")

    print(f"=== CloudGuard Bootstrap Infra (profile={args.profile}, region={args.region}, dry_run={args.dry_run}) ===")

    # 1. Reports Bucket
    create_bucket_if_missing(s3, REPORTS_BUCKET, args.region, args.dry_run)
    configure_reports_bucket(s3, REPORTS_BUCKET, args.dry_run)

    # 2. CloudTrail Bucket
    create_bucket_if_missing(s3, TRAIL_LOGS_BUCKET, args.region, args.dry_run)
    configure_trail_logs_bucket(s3, TRAIL_LOGS_BUCKET, ACCOUNT_ID, args.dry_run)

    # 3. CloudTrail Trail
    setup_cloudtrail(ct, TRAIL_NAME, TRAIL_LOGS_BUCKET, args.dry_run)

    print("\n=== Bootstrap Infra Completed Successfully ===")


if __name__ == "__main__":
    main()

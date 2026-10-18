"""All checks. Each module exposes run(session, region, warnings=None, account_id=None)."""
from scanner.checks import cloudtrail, ec2, iam, s3

ALL_CHECKS = [s3, ec2, iam, cloudtrail]

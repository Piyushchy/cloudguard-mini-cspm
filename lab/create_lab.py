"""
create_lab.py - Creates the deliberately vulnerable lab resources for CloudGuard Mini-CSPM:
  1. S3 bucket: cspm-demo-vuln-bucket-<ACCOUNT_ID> (BPA off, versioning off, public hello.txt) -> S3-001 & S3-002
  2. EC2 Security Group: cspm-demo-vuln-sg (port 22 open to 0.0.0.0/0, no instance attached) -> EC2-001
  3. IAM user: cspm-demo-vuln-user (AdministratorAccess, console login with discarded password, no MFA) -> IAM-001 & IAM-002

All resources are tagged with:
  Project=cspm-demo, Deliberate=true, cspm-remediate=true

Part of P1 (Lab & Platform) Phase 2.
Supports --dry-run and idempotent execution.
"""

import argparse
import json
import sys
from pathlib import Path

# Add repo root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
from botocore.exceptions import ClientError
from lab.lab_common import (
    REGION,
    ACCOUNT_ID,
    VULN_BUCKET,
    VULN_SG_NAME,
    VULN_IAM_USER,
    LAB_TAGS,
    generate_unusable_password,
    get_default_vpc_id,
)


def setup_vuln_s3(s3, s3control, bucket_name: str, region: str, dry_run: bool = False):
    print(f"\n[+] Setting up vulnerable S3 bucket: {bucket_name}...")
    if dry_run:
        print(f"    [DRY-RUN] Would create {bucket_name} in {region} with BPA disabled and public policy.")
        return

    # Check account-level BPA first
    try:
        acct_bpa = s3control.get_public_access_block(AccountId=ACCOUNT_ID)["PublicAccessBlockConfiguration"]
        if acct_bpa.get("BlockPublicPolicy", False) or acct_bpa.get("RestrictPublicBuckets", False):
            print("    [!] WARNING: Account-level S3 Block Public Access is currently ENABLED.")
            print("        For S3-001 to demonstrate a public bucket, account-level BPA must allow public policies.")
    except ClientError:
        pass

    # 1. Create bucket if missing
    try:
        s3.head_bucket(Bucket=bucket_name)
        print(f"    Bucket '{bucket_name}' already exists.")
    except ClientError:
        create_args = {"Bucket": bucket_name}
        if region != "us-east-1":
            create_args["CreateBucketConfiguration"] = {"LocationConstraint": region}
        s3.create_bucket(**create_args)
        print(f"    Created bucket '{bucket_name}'.")

    # 2. Tag bucket
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": LAB_TAGS})
    print("    Applied deliberate tags.")

    # 3. Disable bucket-level Block Public Access (all 4 False)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    print("    Bucket-level Block Public Access turned OFF (vulnerable).")

    # 4. Upload harmless demo file
    demo_content = b"demo only, not sensitive"
    s3.put_object(Bucket=bucket_name, Key="public-demo/hello.txt", Body=demo_content)
    print("    Uploaded 'public-demo/hello.txt'.")

    # 5. Apply public policy on hello.txt
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadDemoObjectOnly",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/public-demo/hello.txt",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
    print("    Public read bucket policy applied (vulnerable: S3-001).")
    print("    Versioning left disabled (vulnerable: S3-002).")


def setup_vuln_sg(ec2, sg_name: str, dry_run: bool = False) -> str:
    print(f"\n[+] Setting up vulnerable Security Group: {sg_name}...")
    if dry_run:
        print(f"    [DRY-RUN] Would create {sg_name} in default VPC with inbound port 22 open to 0.0.0.0/0.")
        return "sg-dryrun"

    vpc_id = get_default_vpc_id(ec2)
    print(f"    Using VPC: {vpc_id}")

    # Check if SG exists
    try:
        res = ec2.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": [sg_name]},
                {"Name": "vpc-id", "Values": [vpc_id]},
            ]
        )
        if res["SecurityGroups"]:
            sg_id = res["SecurityGroups"][0]["GroupId"]
            print(f"    Security group '{sg_name}' already exists ({sg_id}).")
        else:
            create_res = ec2.create_security_group(
                GroupName=sg_name,
                Description="CloudGuard CSPM demo vulnerable security group with port 22 open",
                VpcId=vpc_id,
                TagSpecifications=[
                    {
                        "ResourceType": "security-group",
                        "Tags": LAB_TAGS + [{"Key": "Name", "Value": sg_name}],
                    }
                ],
            )
            sg_id = create_res["GroupId"]
            print(f"    Created security group '{sg_name}' ({sg_id}).")
    except ClientError as e:
        print(f"    Error finding/creating SG: {e}")
        raise

    # Ensure open port 22 ingress rule is present
    try:
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Open SSH (deliberate vulnerability)"}],
                }
            ],
        )
        print("    Inbound rule added: TCP 22 open to 0.0.0.0/0 (vulnerable: EC2-001).")
    except ClientError as e:
        if "InvalidPermission.Duplicate" in str(e):
            print("    Inbound rule TCP 22 to 0.0.0.0/0 already present.")
        else:
            raise

    return sg_id


def setup_vuln_iam(iam, username: str, dry_run: bool = False):
    print(f"\n[+] Setting up vulnerable IAM user: {username}...")
    if dry_run:
        print(f"    [DRY-RUN] Would create user {username}, attach AdministratorAccess, and create console profile with discarded password.")
        return

    # 1. Create user if missing
    try:
        iam.get_user(UserName=username)
        print(f"    User '{username}' already exists.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            iam.create_user(UserName=username, Tags=LAB_TAGS)
            print(f"    Created user '{username}'.")
        else:
            raise

    # Ensure tags
    iam.tag_user(UserName=username, Tags=LAB_TAGS)

    # 2. Attach AdministratorAccess directly (vulnerable: IAM-001)
    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    try:
        iam.attach_user_policy(UserName=username, PolicyArn=admin_arn)
        print(f"    Attached {admin_arn} directly (vulnerable: IAM-001).")
    except ClientError as e:
        print(f"    Error attaching admin policy: {e}")

    # 3. Create console login profile with random password that is discarded (vulnerable: IAM-002)
    # No access keys are created.
    try:
        dummy_password = generate_unusable_password()
        iam.create_login_profile(
            UserName=username,
            Password=dummy_password,
            PasswordResetRequired=False,
        )
        print("    Created console login profile with random discarded password (vulnerable: IAM-002).")
        print("    [!] Password was NOT logged or stored. No sign-in possible.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print("    Console login profile already exists (no MFA = vulnerable: IAM-002).")
        else:
            raise


def main():
    parser = argparse.ArgumentParser(description="Create CloudGuard Mini-CSPM deliberately vulnerable lab.")
    parser.add_argument("--profile", default="cspm-p1", help="AWS CLI profile to use (default: cspm-p1)")
    parser.add_argument("--region", default=REGION, help=f"AWS Region (default: {REGION})")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without modifying AWS")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    s3 = session.client("s3")
    s3control = session.client("s3control", region_name=args.region)
    ec2 = session.client("ec2")
    iam = session.client("iam")

    print(f"=== CloudGuard Lab Creation (profile={args.profile}, region={args.region}, dry_run={args.dry_run}) ===")

    setup_vuln_s3(s3, s3control, VULN_BUCKET, args.region, args.dry_run)
    setup_vuln_sg(ec2, VULN_SG_NAME, args.dry_run)
    setup_vuln_iam(iam, VULN_IAM_USER, args.dry_run)

    print("\n=== Lab Creation Finished Successfully ===")
    if not args.dry_run:
        print("Run 'python lab/verify_lab.py' to confirm all 5 expected FAIL misconfigurations.")


if __name__ == "__main__":
    main()

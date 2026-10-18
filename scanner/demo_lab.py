"""Offline demo helpers - FAKE AWS only (moto). Nothing here touches a real account.

build_lab()             creates the deliberately vulnerable lab inside moto, mirroring
                        what P1's lab/create_lab.py will build in the real account.
simulate_remediation()  imitates what P3's Lambda will do so the demo can show a
                        before/after story. The REAL remediation is P3's job; this is
                        only a stand-in for local demos and tests.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

REGION = "ap-south-1"
LOC = {"LocationConstraint": REGION}
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
VULN_USER = "cspm-demo-vuln-user"


def names(account_id: str) -> dict:
    return {
        "vuln_bucket": f"cspm-demo-vuln-bucket-{account_id}",
        "reports_bucket": f"cspm-demo-reports-{account_id}",
        "trail_bucket": f"cspm-demo-trail-logs-{account_id}",
    }


def build_lab(session) -> dict:
    """Create the lab. Returns the ids the demo needs later."""
    # moto only knows AWS-managed policies (e.g. AdministratorAccess) if this is on.
    os.environ["MOTO_IAM_LOAD_MANAGED_POLICIES"] = "true"
    acct = session.client("sts").get_caller_identity()["Account"]
    n = names(acct)
    s3 = session.client("s3", region_name=REGION)
    ec2 = session.client("ec2", region_name=REGION)
    iam = session.client("iam", region_name=REGION)
    ct = session.client("cloudtrail", region_name=REGION)

    # --- safe buckets (reports + trail logs): private, versioned, BPA on
    for b in (n["reports_bucket"], n["trail_bucket"]):
        s3.create_bucket(Bucket=b, CreateBucketConfiguration=LOC)
        s3.put_public_access_block(Bucket=b, PublicAccessBlockConfiguration={
            k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")})
        s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={"Status": "Enabled"})

    # --- vulnerable bucket: public-read policy, no BPA, no versioning
    v = n["vuln_bucket"]
    s3.create_bucket(Bucket=v, CreateBucketConfiguration=LOC)
    s3.put_object(Bucket=v, Key="hello.txt", Body=b"harmless demo file")
    s3.put_bucket_policy(Bucket=v, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
                       "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{v}/*"}]}))

    # --- vulnerable security group: SSH open to the world
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="cspm-demo-vuln-sg", Description="demo", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    # --- vulnerable IAM user: console password, no MFA, AdministratorAccess
    iam.create_user(UserName=VULN_USER)
    iam.create_login_profile(UserName=VULN_USER, Password="Dem0-Only-Pa55word!", PasswordResetRequired=False)
    iam.attach_user_policy(UserName=VULN_USER, PolicyArn=ADMIN_ARN)

    # --- CloudTrail: multi-region, logging on
    ct.create_trail(Name="cspm-demo-trail", S3BucketName=n["trail_bucket"], IsMultiRegionTrail=True)
    ct.start_logging(Name="cspm-demo-trail")

    return {"account_id": acct, "vuln_sg": sg, **n}


def simulate_remediation(session, lab: dict, scan: dict) -> dict:
    """Apply the four reversible fixes and return a remediation log (contract A5)."""
    s3 = session.client("s3", region_name=REGION)
    ec2 = session.client("ec2", region_name=REGION)
    iam = session.client("iam", region_name=REGION)
    now = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    started, actions = now(), []

    def fid(check):
        return next(f["id"] for f in scan["findings"] if f["check_id"] == check and f["status"] == "FAIL")

    v, sg = lab["vuln_bucket"], lab["vuln_sg"]

    before = {"BlockPublicAcls": False, "IgnorePublicAcls": False,
              "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    s3.put_public_access_block(Bucket=v, PublicAccessBlockConfiguration={k: True for k in before})
    actions.append(("S3-001", v, "S3_ENABLE_BPA", before, "Enabled all four Block Public Access settings."))

    s3.put_bucket_versioning(Bucket=v, VersioningConfiguration={"Status": "Enabled"})
    actions.append(("S3-002", v, "S3_ENABLE_VERSIONING", {"Status": "Disabled"}, "Versioning set to Enabled."))

    perms = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    ec2.revoke_security_group_ingress(GroupId=sg, IpPermissions=perms)
    actions.append(("EC2-001", sg, "EC2_REVOKE_OPEN_INGRESS",
                    {"revoked_rules": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}]},
                    "Revoked 1 open ingress rule (0.0.0.0/0 on port 22)."))

    iam.detach_user_policy(UserName=VULN_USER, PolicyArn=ADMIN_ARN)
    actions.append(("IAM-001", VULN_USER, "IAM_DETACH_ADMIN_POLICY", {"attached_policies": [ADMIN_ARN]},
                    "Detached AdministratorAccess from the user."))

    out = [{"finding_id": fid(c), "check_id": c, "resource_id": r, "action": a, "result": "SUCCESS",
            "before_state": b, "detail": d} for c, r, a, b, d in actions]
    out.append({"finding_id": fid("IAM-002"), "check_id": "IAM-002", "resource_id": VULN_USER,
                "action": "NONE", "result": "SKIPPED_NOT_AUTOMATABLE", "before_state": {},
                "detail": "Needs a human: register MFA or remove the console login profile."})
    return {"scan_id": scan["scan_id"], "mode": "remediate", "started": started,
            "finished": now(), "actions": out}

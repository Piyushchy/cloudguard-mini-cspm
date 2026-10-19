"""Unit tests for Phase 2 remediation actions and safety guardrails using moto."""

import json
from pathlib import Path
from unittest import mock

import boto3
from moto import mock_aws
import pytest

from remediation.actions.ec2_revoke_open_ingress import remediate_ec2_ingress
from remediation.actions.iam_detach_admin_policy import remediate_iam_admin_policy
from remediation.actions.s3_enable_bpa import remediate_s3_bpa
from remediation.actions.s3_enable_versioning import remediate_s3_versioning
from remediation.dispatcher import dispatch_actions


@mock_aws
def test_s3_enable_bpa_lifecycle():
    s3 = boto3.client("s3", region_name="ap-south-1")
    bucket = "cspm-demo-vuln-bucket-123456789012"
    s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": "ap-south-1"},
    )
    finding = {
        "id": f"S3-001#{bucket}",
        "check_id": "S3-001",
        "resource_id": bucket,
        "action": "S3_ENABLE_BPA",
    }

    # 1. Untagged -> SKIPPED_NOT_TAGGED
    res = remediate_s3_bpa(finding, mode="remediate", s3_client=s3)
    assert res["result"] == "SKIPPED_NOT_TAGGED"

    # Add required tag
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "cspm-remediate", "Value": "true"}]},
    )

    # 2. Dry-run mode -> DRY_RUN
    res_dry = remediate_s3_bpa(finding, mode="dry-run", s3_client=s3)
    assert res_dry["result"] == "DRY_RUN"
    assert "Would enable" in res_dry["detail"]

    # 3. Remediate mode -> SUCCESS
    res_live = remediate_s3_bpa(finding, mode="remediate", s3_client=s3)
    assert res_live["result"] == "SUCCESS"
    assert res_live["before_state"]["BlockPublicAcls"] is False

    # 4. Already compliant -> ALREADY_COMPLIANT
    res_again = remediate_s3_bpa(finding, mode="remediate", s3_client=s3)
    assert res_again["result"] == "ALREADY_COMPLIANT"


@mock_aws
def test_s3_enable_versioning_lifecycle():
    s3 = boto3.client("s3", region_name="ap-south-1")
    bucket = "cspm-demo-vuln-bucket-123456789012"
    s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": "ap-south-1"},
    )
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "cspm-remediate", "Value": "true"}]},
    )
    finding = {
        "id": f"S3-002#{bucket}",
        "check_id": "S3-002",
        "resource_id": bucket,
        "action": "S3_ENABLE_VERSIONING",
    }

    # Dry-run
    res_dry = remediate_s3_versioning(finding, mode="dry-run", s3_client=s3)
    assert res_dry["result"] == "DRY_RUN"

    # Remediate
    res_live = remediate_s3_versioning(finding, mode="remediate", s3_client=s3)
    assert res_live["result"] == "SUCCESS"

    # Already compliant
    res_again = remediate_s3_versioning(finding, mode="remediate", s3_client=s3)
    assert res_again["result"] == "ALREADY_COMPLIANT"


@mock_aws
def test_ec2_revoke_open_ingress_lifecycle():
    ec2 = boto3.client("ec2", region_name="ap-south-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    sg = ec2.create_security_group(
        GroupName="cspm-demo-vuln-sg",
        Description="Vuln SG",
        VpcId=vpc["Vpc"]["VpcId"],
    )
    sg_id = sg["GroupId"]

    # Open SSH port 22 to 0.0.0.0/0
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpProtocol="tcp",
        FromPort=22,
        ToPort=22,
        CidrIp="0.0.0.0/0",
    )

    finding = {
        "id": f"EC2-001#{sg_id}",
        "check_id": "EC2-001",
        "resource_id": sg_id,
        "action": "EC2_REVOKE_OPEN_INGRESS",
    }

    # 1. Untagged -> SKIPPED_NOT_TAGGED
    res = remediate_ec2_ingress(finding, mode="remediate", ec2_client=ec2)
    assert res["result"] == "SKIPPED_NOT_TAGGED"

    # Tag security group
    ec2.create_tags(
        Resources=[sg_id],
        Tags=[{"Key": "cspm-remediate", "Value": "true"}],
    )

    # 2. Dry-run
    res_dry = remediate_ec2_ingress(finding, mode="dry-run", ec2_client=ec2)
    assert res_dry["result"] == "DRY_RUN"
    assert len(res_dry["before_state"]["revoked_rules"]) == 1

    # 3. Remediate
    res_live = remediate_ec2_ingress(finding, mode="remediate", ec2_client=ec2)
    assert res_live["result"] == "SUCCESS"

    # 4. Already compliant
    res_again = remediate_ec2_ingress(finding, mode="remediate", ec2_client=ec2)
    assert res_again["result"] == "ALREADY_COMPLIANT"


@mock_aws
def test_iam_detach_admin_policy_lifecycle():
    iam = boto3.client("iam", region_name="ap-south-1")
    user_name = "cspm-demo-vuln-user"
    iam.create_user(UserName=user_name)
    policy_doc = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    pol = iam.create_policy(PolicyName="AdministratorAccess", PolicyDocument=policy_doc)
    admin_arn = pol["Policy"]["Arn"]
    iam.attach_user_policy(UserName=user_name, PolicyArn=admin_arn)


    finding = {
        "id": f"IAM-001#{user_name}",
        "check_id": "IAM-001",
        "resource_id": user_name,
        "action": "IAM_DETACH_ADMIN_POLICY",
    }

    # 1. Non-demo user protection check
    protected_finding = dict(finding, resource_id="another-user")
    res_prot = remediate_iam_admin_policy(protected_finding, mode="remediate", iam_client=iam)
    assert res_prot["result"] == "SKIPPED_PROTECTED_RESOURCE"

    # 2. Untagged demo user -> SKIPPED_NOT_TAGGED
    res_untag = remediate_iam_admin_policy(finding, mode="remediate", iam_client=iam)
    assert res_untag["result"] == "SKIPPED_NOT_TAGGED"

    # Tag user
    iam.tag_user(
        UserName=user_name,
        Tags=[{"Key": "cspm-remediate", "Value": "true"}],
    )

    # 3. Dry-run
    res_dry = remediate_iam_admin_policy(finding, mode="dry-run", iam_client=iam)
    assert res_dry["result"] == "DRY_RUN"

    # 4. Remediate
    res_live = remediate_iam_admin_policy(finding, mode="remediate", iam_client=iam)
    assert res_live["result"] == "SUCCESS"

    # 5. Already compliant
    res_again = remediate_iam_admin_policy(finding, mode="remediate", iam_client=iam)
    assert res_again["result"] == "ALREADY_COMPLIANT"


@mock_aws
def test_full_dispatcher_sample_findings():
    sample_path = Path(__file__).parent.parent.parent / "samples" / "findings_before.json"
    with open(sample_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # In alert-only mode, all actions should be SKIPPED_ALERT_ONLY or SKIPPED_NOT_AUTOMATABLE
    logs = dispatch_actions(data, mode="alert-only")
    assert len(logs) == 5

    results = {l["check_id"]: l["result"] for l in logs}
    assert results["IAM-002"] == "SKIPPED_NOT_AUTOMATABLE"
    assert results["S3-001"] == "SKIPPED_ALERT_ONLY"
    assert results["S3-002"] == "SKIPPED_ALERT_ONLY"
    assert results["EC2-001"] == "SKIPPED_ALERT_ONLY"
    assert results["IAM-001"] == "SKIPPED_ALERT_ONLY"

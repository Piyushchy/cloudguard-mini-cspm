"""Offline tests for every check (fake AWS via moto) + the whole-lab integration test."""
import json

import pytest
from botocore.exceptions import ClientError

from scanner import core, demo_lab
from scanner.checks import cloudtrail, ec2, iam, s3
from scanner.scan import run_scan

REGION = "ap-south-1"
LOC = {"LocationConstraint": REGION}
ALL_BPA = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
PUBLIC_POLICY = lambda b: json.dumps({  # noqa: E731
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                   "Resource": f"arn:aws:s3:::{b}/*"}]})


def by(findings, check, rid=None):
    out = [f for f in findings if f["check_id"] == check and (rid is None or f["resource_id"] == rid)]
    assert len(out) == 1, out
    return out[0]


# ------------------------------------------------------------------ S3
def mk_bucket(session, name):
    session.client("s3", region_name=REGION).create_bucket(Bucket=name, CreateBucketConfiguration=LOC)
    return session.client("s3", region_name=REGION)


def test_s3_public_policy_without_bpa_fails(session):
    c = mk_bucket(session, "pub")
    c.put_bucket_policy(Bucket="pub", Policy=PUBLIC_POLICY("pub"))
    f = by(s3.run(session, REGION), "S3-001", "pub")
    assert f["status"] == "FAIL" and "public bucket policy" in f["description"]
    assert f["severity"] == "CRITICAL" and f["remediation_action"] == "S3_ENABLE_BPA"


def test_s3_public_acl_without_bpa_fails(session):
    c = mk_bucket(session, "aclpub")
    c.put_bucket_acl(Bucket="aclpub", ACL="public-read")
    f = by(s3.run(session, REGION), "S3-001", "aclpub")
    assert f["status"] == "FAIL" and "ACL" in f["description"]


def test_s3_public_policy_with_full_bpa_passes(session):
    c = mk_bucket(session, "blocked")
    c.put_bucket_policy(Bucket="blocked", Policy=PUBLIC_POLICY("blocked"))
    c.put_public_access_block(Bucket="blocked", PublicAccessBlockConfiguration=ALL_BPA)
    assert by(s3.run(session, REGION), "S3-001", "blocked")["status"] == "PASS"


def test_s3_plain_private_bucket_passes_both(session):
    mk_bucket(session, "private")
    out = s3.run(session, REGION)
    assert by(out, "S3-001", "private")["status"] == "PASS"
    assert by(out, "S3-002", "private")["status"] == "FAIL"   # versioning off by default


def test_s3_partial_bpa_and_public_policy_still_fails(session):
    c = mk_bucket(session, "partial")
    c.put_bucket_policy(Bucket="partial", Policy=PUBLIC_POLICY("partial"))
    c.put_public_access_block(Bucket="partial", PublicAccessBlockConfiguration={**ALL_BPA, "RestrictPublicBuckets": False})
    assert by(s3.run(session, REGION), "S3-001", "partial")["status"] == "FAIL"


@pytest.mark.parametrize("status,expected", [("Enabled", "PASS"), ("Suspended", "FAIL")])
def test_s3_versioning(session, status, expected):
    c = mk_bucket(session, "ver")
    c.put_bucket_versioning(Bucket="ver", VersioningConfiguration={"Status": status})
    assert by(s3.run(session, REGION), "S3-002", "ver")["status"] == expected


def test_s3_no_buckets_gives_no_findings(session):
    assert s3.run(session, REGION) == []


# ----------------------------------------------------------------- EC2
def mk_sg(session, name, perms):
    e = session.client("ec2", region_name=REGION)
    vpc = e.describe_vpcs()["Vpcs"][0]["VpcId"]
    gid = e.create_security_group(GroupName=name, Description="t", VpcId=vpc)["GroupId"]
    if perms:
        e.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
    return gid


@pytest.mark.parametrize("perm,mention", [
    ({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, "port 22"),
    ({"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, "port 3389"),
    ({"IpProtocol": "tcp", "FromPort": 20, "ToPort": 30, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, "port 22"),
    ({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}, "::/0"),
    ({"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, "all"),
])
def test_ec2_risky_rules_fail(session, perm, mention):
    gid = mk_sg(session, "risky", [perm])
    f = by(ec2.run(session, REGION), "EC2-001", gid)
    assert f["status"] == "FAIL" and mention in f["description"]
    assert f["resource_arn"].endswith(f"security-group/{gid}")


@pytest.mark.parametrize("perm", [
    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
])
def test_ec2_safe_rules_pass(session, perm):
    gid = mk_sg(session, "safe", [perm])
    assert by(ec2.run(session, REGION), "EC2-001", gid)["status"] == "PASS"


def test_ec2_default_sg_is_checked_too(session):
    out = ec2.run(session, REGION)
    assert len(out) >= 1 and all(f["status"] == "PASS" for f in out)


# ----------------------------------------------------------------- IAM
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def test_iam_admin_attached_fails_and_clean_user_passes(session, monkeypatch):
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")   # needs AdministratorAccess
    i = session.client("iam")
    i.create_user(UserName="admin"); i.create_user(UserName="clean")
    i.attach_user_policy(UserName="admin", PolicyArn=ADMIN)
    out = iam.run(session, REGION)
    assert by(out, "IAM-001", "admin")["status"] == "FAIL"
    assert by(out, "IAM-001", "clean")["status"] == "PASS"      # user with no policies at all


def test_iam_console_no_mfa_fails_variants_pass(session):
    i = session.client("iam")
    for u in ("nomfa", "nologin", "withmfa"):
        i.create_user(UserName=u)
    for u in ("nomfa", "withmfa"):
        i.create_login_profile(UserName=u, Password="Aa1!aaaaaaaa", PasswordResetRequired=False)
    serial = i.create_virtual_mfa_device(VirtualMFADeviceName="m")["VirtualMFADevice"]["SerialNumber"]
    i.enable_mfa_device(UserName="withmfa", SerialNumber=serial,
                        AuthenticationCode1="123456", AuthenticationCode2="654321")
    out = iam.run(session, REGION)
    assert by(out, "IAM-002", "nomfa")["status"] == "FAIL"
    assert by(out, "IAM-002", "nomfa")["auto_remediable"] is False
    assert by(out, "IAM-002", "nologin")["status"] == "PASS"
    assert by(out, "IAM-002", "withmfa")["status"] == "PASS"


def test_iam_no_users_no_findings(session):
    assert iam.run(session, REGION) == []


# ---------------------------------------------------------- CloudTrail
def mk_trail(session, multi=True, logging=True):
    session.client("s3", region_name=REGION).create_bucket(Bucket="trail-logs-bucket", CreateBucketConfiguration=LOC)
    ct = session.client("cloudtrail", region_name=REGION)
    ct.create_trail(Name="trail-one", S3BucketName="trail-logs-bucket", IsMultiRegionTrail=multi)
    if logging:
        ct.start_logging(Name="trail-one")


def test_ct_active_multiregion_passes(session):
    mk_trail(session)
    f = by(cloudtrail.run(session, REGION), "CT-001")
    assert f["status"] == "PASS" and f["resource_id"] == "123456789012" and "trail-one" in f["description"]


@pytest.mark.parametrize("kw", [{"multi": False}, {"logging": False}])
def test_ct_inactive_or_single_region_fails(session, kw):
    mk_trail(session, **kw)
    assert by(cloudtrail.run(session, REGION), "CT-001")["status"] == "FAIL"


def test_ct_no_trail_fails_with_same_id_shape(session):
    f = by(cloudtrail.run(session, REGION), "CT-001")
    assert f["status"] == "FAIL" and f["id"] == "CT-001#123456789012"


# --------------------------------------------- whole lab (Gate 2, offline)
def test_full_lab_gives_exactly_the_five_expected_fails(session):
    demo_lab.build_lab(session)
    scan, warnings = run_scan(session, REGION, "before")
    core.validate(scan)
    assert warnings == []
    fails = sorted(f["check_id"] for f in scan["findings"] if f["status"] == "FAIL")
    assert fails == ["EC2-001", "IAM-001", "IAM-002", "S3-001", "S3-002"]
    assert scan["summary"] == {"score": 51, "total": 11, "failed": 5,
                               "by_severity": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 0, "LOW": 1}}


def test_after_remediation_only_iam002_remains(session):
    lab = demo_lab.build_lab(session)
    before, _ = run_scan(session, REGION, "before")
    log = demo_lab.simulate_remediation(session, lab, before)
    after, _ = run_scan(session, REGION, "after")
    core.validate(after)
    assert [f["check_id"] for f in after["findings"] if f["status"] == "FAIL"] == ["IAM-002"]
    assert after["summary"]["score"] == 89
    assert [a["result"] for a in log["actions"]].count("SUCCESS") == 4


def test_after_human_fix_scores_100(session):
    lab = demo_lab.build_lab(session)
    before, _ = run_scan(session, REGION, "before")
    demo_lab.simulate_remediation(session, lab, before)
    session.client("iam").delete_login_profile(UserName=demo_lab.VULN_USER)
    final, _ = run_scan(session, REGION, "adhoc")
    assert final["summary"]["score"] == 100 and final["summary"]["failed"] == 0


def test_empty_account_scan_is_valid(session):
    scan, warnings = run_scan(session, REGION, "adhoc")
    core.validate(scan)
    assert not warnings


# --------------------------------------------- errors never crash the scan
class DenyingSession:
    """Wraps a real session but makes one service answer AccessDenied."""
    def __init__(self, real, deny):
        self.real, self.deny = real, deny

    def client(self, name, **kw):
        c = self.real.client(name, **kw)
        if name == self.deny:
            def boom(*a, **k):
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "Op")
            c.list_buckets = c.describe_security_groups = c.get_paginator = boom
            c.describe_trails = boom
        return c


@pytest.mark.parametrize("service,missing", [("s3", "S3-"), ("ec2", "EC2-"), ("iam", "IAM-"), ("cloudtrail", "CT-")])
def test_access_denied_becomes_warning_and_scan_continues(session, service, missing):
    demo_lab.build_lab(session)
    scan, warnings = run_scan(DenyingSession(session, service), REGION, "adhoc")
    core.validate(scan)
    assert any("AccessDenied" in w for w in warnings)
    assert not any(f["check_id"].startswith(missing) for f in scan["findings"])
    assert scan["findings"], "the other services must still be scanned"


def test_throttling_config_is_set():
    from scanner.checks._util import CONFIG
    assert CONFIG.retries["mode"] == "standard"
    assert CONFIG.retries["total_max_attempts"] == 9   # botocore stores max_attempts=8 as 1 try + 8 retries

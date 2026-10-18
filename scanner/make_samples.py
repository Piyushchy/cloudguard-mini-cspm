"""Generate samples/findings_before.json, findings_after.json, remediation_log.json.

Run from the repo root:  python -m scanner.make_samples
Samples are built with core.py, so scores and summaries are always consistent.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from scanner import core

ACCOUNT = "123456789012"
REGION = "ap-south-1"
SAMPLES = Path(__file__).resolve().parent.parent / "samples"

VULN_BUCKET = f"cspm-demo-vuln-bucket-{ACCOUNT}"
REPORTS_BUCKET = f"cspm-demo-reports-{ACCOUNT}"
TRAIL_BUCKET = f"cspm-demo-trail-logs-{ACCOUNT}"
VULN_SG = "sg-0a1b2c3d4e5f60718"      # cspm-demo-vuln-sg
DEFAULT_SG = "sg-0f9e8d7c6b5a43210"   # default VPC security group
VULN_USER = "cspm-demo-vuln-user"
TRAIL = "cspm-demo-trail"


def s3_arn(b): return f"arn:aws:s3:::{b}"
def sg_arn(g): return f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{g}"
def user_arn(u): return f"arn:aws:iam::{ACCOUNT}:user/{u}"
def trail_arn(t): return f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/{t}"


def F(check, rid, arn, status, desc):
    return core.make_finding(check, rid, arn, status, desc)


def build_findings(*, fixed: bool) -> list[dict]:
    """fixed=False -> lab before remediation, fixed=True -> after auto-remediation."""
    P, X = "PASS", "FAIL"
    s = P if fixed else X  # status of the four auto-fixable problems
    return [
        # S3-001
        F("S3-001", VULN_BUCKET, s3_arn(VULN_BUCKET), s,
          "Block Public Access is fully enabled; the bucket is not public." if fixed else
          "Public read is granted by bucket policy and Block Public Access is off."),
        F("S3-001", REPORTS_BUCKET, s3_arn(REPORTS_BUCKET), P,
          "Block Public Access is fully enabled; the bucket is not public."),
        F("S3-001", TRAIL_BUCKET, s3_arn(TRAIL_BUCKET), P,
          "Block Public Access is fully enabled; the bucket is not public."),
        # S3-002
        F("S3-002", VULN_BUCKET, s3_arn(VULN_BUCKET), s,
          "Versioning is enabled." if fixed else "Versioning is not enabled on this bucket."),
        F("S3-002", REPORTS_BUCKET, s3_arn(REPORTS_BUCKET), P, "Versioning is enabled."),
        F("S3-002", TRAIL_BUCKET, s3_arn(TRAIL_BUCKET), P, "Versioning is enabled."),
        # EC2-001
        F("EC2-001", VULN_SG, sg_arn(VULN_SG), s,
          "No ingress rule is open to the internet on port 22, 3389 or all ports."
          if fixed else
          "Security group cspm-demo-vuln-sg allows 0.0.0.0/0 on port 22 (SSH)."),
        F("EC2-001", DEFAULT_SG, sg_arn(DEFAULT_SG), P,
          "No ingress rule is open to the internet on port 22, 3389 or all ports."),
        # IAM-001
        F("IAM-001", VULN_USER, user_arn(VULN_USER), s,
          "AdministratorAccess is not attached directly to the user." if fixed else
          "AdministratorAccess is attached directly to the user."),
        # IAM-002 stays FAIL after auto-remediation: needs a human
        F("IAM-002", VULN_USER, user_arn(VULN_USER), X,
          "User has a console password but no MFA device registered."),
        # CT-001
        F("CT-001", ACCOUNT, trail_arn(TRAIL), P,
          "Trail cspm-demo-trail is multi-region and logging is on."),
    ]


def main() -> None:
    SAMPLES.mkdir(exist_ok=True)

    t_before = datetime(2026, 11, 5, 9, 30, 0, tzinfo=timezone.utc)
    t_after = datetime(2026, 11, 5, 9, 32, 0, tzinfo=timezone.utc)

    before = core.build_scan(build_findings(fixed=False), ACCOUNT, REGION, "before", t_before)
    after = core.build_scan(build_findings(fixed=True), ACCOUNT, REGION, "after", t_after)
    core.validate(before)
    core.validate(after)
    core.write_scan(before, SAMPLES / "findings_before.json")
    core.write_scan(after, SAMPLES / "findings_after.json")

    def fid(check):
        return next(f["id"] for f in before["findings"]
                    if f["check_id"] == check and f["status"] == "FAIL")

    log = {
        "scan_id": before["scan_id"],
        "mode": "remediate",
        "started": "2026-11-05T09:30:04Z",
        "finished": "2026-11-05T09:30:09Z",
        "actions": [
            {"finding_id": fid("S3-001"), "check_id": "S3-001", "resource_id": VULN_BUCKET,
             "action": "S3_ENABLE_BPA", "result": "SUCCESS",
             "before_state": {"BlockPublicAcls": False, "IgnorePublicAcls": False,
                              "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
             "detail": "Enabled all four Block Public Access settings."},
            {"finding_id": fid("S3-002"), "check_id": "S3-002", "resource_id": VULN_BUCKET,
             "action": "S3_ENABLE_VERSIONING", "result": "SUCCESS",
             "before_state": {"Status": "Disabled"},
             "detail": "Versioning set to Enabled."},
            {"finding_id": fid("EC2-001"), "check_id": "EC2-001", "resource_id": VULN_SG,
             "action": "EC2_REVOKE_OPEN_INGRESS", "result": "SUCCESS",
             "before_state": {"revoked_rules": [{"IpProtocol": "tcp", "FromPort": 22,
                                                 "ToPort": 22, "CidrIp": "0.0.0.0/0"}]},
             "detail": "Revoked 1 open ingress rule (0.0.0.0/0 on port 22)."},
            {"finding_id": fid("IAM-001"), "check_id": "IAM-001", "resource_id": VULN_USER,
             "action": "IAM_DETACH_ADMIN_POLICY", "result": "SUCCESS",
             "before_state": {"attached_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"]},
             "detail": "Detached AdministratorAccess from the user."},
            {"finding_id": fid("IAM-002"), "check_id": "IAM-002", "resource_id": VULN_USER,
             "action": "NONE", "result": "SKIPPED_NOT_AUTOMATABLE",
             "before_state": {},
             "detail": "Needs a human: register MFA or remove the console login profile."},
        ],
    }
    (SAMPLES / "remediation_log.json").write_text(json.dumps(log, indent=2) + "\n", "utf-8")

    for name, scan in (("before", before), ("after", after)):
        s = scan["summary"]
        print(f"{name:6} {scan['scan_id']}  score={s['score']}  failed={s['failed']}/{s['total']}  {s['by_severity']}")


if __name__ == "__main__":
    main()

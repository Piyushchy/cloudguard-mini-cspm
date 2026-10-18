"""Offline unit tests for scanner/core.py and the sample files.

Scoring reminder:
    weights  CRITICAL=10  HIGH=7  MEDIUM=4  LOW=1
    score = round(100 * (sum of PASS weights) / (sum of ALL weights))
"""
import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scanner import core

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "samples"
ARN = "arn:aws:s3:::x"


def f(check_id, status, rid="r"):
    return core.make_finding(check_id, rid, ARN, status, "test")


# ---------------------------------------------------------------- scoring
def test_all_pass_is_100():
    # pass = 10 + 7 + 4 = 21, total = 21  ->  100 * 21/21 = 100
    s = core.compute_summary([f("S3-001", "PASS"), f("EC2-001", "PASS"), f("CT-001", "PASS")])
    assert s["score"] == 100 and s["failed"] == 0 and s["total"] == 3


def test_no_findings_is_100():
    assert core.compute_summary([])["score"] == 100


def test_all_fail_is_0():
    assert core.compute_summary([f("S3-001", "FAIL"), f("IAM-001", "FAIL")])["score"] == 0


def test_mixed_severities():
    # FAIL: S3-001 (10) + S3-002 (1) = 11    PASS: EC2-001 (7) + CT-001 (4) = 11
    # total = 22, pass = 11  ->  100 * 11/22 = 50
    s = core.compute_summary([
        f("S3-001", "FAIL"), f("S3-002", "FAIL"), f("EC2-001", "PASS"), f("CT-001", "PASS"),
    ])
    assert s["score"] == 50
    assert s["by_severity"] == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 1}


def test_half_rounds_up_not_to_even():
    # FAIL EC2-001 (7) + PASS S3-002 (1): total 8, pass 1 -> 12.5 -> 13
    # (Python's built-in round(12.5) would give 12.)
    assert core.compute_summary([f("EC2-001", "FAIL"), f("S3-002", "PASS")])["score"] == 13


def lab(fixed):
    from scanner.make_samples import build_findings
    return build_findings(fixed=fixed)


def test_lab_before_hand_calculated():
    # FAIL: S3-001 10 + S3-002 1 + EC2-001 7 + IAM-001 7 + IAM-002 7 = 32 (5 findings)
    # PASS: S3-001 x2 (20) + S3-002 x2 (2) + EC2-001 default SG (7) + CT-001 (4) = 33 (6 findings)
    # total = 65   ->  100 * 33/65 = 50.77 -> 51
    s = core.compute_summary(lab(False))
    assert s == {"score": 51, "total": 11, "failed": 5,
                 "by_severity": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 0, "LOW": 1}}


def test_lab_after_auto_remediation():
    # Only IAM-002 (7) still FAILs. pass = 65 - 7 = 58  ->  100 * 58/65 = 89.23 -> 89
    s = core.compute_summary(lab(True))
    assert s["score"] == 89 and s["failed"] == 1
    assert s["by_severity"]["HIGH"] == 1


def test_lab_after_human_fix_is_100():
    findings = [x for x in lab(True) if x["check_id"] != "IAM-002"]
    findings.append(f("IAM-002", "PASS", "cspm-demo-vuln-user"))
    assert core.compute_summary(findings)["score"] == 100


# ------------------------------------------------------- findings / ids
def test_make_finding_follows_catalogue():
    x = core.make_finding("IAM-002", "u", "arn:aws:iam::1:user/u", "FAIL", "d")
    assert x["id"] == "IAM-002#u"
    assert x["severity"] == "HIGH"
    assert x["auto_remediable"] is False and x["remediation_action"] == "NONE"
    y = core.make_finding("S3-001", "b", ARN, "FAIL", "d")
    assert y["severity"] == "CRITICAL" and y["remediation_action"] == "S3_ENABLE_BPA"


def test_make_finding_rejects_bad_input():
    with pytest.raises(ValueError):
        core.make_finding("NOPE-1", "r", ARN, "FAIL", "d")
    with pytest.raises(ValueError):
        core.make_finding("S3-001", "r", ARN, "MAYBE", "d")


def test_scan_id_format():
    t = datetime(2026, 11, 5, 9, 30, 0, tzinfo=timezone.utc)
    assert core.new_scan_id("before", t) == "20261105T093000Z-before"
    with pytest.raises(ValueError):
        core.new_scan_id("tuesday", t)


# --------------------------------------------------------- validation
def load(name):
    return json.loads((SAMPLES / name).read_text("utf-8"))


@pytest.mark.parametrize("name", ["findings_before.json", "findings_after.json"])
def test_samples_are_valid(name):
    core.validate(load(name))


def test_before_sample_has_the_five_expected_fails():
    fails = {x["check_id"] for x in load("findings_before.json")["findings"] if x["status"] == "FAIL"}
    assert fails == {"S3-001", "S3-002", "EC2-001", "IAM-001", "IAM-002"}


def test_after_sample_only_iam002_fails():
    fails = {x["check_id"] for x in load("findings_after.json")["findings"] if x["status"] == "FAIL"}
    assert fails == {"IAM-002"}


def test_validate_rejects_wrong_summary():
    bad = load("findings_before.json")
    bad["summary"]["score"] = 99
    with pytest.raises(core.ScanValidationError, match="summary"):
        core.validate(bad)


def test_validate_rejects_missing_field():
    bad = load("findings_before.json")
    del bad["findings"][0]["severity"]
    with pytest.raises(core.ScanValidationError, match="severity"):
        core.validate(bad)


def test_validate_rejects_bad_enum_and_extra_field():
    bad = load("findings_before.json")
    bad["findings"][0]["remediation_action"] = "DELETE_EVERYTHING"
    with pytest.raises(core.ScanValidationError):
        core.validate(bad)
    bad2 = copy.deepcopy(load("findings_before.json"))
    bad2["surprise"] = 1
    with pytest.raises(core.ScanValidationError):
        core.validate(bad2)


def test_validate_rejects_duplicate_ids():
    bad = load("findings_before.json")
    bad["findings"].append(copy.deepcopy(bad["findings"][0]))
    bad["summary"] = core.compute_summary(bad["findings"])
    with pytest.raises(core.ScanValidationError, match="duplicate"):
        core.validate(bad)


def test_build_scan_roundtrip_validates():
    t = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    scan = core.build_scan(lab(False), "123456789012", "ap-south-1", "adhoc", t)
    core.validate(scan)
    assert scan["scan_id"] == "20260102T030405Z-adhoc"
    assert scan["timestamp"] == "2026-01-02T03:04:05Z"


# ----------------------------------------------------- remediation log
def test_remediation_log_sample_matches_contract():
    log = load("remediation_log.json")
    before = load("findings_before.json")
    assert log["scan_id"] == before["scan_id"]
    allowed = {"SUCCESS", "DRY_RUN", "SKIPPED_NOT_TAGGED", "SKIPPED_NOT_AUTOMATABLE",
               "ALREADY_COMPLIANT", "FAILED"}
    before_ids = {x["id"] for x in before["findings"]}
    for a in log["actions"]:
        assert a["result"] in allowed
        assert a["finding_id"] in before_ids
        assert {"finding_id", "check_id", "resource_id", "action", "result",
                "before_state", "detail"} <= a.keys()
    t0 = datetime.fromisoformat(before["timestamp"].replace("Z", "+00:00"))
    t1 = datetime.fromisoformat(log["finished"].replace("Z", "+00:00"))
    assert (t1 - t0).total_seconds() == 9  # MTTR = 9 s in the sample

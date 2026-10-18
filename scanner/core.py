"""CloudGuard core: finding builder, scoring, scan IDs, schema validation.

Everything here is pure Python (no AWS calls) so it can be unit-tested offline.
The check catalogue below mirrors section A5 of the shared contract exactly.
If the contract changes, change CHECKS (and the schema) together.
"""
from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

# --------------------------------------------------------------------------
# Constants (contract A5)
# --------------------------------------------------------------------------
SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
SEVERITIES = tuple(SEVERITY_WEIGHTS)
VALID_LABELS = ("before", "after", "adhoc")
VALID_STATUSES = ("PASS", "FAIL")

DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent / "shared" / "findings.schema.json"
)

# check_id -> static facts about the check. One finding is produced per resource.
CHECKS = {
    "S3-001": {
        "title": "S3 bucket is publicly accessible",
        "service": "s3",
        "severity": "CRITICAL",
        "auto_remediable": True,
        "remediation_action": "S3_ENABLE_BPA",
        "remediation_hint": "Enable all four Block Public Access settings.",
    },
    "S3-002": {
        "title": "S3 bucket versioning is disabled",
        "service": "s3",
        "severity": "LOW",
        "auto_remediable": True,
        "remediation_action": "S3_ENABLE_VERSIONING",
        "remediation_hint": "Enable versioning on the bucket.",
    },
    "EC2-001": {
        "title": "Security group allows open ingress to the internet",
        "service": "ec2",
        "severity": "HIGH",
        "auto_remediable": True,
        "remediation_action": "EC2_REVOKE_OPEN_INGRESS",
        "remediation_hint": (
            "Remove the 0.0.0.0/0 and ::/0 ingress rules for SSH (22), "
            "RDP (3389) or all ports."
        ),
    },
    "IAM-001": {
        "title": "IAM user has AdministratorAccess attached directly",
        "service": "iam",
        "severity": "HIGH",
        "auto_remediable": True,
        "remediation_action": "IAM_DETACH_ADMIN_POLICY",
        "remediation_hint": (
            "Detach AdministratorAccess from the user and grant only the "
            "permissions they need."
        ),
    },
    "IAM-002": {
        "title": "IAM user has console access but no MFA",
        "service": "iam",
        "severity": "HIGH",
        "auto_remediable": False,
        "remediation_action": "NONE",
        "remediation_hint": (
            "Register an MFA device for the user, or remove their console "
            "login profile. Needs a human."
        ),
    },
    "CT-001": {
        "title": "No active multi-region CloudTrail trail",
        "service": "cloudtrail",
        "severity": "MEDIUM",
        "auto_remediable": False,
        "remediation_action": "NONE",
        "remediation_hint": (
            "Create a multi-region CloudTrail trail and make sure logging "
            "is turned on."
        ),
    },
}


class ScanValidationError(ValueError):
    """Raised when a scan dict does not follow the findings contract."""


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------
def make_finding(
    check_id: str,
    resource_id: str,
    resource_arn: str,
    status: str,
    description: str,
) -> dict:
    """Build one finding with exactly the fields listed in contract A5.

    Static fields (title, severity, remediation_*) come from CHECKS so a
    check can never disagree with the catalogue.
    """
    if check_id not in CHECKS:
        raise ValueError(f"Unknown check_id {check_id!r}. Known: {sorted(CHECKS)}")
    if status not in VALID_STATUSES:
        raise ValueError(f"status must be one of {VALID_STATUSES}, got {status!r}")
    c = CHECKS[check_id]
    return {
        "id": f"{check_id}#{resource_id}",
        "check_id": check_id,
        "title": c["title"],
        "service": c["service"],
        "resource_id": resource_id,
        "resource_arn": resource_arn,
        "severity": c["severity"],
        "status": status,
        "description": description,
        "remediation_hint": c["remediation_hint"],
        "auto_remediable": c["auto_remediable"],
        "remediation_action": c["remediation_action"],
    }


# --------------------------------------------------------------------------
# Scoring (contract A5)
# --------------------------------------------------------------------------
def _round_half_up(x: float) -> int:
    """Round .5 upwards. Python's round() rounds .5 to the nearest EVEN number
    (round(12.5) == 12), which would surprise people recomputing by hand."""
    return int(math.floor(x + 0.5))


def compute_summary(findings: list[dict]) -> dict:
    """score = round(100 * sum(weights of PASS) / sum(weights of all findings)).

    Counts per severity are for FAIL findings only. With no findings at all,
    nothing is wrong, so the score is 100.
    """
    total_weight = 0
    pass_weight = 0
    by_severity = {s: 0 for s in SEVERITIES}
    failed = 0
    for f in findings:
        w = SEVERITY_WEIGHTS[f["severity"]]
        total_weight += w
        if f["status"] == "PASS":
            pass_weight += w
        else:
            failed += 1
            by_severity[f["severity"]] += 1
    score = 100 if total_weight == 0 else _round_half_up(100 * pass_weight / total_weight)
    return {
        "score": score,
        "total": len(findings),
        "failed": failed,
        "by_severity": by_severity,
    }


# --------------------------------------------------------------------------
# Scan IDs and scan documents
# --------------------------------------------------------------------------
def _utc(now: datetime | None) -> datetime:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc).replace(microsecond=0)


def new_scan_id(label: str, now: datetime | None = None) -> str:
    """YYYYMMDDTHHMMSSZ-<label>, e.g. 20261105T093000Z-before."""
    if label not in VALID_LABELS:
        raise ValueError(f"label must be one of {VALID_LABELS}, got {label!r}")
    return f"{_utc(now).strftime('%Y%m%dT%H%M%SZ')}-{label}"


def build_scan(
    findings: list[dict],
    account_id: str,
    region: str,
    label: str,
    now: datetime | None = None,
) -> dict:
    """Assemble the full scan document. scan_id and timestamp share one clock
    reading so they can never disagree."""
    now = _utc(now)
    findings = sorted(findings, key=lambda f: (f["check_id"], f["resource_id"]))
    return {
        "scan_id": new_scan_id(label, now),
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "account_id": account_id,
        "region": region,
        "label": label,
        "summary": compute_summary(findings),
        "findings": findings,
    }


def write_scan(scan: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scan, indent=2) + "\n", encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------
def validate(scan: dict, schema_path: str | Path | None = None) -> None:
    """Validate a scan against shared/findings.schema.json, then check the
    things a schema cannot express (summary matches findings, ids consistent).

    Raises ScanValidationError with a readable message. Returns None on success.
    """
    schema = json.loads(Path(schema_path or DEFAULT_SCHEMA_PATH).read_text("utf-8"))
    try:
        jsonschema.validate(instance=scan, schema=schema)
    except jsonschema.ValidationError as e:
        where = "/".join(str(p) for p in e.absolute_path) or "<root>"
        raise ScanValidationError(f"Schema error at {where}: {e.message}") from e

    expected = compute_summary(scan["findings"])
    if scan["summary"] != expected:
        raise ScanValidationError(
            f"summary does not match findings. File says {scan['summary']}, "
            f"recomputed {expected}"
        )
    for f in scan["findings"]:
        if f["id"] != f"{f['check_id']}#{f['resource_id']}":
            raise ScanValidationError(f"finding id {f['id']!r} is not check_id#resource_id")
    ids = [f["id"] for f in scan["findings"]]
    if len(ids) != len(set(ids)):
        raise ScanValidationError("duplicate finding ids in scan")
    if not scan["scan_id"].endswith(f"-{scan['label']}"):
        raise ScanValidationError("scan_id suffix does not match label")
    if scan["scan_id"][:16] != scan["timestamp"].replace("-", "").replace(":", ""):
        raise ScanValidationError("scan_id time does not match timestamp")

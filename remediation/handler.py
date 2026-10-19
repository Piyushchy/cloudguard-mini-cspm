"""remediation.handler — AWS Lambda Entry Point for CloudGuard Mini-CSPM (P3)

Triggered by S3 ObjectCreated events on prefix 'scans/*.json'.
1. Validates incoming scan against findings.schema.json.
2. Formats and dispatches SNS security posture alert.
3. Evaluates MODE (alert-only, dry-run, remediate).
4. Executes remediation actions if configured.
5. Writes audit trail log to 'remediation-logs/<scan_id>.json'.
"""

import json
import logging
import os
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import boto3
try:
    import jsonschema
except ImportError:
    jsonschema = None


# Setup structured logging
logger = logging.getLogger("cloudguard.remediator")
logger.setLevel(logging.INFO)

# Allowed modes according to Contract A6
VALID_MODES = {"alert-only", "dry-run", "remediate"}

# Deliberate protection list according to Contract A6 & B2
PROTECTED_RESOURCES = {
    "root",
    "cspm-p3-remediator",
    "cspm-scanner",
}


def load_findings_schema() -> Dict[str, Any]:
    """Load findings schema from local package or shared folder."""
    candidates = [
        Path(__file__).parent.parent / "shared" / "findings.schema.json",
        Path(__file__).parent / "findings.schema.json",
        Path("/var/task/shared/findings.schema.json"),
        Path("/var/task/findings.schema.json"),
    ]
    for p in candidates:
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
    raise FileNotFoundError("Could not locate findings.schema.json")


def parse_s3_event(event: Dict[str, Any]) -> Tuple[str, str]:
    """Extract bucket name and object key from S3 ObjectCreated event."""
    records = event.get("Records", [])
    if not records:
        raise ValueError("Invalid S3 event: No 'Records' found")

    record = records[0]
    bucket_name = record["s3"]["bucket"]["name"]
    object_key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
    return bucket_name, object_key


def format_sns_alert(findings_data: Dict[str, Any], mode: str) -> Tuple[str, str]:
    """Build SNS subject and body according to Contract A5 / B1."""
    summary = findings_data.get("summary", {})
    score = summary.get("score", 0)
    failed = summary.get("failed", 0)
    by_sev = summary.get("by_severity", {})
    crit_count = by_sev.get("CRITICAL", 0)
    high_count = by_sev.get("HIGH", 0)
    med_count = by_sev.get("MEDIUM", 0)
    low_count = by_sev.get("LOW", 0)
    scan_id = findings_data.get("scan_id", "unknown")
    label = findings_data.get("label", "unknown")

    # Subject line
    subject = f"[CloudGuard] Score {score}/100 - {crit_count} CRITICAL, {high_count} HIGH"
    # Ensure subject does not exceed 100 characters for SNS
    if len(subject) > 100:
        subject = subject[:97] + "..."

    # Top findings
    failed_findings = [f for f in findings_data.get("findings", []) if f.get("status") == "FAIL"]
    # Sort by severity weight
    sev_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    failed_findings.sort(key=lambda x: sev_weights.get(x.get("severity", "LOW"), 0), reverse=True)

    top_3 = failed_findings[:3]
    top_findings_str = ""
    for idx, f in enumerate(top_3, 1):
        auto_flag = "[Auto-remediable]" if f.get("auto_remediable") else "[Needs Human]"
        top_findings_str += (
            f"  {idx}. [{f.get('severity')}] {f.get('check_id')}: {f.get('title')}\n"
            f"     Resource: {f.get('resource_id')}\n"
            f"     Status: {auto_flag} -> {f.get('remediation_action')}\n"
        )

    if not top_findings_str:
        top_findings_str = "  No failed findings. Posture is 100% compliant!\n"

    body = (
        f"===========================================================\n"
        f" CloudGuard Mini-CSPM Security Posture Alert\n"
        f"===========================================================\n\n"
        f"Scan ID:      {scan_id}\n"
        f"Label:        {label}\n"
        f"Pipeline Mode:{mode}\n"
        f"Timestamp:    {findings_data.get('timestamp')}\n"
        f"Account ID:   {findings_data.get('account_id')}\n"
        f"Region:       {findings_data.get('region')}\n\n"
        f"Posture Score:{score} / 100\n"
        f"Total Checks: {summary.get('total', 0)}\n"
        f"Failed Checks:{failed} (CRITICAL: {crit_count}, HIGH: {high_count}, MEDIUM: {med_count}, LOW: {low_count})\n\n"
        f"-----------------------------------------------------------\n"
        f"Top Priority Findings:\n"
        f"-----------------------------------------------------------\n"
        f"{top_findings_str}\n"
        f"-----------------------------------------------------------\n"
        f"Remediation Strategy: Mode is '{mode}'.\n"
    )

    if mode == "alert-only":
        body += "No changes will be applied to AWS resources.\n"
    elif mode == "dry-run":
        body += "Simulating changes; safety verification only.\n"
    elif mode == "remediate":
        body += "Applying automated fixes to eligible tagged resources.\n"

    body += "Audit log will be written to reports bucket under remediation-logs/.\n"
    return subject, body


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entrypoint triggered by S3 ObjectCreated event."""
    started_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    logger.info("CloudGuard remediator invoked with event: %s", json.dumps(event))

    # Read configuration
    mode = os.environ.get("MODE", "alert-only").strip().lower()
    if mode not in VALID_MODES:
        error_msg = f"Invalid MODE '{mode}'. Must be one of {sorted(VALID_MODES)}"
        logger.error(error_msg)
        raise ValueError(error_msg)

    # 1. Parse S3 Event
    bucket_name, object_key = parse_s3_event(event)

    # Contract A6 rule 5: Lambda is triggered only by prefix scans/, ignored otherwise
    if not object_key.startswith("scans/") or not object_key.endswith(".json"):
        logger.info("Ignoring object '%s' not matching 'scans/*.json'", object_key)
        return {
            "statusCode": 200,
            "body": f"Ignored non-scan object: {object_key}",
        }

    s3_client = boto3.client("s3")
    sns_client = boto3.client("sns")

    # 2. Fetch Findings JSON
    logger.info("Fetching scan from s3://%s/%s", bucket_name, object_key)
    response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
    raw_content = response["Body"].read().decode("utf-8")

    try:
        findings_data = json.loads(raw_content)
    except json.JSONDecodeError as err:
        logger.error("Failed to parse JSON from %s: %s", object_key, err)
        raise

    # 3. Validate against schema
    if jsonschema is not None:
        try:
            schema = load_findings_schema()
            jsonschema.validate(instance=findings_data, schema=schema)
            logger.info("Scan validation against findings.schema.json: SUCCESS")
        except jsonschema.ValidationError as val_err:
            logger.error("Schema validation failed: %s", val_err.message)
            raise
    else:
        logger.info("jsonschema not loaded; proceeding with basic validation.")


    # 4. Dispatch SNS Alert
    topic_arn = os.environ.get("TOPIC_ARN")
    if topic_arn:
        subject, body = format_sns_alert(findings_data, mode)
        logger.info("Publishing SNS alert to %s", topic_arn)
        try:
            sns_client.publish(
                TopicArn=topic_arn,
                Subject=subject,
                Message=body,
            )
            logger.info("SNS alert published successfully.")
        except Exception as e:
            logger.error("Failed to publish SNS alert: %s", e)
            # Do not crash the entire function if SNS fails, proceed with logging
    else:
        logger.warning("TOPIC_ARN environment variable not set; skipping SNS alert.")

    # 5. Execute or evaluate remediation actions
    actions_log: List[Dict[str, Any]] = []

    # Import actions dispatcher if available
    try:
        from remediation.dispatcher import dispatch_actions

        actions_log = dispatch_actions(findings_data=findings_data, mode=mode)
    except ImportError:
        logger.info("remediation.dispatcher not imported; running in base skeleton mode.")
        for f in findings_data.get("findings", []):
            if f.get("status") == "FAIL":
                actions_log.append({
                    "finding_id": f.get("id"),
                    "check_id": f.get("check_id"),
                    "resource_id": f.get("resource_id"),
                    "action": f.get("remediation_action"),
                    "result": "SKIPPED_ALERT_ONLY" if mode == "alert-only" else "PENDING",
                    "before_state": {},
                    "detail": f"Mode is {mode}. Skeleton handler active.",
                })

    # 6. Build Remediation Log
    finished_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    scan_id = findings_data.get("scan_id", "unknown-scan")
    log_doc = {
        "scan_id": scan_id,
        "mode": mode,
        "started": started_iso,
        "finished": finished_iso,
        "actions": actions_log,
    }

    # Write log to S3
    log_key = f"remediation-logs/{scan_id}.json"
    logger.info("Writing remediation log to s3://%s/%s", bucket_name, log_key)
    s3_client.put_object(
        Bucket=bucket_name,
        Key=log_key,
        Body=json.dumps(log_doc, indent=2),
        ContentType="application/json",
    )

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "CloudGuard remediation cycle completed",
            "scan_id": scan_id,
            "mode": mode,
            "actions_count": len(actions_log),
            "log_key": log_key,
        }),
    }

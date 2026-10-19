"""Unit tests for remediation/handler.py using moto and pytest."""

import json
import os
from pathlib import Path
from unittest import mock

import boto3
from moto import mock_aws
import pytest

from remediation.handler import format_sns_alert, lambda_handler


@pytest.fixture
def sample_findings():
    sample_path = Path(__file__).parent.parent.parent / "samples" / "findings_before.json"
    with open(sample_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def s3_event():
    return {
        "Records": [
            {
                "eventVersion": "2.1",
                "eventSource": "aws:s3",
                "awsRegion": "ap-south-1",
                "eventName": "ObjectCreated:Put",
                "s3": {
                    "bucket": {
                        "name": "cspm-demo-reports-310788607340",
                        "arn": "arn:aws:s3:::cspm-demo-reports-310788607340",
                    },
                    "object": {
                        "key": "scans/20261105T093000Z-before.json",
                        "size": 1024,
                    },
                },
            }
        ]
    }


@mock_aws
def test_valid_scan_alert_only_mode(sample_findings, s3_event):
    """Test valid scan file in default alert-only mode."""
    # Setup mock S3
    s3 = boto3.client("s3", region_name="ap-south-1")
    bucket = "cspm-demo-reports-310788607340"
    s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": "ap-south-1"},
    )
    scan_key = "scans/20261105T093000Z-before.json"
    s3.put_object(
        Bucket=bucket,
        Key=scan_key,
        Body=json.dumps(sample_findings),
    )

    # Setup mock SNS
    sns = boto3.client("sns", region_name="ap-south-1")
    topic = sns.create_topic(Name="cspm-demo-alerts")
    topic_arn = topic["TopicArn"]

    with mock.patch.dict(
        os.environ,
        {"MODE": "alert-only", "TOPIC_ARN": topic_arn, "AWS_DEFAULT_REGION": "ap-south-1"},
    ):
        result = lambda_handler(s3_event)
        assert result["statusCode"] == 200

        # Check that remediation log was created in S3
        log_key = "remediation-logs/20261105T093000Z-before.json"
        log_obj = s3.get_object(Bucket=bucket, Key=log_key)
        log_data = json.loads(log_obj["Body"].read().decode("utf-8"))

        assert log_data["scan_id"] == "20261105T093000Z-before"
        assert log_data["mode"] == "alert-only"
        assert len(log_data["actions"]) > 0


@mock_aws
def test_ignore_non_scan_object():
    """Test loop-safety: non-scan prefix objects are ignored."""
    ignored_event = {
        "Records": [
            {
                "s3": {
                    "bucket": {"name": "cspm-demo-reports-310788607340"},
                    "object": {"key": "remediation-logs/20261105T093000Z-before.json"},
                }
            }
        ]
    }
    with mock.patch.dict(os.environ, {"MODE": "alert-only"}):
        result = lambda_handler(ignored_event)
        assert result["statusCode"] == 200
        assert "Ignored" in result["body"]


def test_invalid_mode_raises_error(s3_event):
    """Test that an unsupported mode raises ValueError."""
    with mock.patch.dict(os.environ, {"MODE": "unsupported-mode"}):
        with pytest.raises(ValueError, match="Invalid MODE"):
            lambda_handler(s3_event)


@mock_aws
def test_invalid_json_raises_error(s3_event):
    """Test that invalid JSON content raises JSONDecodeError."""
    s3 = boto3.client("s3", region_name="ap-south-1")
    bucket = "cspm-demo-reports-310788607340"
    s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": "ap-south-1"},
    )
    s3.put_object(
        Bucket=bucket,
        Key="scans/20261105T093000Z-before.json",
        Body="NOT_VALID_JSON{{{",
    )

    with mock.patch.dict(os.environ, {"MODE": "alert-only", "AWS_DEFAULT_REGION": "ap-south-1"}):
        with pytest.raises(json.JSONDecodeError):
            lambda_handler(s3_event)


def test_format_sns_alert(sample_findings):
    """Verify SNS alert subject and body contents."""
    expected_score = sample_findings["summary"]["score"]
    subject, body = format_sns_alert(sample_findings, mode="alert-only")
    assert "[CloudGuard]" in subject
    assert f"Score {expected_score}/100" in subject
    assert "CRITICAL" in subject
    assert "Scan ID:" in body
    assert "20261105T093000Z-before" in body
    assert "Top Priority Findings:" in body


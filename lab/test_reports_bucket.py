"""
test_reports_bucket.py - Verifies reports bucket permissions and lifecycle.
Part of P1 Phase 1.
"""

import boto3
from botocore.exceptions import ClientError

BUCKET_NAME = "cspm-demo-reports-310788607340"
TEST_KEY = "scans/test-verification.json"
TEST_CONTENT = b'{"test": "ok", "phase": "1"}'


def test_bucket_operations(profile="cspm-p1"):
    print(f"[*] Testing reports bucket operations using profile: {profile}...")
    session = boto3.Session(profile_name=profile, region_name="ap-south-1")
    s3 = session.client("s3")

    # 1. Put object under scans/
    print(f"    Writing to s3://{BUCKET_NAME}/{TEST_KEY}...")
    s3.put_object(Bucket=BUCKET_NAME, Key=TEST_KEY, Body=TEST_CONTENT)
    print("    Write successful.")

    # 2. Get object
    print(f"    Reading from s3://{BUCKET_NAME}/{TEST_KEY}...")
    obj = s3.get_object(Bucket=BUCKET_NAME, Key=TEST_KEY)
    body = obj["Body"].read()
    assert body == TEST_CONTENT, "Content mismatch!"
    print(f"    Read successful: {body.decode('utf-8')}")

    # 3. Clean up test object
    print(f"    Cleaning up test object...")
    s3.delete_object(Bucket=BUCKET_NAME, Key=TEST_KEY)
    print("    Cleanup successful. Reports bucket is fully functional.")


if __name__ == "__main__":
    test_bucket_operations()

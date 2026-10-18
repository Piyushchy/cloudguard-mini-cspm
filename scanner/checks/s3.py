"""S3-001 (public bucket) and S3-002 (versioning disabled)."""
from __future__ import annotations

from botocore.exceptions import ClientError

from scanner import core
from scanner.checks._util import client, err_code, get_account_id

BPA_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def _bpa_full(s3, bucket: str) -> tuple[bool, bool]:
    """Return (all four BPA settings on, any BPA config exists)."""
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if err_code(e) == "NoSuchPublicAccessBlockConfiguration":
            return False, False
        raise
    return all(cfg.get(k) for k in BPA_KEYS), True


def _policy_public(s3, bucket: str) -> bool:
    try:
        return bool(s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"])
    except ClientError as e:
        if err_code(e) == "NoSuchBucketPolicy":
            return False
        raise


def _acl_public(s3, bucket: str) -> bool:
    grants = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    return any(g.get("Grantee", {}).get("URI") in PUBLIC_GROUPS for g in grants)


def run(session, region: str, warnings: list | None = None, account_id: str | None = None) -> list[dict]:
    warnings = warnings if warnings is not None else []
    s3 = client(session, "s3", region)
    try:
        names = sorted(b["Name"] for b in s3.list_buckets()["Buckets"])
    except ClientError as e:
        warnings.append(f"S3: cannot list buckets ({err_code(e)}); S3 results are missing")
        return []

    findings = []
    for name in names:
        arn = f"arn:aws:s3:::{name}"

        # ---- S3-001
        try:
            bpa_full, _ = _bpa_full(s3, name)
            pol, acl = _policy_public(s3, name), _acl_public(s3, name)
            reasons = [r for r, on in (("a public bucket policy", pol), ("a public ACL grant", acl)) if on]
            if reasons and not bpa_full:
                status = "FAIL"
                desc = f"Bucket is public through {' and '.join(reasons)}, and Block Public Access is not fully on."
            elif reasons:
                status = "PASS"
                desc = (f"Bucket has {' and '.join(reasons)}, but Block Public Access is fully enabled, "
                        "so public access is blocked.")
            elif bpa_full:
                status, desc = "PASS", "Block Public Access is fully enabled; the bucket is not public."
            else:
                status, desc = "PASS", "No public bucket policy or ACL grant found."
            findings.append(core.make_finding("S3-001", name, arn, status, desc))
        except ClientError as e:
            warnings.append(f"S3-001 {name}: skipped ({err_code(e)})")

        # ---- S3-002
        try:
            v = s3.get_bucket_versioning(Bucket=name).get("Status")
            if v == "Enabled":
                findings.append(core.make_finding("S3-002", name, arn, "PASS", "Versioning is enabled."))
            else:
                state = "suspended" if v == "Suspended" else "not enabled"
                findings.append(core.make_finding("S3-002", name, arn, "FAIL", f"Versioning is {state} on this bucket."))
        except ClientError as e:
            warnings.append(f"S3-002 {name}: skipped ({err_code(e)})")
    return findings

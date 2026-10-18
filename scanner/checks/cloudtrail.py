"""CT-001: at least one active (logging) multi-region CloudTrail trail.

One finding per account (resource_id = account id) so the finding id stays the
same before and after, which lets compare.py match them.
"""
from __future__ import annotations

from botocore.exceptions import ClientError

from scanner import core
from scanner.checks._util import client, err_code, get_account_id


def run(session, region: str, warnings: list | None = None, account_id: str | None = None) -> list[dict]:
    warnings = warnings if warnings is not None else []
    account_id = account_id or get_account_id(session)
    try:
        trails = client(session, "cloudtrail", region).describe_trails(includeShadowTrails=True)["trailList"]
    except ClientError as e:
        warnings.append(f"CT-001: cannot describe trails ({err_code(e)}); CloudTrail result is missing")
        return []

    active = []
    for t in trails:
        if not t.get("IsMultiRegionTrail"):
            continue
        home = t.get("HomeRegion") or region
        try:
            status = client(session, "cloudtrail", home).get_trail_status(Name=t["TrailARN"])
        except ClientError as e:
            warnings.append(f"CT-001 {t.get('Name')}: cannot read trail status ({err_code(e)})")
            continue
        if status.get("IsLogging"):
            active.append(t)

    if active:
        t = sorted(active, key=lambda x: x["Name"])[0]
        return [core.make_finding("CT-001", account_id, t["TrailARN"], "PASS",
                                  f"Trail {t['Name']} is multi-region and logging is on.")]
    return [core.make_finding(
        "CT-001", account_id, f"arn:aws:cloudtrail:{region}:{account_id}:trail", "FAIL",
        "No multi-region CloudTrail trail with logging turned on was found.")]

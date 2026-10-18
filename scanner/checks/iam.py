"""IAM-001 (direct AdministratorAccess) and IAM-002 (console password without MFA)."""
from __future__ import annotations

from botocore.exceptions import ClientError

from scanner import core
from scanner.checks._util import client, err_code

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _has_console(iam, user: str) -> bool:
    try:
        iam.get_login_profile(UserName=user)
        return True
    except ClientError as e:
        if err_code(e) == "NoSuchEntity":
            return False
        raise


def run(session, region: str, warnings: list | None = None, account_id: str | None = None) -> list[dict]:
    warnings = warnings if warnings is not None else []
    iam = client(session, "iam", region)
    try:
        users = [u for page in iam.get_paginator("list_users").paginate() for u in page["Users"]]
    except ClientError as e:
        warnings.append(f"IAM: cannot list users ({err_code(e)}); IAM results are missing")
        return []

    findings = []
    for u in sorted(users, key=lambda x: x["UserName"]):
        name, arn = u["UserName"], u["Arn"]

        # ---- IAM-001
        try:
            attached = [p for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=name)
                        for p in page["AttachedPolicies"]]
            if any(p["PolicyArn"] == ADMIN_ARN for p in attached):
                findings.append(core.make_finding("IAM-001", name, arn, "FAIL",
                                "AdministratorAccess is attached directly to the user."))
            else:
                findings.append(core.make_finding("IAM-001", name, arn, "PASS",
                                "AdministratorAccess is not attached directly to the user."))
        except ClientError as e:
            warnings.append(f"IAM-001 {name}: skipped ({err_code(e)})")

        # ---- IAM-002
        try:
            if not _has_console(iam, name):
                findings.append(core.make_finding("IAM-002", name, arn, "PASS",
                                "User has no console password, so MFA is not required."))
            elif iam.list_mfa_devices(UserName=name)["MFADevices"]:
                findings.append(core.make_finding("IAM-002", name, arn, "PASS",
                                "User has a console password and an MFA device."))
            else:
                findings.append(core.make_finding("IAM-002", name, arn, "FAIL",
                                "User has a console password but no MFA device registered."))
        except ClientError as e:
            warnings.append(f"IAM-002 {name}: skipped ({err_code(e)})")
    return findings

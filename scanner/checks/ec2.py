"""EC2-001: security group open to the internet on SSH, RDP or all ports."""
from __future__ import annotations

from botocore.exceptions import ClientError

from scanner import core
from scanner.checks._util import client, err_code, get_account_id

RISKY_PORTS = ((22, "SSH"), (3389, "RDP"))


def open_rules(sg: dict) -> list[str]:
    """Describe every ingress rule that exposes SSH/RDP/all ports to 0.0.0.0/0 or ::/0."""
    hits = []
    for perm in sg.get("IpPermissions", []):
        sources = []
        if any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])):
            sources.append("0.0.0.0/0")
        if any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])):
            sources.append("::/0")
        if not sources:
            continue
        src = " and ".join(sources)
        proto = str(perm.get("IpProtocol"))
        if proto == "-1":
            hits.append(f"{src} on all traffic (all ports)")
        elif proto in ("tcp", "6"):
            lo, hi = perm.get("FromPort"), perm.get("ToPort")
            if lo is None or hi is None:
                continue
            if lo == 0 and hi == 65535:
                hits.append(f"{src} on all TCP ports")
                continue
            for port, name in RISKY_PORTS:
                if lo <= port <= hi:
                    hits.append(f"{src} on port {port} ({name})")
    return hits


def run(session, region: str, warnings: list | None = None, account_id: str | None = None) -> list[dict]:
    warnings = warnings if warnings is not None else []
    account_id = account_id or get_account_id(session)
    ec2 = client(session, "ec2", region)
    try:
        sgs = [sg for page in ec2.get_paginator("describe_security_groups").paginate()
               for sg in page["SecurityGroups"]]
    except ClientError as e:
        warnings.append(f"EC2: cannot describe security groups ({err_code(e)}); EC2 results are missing")
        return []

    findings = []
    for sg in sorted(sgs, key=lambda s: s["GroupId"]):
        gid, gname = sg["GroupId"], sg.get("GroupName", "")
        arn = f"arn:aws:ec2:{region}:{account_id}:security-group/{gid}"
        hits = open_rules(sg)
        if hits:
            desc = f"Security group {gname} allows {'; '.join(hits)}."
            findings.append(core.make_finding("EC2-001", gid, arn, "FAIL", desc))
        else:
            findings.append(core.make_finding(
                "EC2-001", gid, arn, "PASS",
                "No ingress rule is open to the internet on port 22, 3389 or all ports."))
    return findings

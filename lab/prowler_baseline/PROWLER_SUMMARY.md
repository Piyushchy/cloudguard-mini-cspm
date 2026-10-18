# Prowler Benchmark Mapping and Comparison

This document maps CloudGuard's 6 custom checks to their industry-standard [Prowler](https://github.com/prowler-cloud/prowler) equivalents, serving as the benchmark reference for Section 7b of the project report.

## Check Mapping Table

| CloudGuard Check | Severity | Description | Corresponding Prowler Check ID | Prowler Compliance Framework |
|---|---|---|---|---|
| **S3-001** | CRITICAL | S3 bucket is publicly accessible (BPA off + public policy) | `s3_bucket_level_public_access_block`, `s3_bucket_policy_public_write_access` | CIS AWS 2.1.5, AWS Well-Architected |
| **S3-002** | LOW | S3 bucket versioning is disabled | `s3_bucket_versioning_enabled` | CIS AWS 2.1.3 |
| **EC2-001** | HIGH | Security group allows ingress from 0.0.0.0/0 on port 22/3389/all | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22`, `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389` | CIS AWS 5.2, 5.3 |
| **IAM-001** | HIGH | IAM user has `AdministratorAccess` attached directly | `iam_user_administrator_access_policy`, `iam_policy_no_administrative_privileges` | CIS AWS 1.16 |
| **IAM-002** | HIGH | IAM user has console password but no MFA enabled | `iam_user_mfa_enabled_console_access` | CIS AWS 1.10 |
| **CT-001** | MEDIUM | No active multi-region CloudTrail trail logging | `cloudtrail_multi_region_enabled`, `cloudtrail_status_is_logging` | CIS AWS 3.1 |

---

## Benchmark Observations & Synthesis (For Report Section 7b)

1. **Agreement on Findings**:
   - Both Prowler and CloudGuard flag the 5 deliberate lab misconfigurations as critical/high security risks.
   - Both tools identify open ingress on port 22 (SSH) and unmanaged administrative IAM access as top-tier risks requiring immediate remediation.
2. **Key Architectural Differences**:
   - **Scope & Performance**: Prowler runs hundreds of broad CIS checks across dozens of services, taking several minutes to complete. CloudGuard runs focused, deterministic checks in under 5 seconds.
   - **Remediation Coupling**: Prowler is an audit tool with no native serverless auto-remediation pipeline. CloudGuard directly integrates finding output with automated Lambda event remediation and MTTR tracking.
   - **Scoring**: CloudGuard provides a deterministic 0–100 weighted posture score ($CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1$) that maps directly to SLOs ("posture score $\ge$ 90%").

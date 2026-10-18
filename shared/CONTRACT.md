# CloudGuard Mini-CSPM — Project Contract

This repository follows the Shared Project Contract defined in `Part A` of the project specification documents (`01_P1_Lab_and_Platform.md`, `02_P2_Scanner_and_Dashboard.md`, and `03_P3_Alert_and_Remediation.md`).

## Summary of Conventions

- **AWS Region**: `ap-south-1` (Mumbai)
- **Standard Prefix**: `cspm-demo-`
- **Reports Bucket**: `cspm-demo-reports-310788607340`
- **CloudTrail**: `cspm-demo-trail` with log bucket `cspm-demo-trail-logs-310788607340`
- **SNS Topic**: `cspm-demo-alerts`
- **Lambda Remediator**: `cspm-demo-remediator` (Role: `cspm-demo-remediator-role`)
- **Scanner Profile**: `cspm-scanner`
- **Mandatory Resource Tags**:
  - `Project = cspm-demo`
  - `Deliberate = true`
  - `cspm-remediate = true`

## Check Catalogue

| check_id | Target Check | Severity | Auto-fix? | remediation_action |
|---|---|---|---|---|
| **S3-001** | Bucket publicly accessible (BPA off & policy/ACL open) | CRITICAL | Yes | `S3_ENABLE_BPA` |
| **S3-002** | Bucket versioning disabled | LOW | Yes | `S3_ENABLE_VERSIONING` |
| **EC2-001** | Security group allows 0.0.0.0/0 on port 22, 3389, or all | HIGH | Yes | `EC2_REVOKE_OPEN_INGRESS` |
| **IAM-001** | IAM user has direct `AdministratorAccess` policy | HIGH | Yes | `IAM_DETACH_ADMIN_POLICY` |
| **IAM-002** | IAM user has console password but no MFA | HIGH | No | `NONE` |
| **CT-001** | No active multi-region CloudTrail trail | MEDIUM | No | `NONE` |

## Scoring Formula

$$\text{Score} = \text{round}\left(100 \times \frac{\sum \text{Weights of PASS}}{\sum \text{Weights of ALL}}\right)$$

Weights:
- **CRITICAL**: 10
- **HIGH**: 7
- **MEDIUM**: 4
- **LOW**: 1

Before remediation expected score on lab: ~51/100 (5 FAILs).  
After auto-remediation: ~89/100 (only IAM-002 FAIL remaining).  
After human manual fix of IAM-002: 100/100.

# IAM Least Privilege Policy Documentation (Report Section 8)

This directory defines the IAM execution role policy for `cspm-demo-remediator`. Every action is scoped to least privilege as required by the CloudGuard contract:

| Statement ID | Actions | Target Resource | One-Line Justification |
|---|---|---|---|
| `CloudWatchLogsAccess` | `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` | `/aws/lambda/cspm-demo-remediator:*` | Required for standard Lambda execution monitoring and audit trail |
| `S3ReportsBucketAccess` | `s3:GetObject` | `cspm-demo-reports-*/scans/*` | Allows reading incoming scan JSON files uploaded by P2's scanner |
| `S3RemediationLogsAccess` | `s3:PutObject` | `cspm-demo-reports-*/remediation-logs/*` | Allows writing audit/remediation logs for P2's dashboard to consume |
| `SNSPublishAlerts` | `sns:Publish` | `arn:aws:sns:...:cspm-demo-alerts` | Allows publishing scan summary and remediation alert emails |
| `S3RemediationActions` | `s3:GetBucketTagging`, `s3:GetBucketPublicAccessBlock`, `s3:PutBucketPublicAccessBlock`, `s3:GetBucketVersioning`, `s3:PutBucketVersioning` | `cspm-demo-vuln-bucket-*` | Required to inspect tags, apply S3 BPA (`S3_ENABLE_BPA`), and enable versioning (`S3_ENABLE_VERSIONING`) |
| `EC2RemediationActions` | `ec2:DescribeSecurityGroups`, `ec2:RevokeSecurityGroupIngress` | `*` (EC2 Revoke requires `*` or SG ARN) | Required to describe SG tags/rules and revoke 0.0.0.0/0 ingress (`EC2_REVOKE_OPEN_INGRESS`) |
| `IAMRemediationActions` | `iam:ListUserTags`, `iam:ListAttachedUserPolicies`, `iam:DetachUserPolicy` | `cspm-demo-vuln-user` | Required to verify tags and detach `AdministratorAccess` (`IAM_DETACH_ADMIN_POLICY`) strictly from the demo user only |

### Security Safeguards
1. **No wildcard permissions** on sensitive operations (`s3:*`, `iam:*`, `ec2:*` are strictly forbidden).
2. **Resource restriction**: Only the designated vulnerable bucket and vulnerable IAM user can be modified.
3. **Protected Resources**: CloudTrail trail bucket, reports bucket, root account, and scanner/remediator IAM users cannot be modified.

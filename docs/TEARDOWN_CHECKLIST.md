# CloudGuard Mini-CSPM — Final Teardown Checklist

> **IMPORTANT**: Execute this checklist **ONLY after** the project video is recorded and final course deliverables are submitted.

## Step 1: Teammate Local Credentials
- [ ] P2 deletes local `cspm-scanner` AWS CLI profile and access key.
- [ ] P3 deletes local `cspm-p3` AWS CLI profile and access key.

## Step 2: Teardown Vulnerable Lab Resources
Run the automated lab teardown:
```bash
python lab/teardown_lab.py --yes
```
This cleanly empties and deletes:
- `cspm-demo-vuln-bucket-<ACCOUNT_ID>`
- `cspm-demo-vuln-sg`
- `cspm-demo-vuln-user`

## Step 3: Teardown Serverless Remediation (P3)
If P3 created Lambda and SNS:
```bash
bash remediation/teardown.sh
```
Or delete via AWS CLI:
- Function: `cspm-demo-remediator`
- Role: `cspm-demo-remediator-role`
- SNS Topic: `cspm-demo-alerts`

## Step 4: Teardown Shared Infrastructure (P1)
Run the infrastructure teardown:
```bash
python lab/teardown_lab.py --include-infra --yes
```
This cleanly empties and deletes:
- Multi-region CloudTrail `cspm-demo-trail`
- Trail logs bucket `cspm-demo-trail-logs-<ACCOUNT_ID>`
- Central reports bucket `cspm-demo-reports-<ACCOUNT_ID>`

## Step 5: IAM Cleanup
Delete teammate IAM users:
```bash
aws iam detach-user-policy --user-name cspm-p2-scanner --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam detach-user-policy --user-name cspm-p2-scanner --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
aws iam delete-user-policy --user-name cspm-p2-scanner --policy-name cspm-reports-bucket-access
aws iam delete-user --user-name cspm-p2-scanner

aws iam detach-user-policy --user-name cspm-p3-remediator --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
aws iam delete-user-policy --user-name cspm-p3-remediator --policy-name cspm-remediator-role-management
aws iam delete-user --user-name cspm-p3-remediator
```

## Step 6: Billing Verification
- [ ] Check AWS Billing & Cost Management console $\rightarrow$ Bills.
- [ ] Verify total incurred charges are $0.00.
- [ ] Leave the $1.00 budget alert active for 48 hours to confirm zero lingering costs.

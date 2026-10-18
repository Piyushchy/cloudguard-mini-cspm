# P1 Command Log

Running log of all commands executed for P1 (Lab & Platform) for documentation, reproducibility, and the project report.

## Phase 0: Kickoff & Access Setup

```bash
# Verify Python version
python --version
# Output: Python 3.13.7

# Verify Git version
git --version
# Output: git version 2.50.0.windows.2

# Configure AWS credentials for P1 profile (interactive)
aws configure --profile cspm-p1
# Configured region: ap-south-1, format: json

# Verify caller identity
aws sts get-caller-identity --profile cspm-p1
# Output:
# {
#     "UserId": "AIDAUQXDRZVWL5PYFVTMZ",
#     "Account": "310788607340",
#     "Arn": "arn:aws:iam::310788607340:user/cspm-admin"
# }

# Create and switch to p1/platform branch
git checkout -b p1/platform

# Provision IAM users and policies for teammates P2 and P3
.venv\Scripts\python.exe lab/setup_teammate_iam.py
# Output:
# Created user 'cspm-p2-scanner' with SecurityAudit, ViewOnlyAccess, and S3 reports inline policy.
# Created user 'cspm-p3-remediator' with PowerUserAccess and scoped IAM role management inline policy.

## Phase 1: Shared Infrastructure Bootstrap

```bash
# Provision reports bucket and CloudTrail trail
.venv\Scripts\python.exe lab/bootstrap_infra.py
# Output:
# Created bucket 'cspm-demo-reports-310788607340' (BPA on, versioning on, 30-day lifecycle)
# Created bucket 'cspm-demo-trail-logs-310788607340' (BPA on, CloudTrail policy)
# Created and started multi-region trail 'cspm-demo-trail'

# Verify S3 buckets and CloudTrail status
aws s3 ls --profile cspm-p1
aws cloudtrail get-trail-status --name cspm-demo-trail --profile cspm-p1

# Verify reports bucket write/read/delete
.venv\Scripts\python.exe lab/test_reports_bucket.py
```

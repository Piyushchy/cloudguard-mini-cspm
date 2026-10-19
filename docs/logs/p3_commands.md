# P3 Command Log — Alert & Remediation

All commands run by P3 during the project, for traceability and the report.

---

## Phase 0 — Kickoff & Access

```bash
# Create P3 branch from p2/scanner
git checkout p2/scanner
git checkout -b p3/remediation

# Check Python version
python --version
# → Python 3.14.3

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate
pip install -r remediation/requirements-dev.txt

# Verify AWS access (run by HUMAN — keys never pasted in chat)
.venv\Scripts\python remediation/setup_profile.py
# → STS Identity Verified: Account 310788607340, User arn:aws:iam::310788607340:user/cspm-p3-remediator
```

---

## Phase 1 — Foundations (Alerting, IAM, Handler)

```bash
# Verify read-only access to SNS in ap-south-1
.venv\Scripts\python -c "import boto3; s = boto3.Session(profile_name='cspm-p3'); sns = s.client('sns', region_name='ap-south-1'); print(sns.list_topics())"

# Run offline unit tests for Lambda handler skeleton
.venv\Scripts\pytest remediation/tests/test_handler.py -v
```

---

## Phase 2 — Core Remediation Actions & Safety System

```bash
# Run unit tests covering all 4 actions, safety guardrails, and modes with moto
.venv\Scripts\pytest remediation/tests/test_actions.py -v

# Run full test suite
.venv\Scripts\pytest remediation/tests -v

# Test local runner in alert-only mode against sample findings
.venv\Scripts\python remediation/run_local.py --findings samples/findings_before.json --mode alert-only
```

---

## Phase 3 — Integration & Deployment

```bash
# Dry-run package build verification
.venv\Scripts\python remediation/deploy.py --help

# Push P3 branch to GitHub remote repository
git push -u origin p3/remediation
# → https://github.com/Piyushchy/cloudguard-mini-cspm/pull/new/p3/remediation
```


# CloudGuard Mini-CSPM — Project Status Tracker

## Phase Status Summary

| Phase | Description | Owner | Status | Gate Criteria |
|---|---|---|---|---|
| **Phase 0** | Kickoff & Access Setup | All / P1 | **COMPLETED (Gate 0 Passed)** | All humans verified via `aws sts get-caller-identity`, repo cloned, Part A agreed. |
| **Phase 1** | Foundations (Reports bucket, CloudTrail, IAM) | Parallel / P1 | **COMPLETED (Gate 1 Passed)** | Reports bucket, trail, scanner profile exist; sample findings committed. |
| **Phase 2** | Core Build (Vulnerable lab & remediation Lambda) | Parallel / P1, P3 | **COMPLETED (Gate 2 Passed)** | Lab created & verified; scanner reports 5 FAILs; remediation verified. |
| **Phase 3** | Integration (E2E pipeline test) | All | **COMPLETED** | Clean run twice in a row: scan $\rightarrow$ alert $\rightarrow$ fix $\rightarrow$ rescan. |
| **Phase 4** | Hardening & Rehearsal | All | PENDING | Dry-run screencast under 7:30; reset-and-retake verified. |
| **Phase 5** | Report & Presentation Slides | All | PENDING | Complete 10-section report compiled; slide deck finalized. |
| **Phase 6** | Recording, Submission & Teardown | All | PENDING | Video recorded & assembled; all AWS resources cleanly deleted. |

---

### Handoff Notes

#### Phase 0 — P1 Handoff
- **Done**:
  - AWS CLI v2 and Python verified.
  - Admin IAM user `cspm-admin` created on AWS account `310788607340`.
  - CLI profile `cspm-p1` configured and verified via `aws sts get-caller-identity`.
  - Repo branched to `p1/platform`.
  - `shared/config.env` and `shared/CONTRACT.md` initialized.
  - IAM permission drafts created for P2 and P3.
- **Artifacts**:
  - `shared/config.env`
  - `shared/CONTRACT.md`
  - `docs/STATUS.md`
  - `docs/logs/p1_commands.md`
- **Contract changes proposed**: None.
- **Blockers / needs from teammates**:
  - P2 and P3 teammate user names / setup decision (if separate human teammates or single-developer simulation).
- **Ready for next phase?**: Yes (pending Gate 0 signoff).

---

#### Phase 0 — P3 Handoff (Alert & Remediation)
- **Done**:
  - Created and checked out branch `p3/remediation` (branched from `p2/scanner`).
  - Verified local Python environment and installed dev dependencies (`boto3`, `botocore`, `pytest`, `moto`, `jsonschema`).
  - Evaluated AWS Lambda runtimes: targeted `python3.13` (GA on Amazon Linux 2023) for Lambda deployment.
  - Initialized `remediation/` package structure (`remediation/actions/`, `remediation/iam/`, `remediation/tests/`).
  - Created and tested AWS profile `cspm-p3` locally via `remediation/setup_profile.py`.
  - Verified AWS STS caller identity: authenticated successfully to shared Account `310788607340` as `arn:aws:iam::310788607340:user/cspm-p3-remediator`.
  - Initialized running command log at `docs/logs/p3_commands.md`.
- **Artifacts**:
  - Branch: `p3/remediation`
  - `remediation/__init__.py`
  - `remediation/requirements-dev.txt`
  - `remediation/setup_profile.py`
  - `docs/logs/p3_commands.md`
- **Contract changes proposed**: None.
- **Ready for next phase?**: Yes.

---

#### Phase 1 & 2 — P3 Handoff (Alert & Remediation)
- **Done**:
  - Created least-privilege IAM policy and trust policy in `remediation/iam/` (`policy.json`, `trust_policy.json`) and documented justifications in `remediation/iam/README.md`.
  - Implemented core Lambda skeleton in `remediation/handler.py` with S3 event parsing, schema validation, SNS alert formatter, and audit log generation.
  - Implemented central safety guardrails in `remediation/safety.py` (tag checks for `cspm-remediate=true`, non-negotiable protection list).
  - Implemented all 4 remediation actions in `remediation/actions/`:
    1. `S3_ENABLE_BPA` (Turn on all 4 Block Public Access settings, preserve policies).
    2. `S3_ENABLE_VERSIONING` (Enable object versioning).
    3. `EC2_REVOKE_OPEN_INGRESS` (Revoke specific `0.0.0.0/0` or `::/0` ingress on ports 22, 3389, and all ports).
    4. `IAM_DETACH_ADMIN_POLICY` (Detach `AdministratorAccess` strictly from `cspm-demo-vuln-user` only).
  - Implemented action dispatcher in `remediation/dispatcher.py` with 3 modes (`alert-only`, `dry-run`, `remediate`), exception isolation, and handling for non-automatable findings (`IAM-002`, `CT-001`).
  - Built local test runner `remediation/run_local.py` for testing before Lambda deployment.
  - Built deployment pipeline in `remediation/deploy.py` and `remediation/deploy.sh` (automatic packaging, concurrency=1, S3 notification configuration).
  - Built rollback CLI `remediation/rollback.py` to restore state from remediation logs.
  - Built cleanup tool `remediation/teardown.py` and `remediation/teardown.sh`.
  - Passed 10/10 offline unit tests with `moto` and `pytest` (`test_handler.py`, `test_actions.py`).
- **Artifacts**:
  - `remediation/handler.py`
  - `remediation/safety.py`
  - `remediation/dispatcher.py`
  - `remediation/actions/`
  - `remediation/run_local.py`
  - `remediation/deploy.py`
  - `remediation/rollback.py`
  - `remediation/teardown.py`
  - `remediation/tests/`
- **Contract changes proposed**: None.
- **Blockers / needs from teammates**:
  - None. Everything for P3 is deployed and verified!
- **Ready for next phase?**: Yes.

---

#### Phase 3 — P3 Handoff (Alert & Remediation)
- **Done**:
  - Created SNS Topic `cspm-demo-alerts` (`arn:aws:sns:ap-south-1:310788607340:cspm-demo-alerts`) and confirmed subscription for `shreya.tiwari0416@gmail.com`.
  - Created least-privilege IAM execution role `cspm-demo-remediator-role` in AWS with inline policy.
  - Packaged and deployed Lambda function `cspm-demo-remediator` (Python 3.13, 256MB, Amazon Linux wheels bundled).
  - Configured S3 bucket notification trigger on `cspm-demo-reports-310788607340` (`scans/*.json` -> `cspm-demo-remediator`).
  - Successfully executed live end-to-end integration test in AWS against `scans/20261018T173826Z-before.json`:
    - Lambda invoked successfully (HTTP 200).
    - SNS security posture alert email dispatched to subscriber.
    - Audit remediation log written to `s3://cspm-demo-reports-310788607340/remediation-logs/20261018T173826Z-before.json`.
  - Tested local action runner and verified safety safeguards against real AWS resources.
- **Artifacts**:
  - Lambda: `arn:aws:lambda:ap-south-1:310788607340:function:cspm-demo-remediator`
  - SNS Topic: `arn:aws:sns:ap-south-1:310788607340:cspm-demo-alerts`
  - IAM Role: `arn:aws:iam::310788607340:role/cspm-demo-remediator-role`
  - S3 Audit Log: `s3://cspm-demo-reports-310788607340/remediation-logs/20261018T173826Z-before.json`
  - Codebase: `remediation/` (all modules, tests, deploy, rollback, and teardown scripts)
- **Contract changes proposed**: None.
- **Blockers / needs from teammates**:
  - None. P3 serverless pipeline is fully operational and ready for the complete team demo!
- **Ready for next phase?**: Yes.

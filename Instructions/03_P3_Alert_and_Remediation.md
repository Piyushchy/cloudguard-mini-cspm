# CloudGuard Mini-CSPM — File 3 of 3 — P3: ALERT & REMEDIATION

**Paste this whole file into your AI agent first.** Then say: *"Follow Section A10. Start with your summary and Phase 0 plan."*

You are the AI assistant of **P3 (Alert & Remediation)**. Your human builds the serverless part: the Lambda that reacts to new scan results, sends alerts through SNS, safely fixes eligible findings, and logs what it did. Teammates: P1 (Lab & Platform, owns AWS account and repo) and P2 (Scanner & Dashboard).

---
# PART A — SHARED PROJECT CONTRACT (identical in all three files)

> Do not change anything in Part A on your own. If you think the contract must change, tell your human. All three humans must approve, then every agent's copy is updated.

## A1. Project summary
**CloudGuard: a Mini Cloud Security Posture Management (CSPM) tool on AWS.**
Course: Cloud Computing (advanced application project). Deliverables: working prototype on AWS, 7–8 min screencast with all 3 members speaking, a report, and a presentation.

**Story the demo tells:** (1) deliberately create a misconfigured AWS lab → (2) scan it and score it → (3) alert the team → (4) auto-fix what is safe to fix → (5) re-scan and show the score improve → (6) show one issue that still needs a human.

**Syllabus mapping (use this in the report):**
- 1.1 Cloud service models and the shared responsibility model (customer owns configuration).
- 2.1 Service management: security posture score as a KPI, SLO such as "posture score ≥ 90%", MTTR (time from scan upload to fix) as a monitored metric.
- 2.2 Cloud economics: whole solution runs on free-tier / pay-per-use services (near-zero cost) vs. the cost of a breach.
- 3.x Managing data: S3 object storage holds scan results and logs; event-driven processing of that data.
- Serverless/event-driven design (Lambda + S3 events + SNS).

## A2. Team roles (equal workload)
| Role | Owns | One-line mission |
|---|---|---|
| **P1 – Lab & Platform** | AWS account, budgets, IAM users, repo, shared infra, vulnerable lab, Prowler benchmark, E2E tests, demo runbook, teardown | "Build the world that gets scanned, and keep everything safe and cheap." |
| **P2 – Scanner & Dashboard** | Scanner checks, scoring, findings JSON, dashboard, before/after comparison | "Find the problems and show them clearly." |
| **P3 – Alert & Remediation** | SNS alerts, remediation Lambda, safety model, S3 event wiring, rollback | "Notify and safely fix what can be fixed." |

Names: P1 = ____________  P2 = ____________  P3 = ____________   Deadline: ____________

## A3. Architecture
```
 P1 Lab (deliberately vulnerable resources)
        │  scanned by
        ▼
 P2 scan.py (boto3 checks + scoring) ──uploads──► S3: cspm-demo-reports-<ACCOUNT_ID>
        │                                          key: scans/<scan_id>.json
        │                                                │ S3 ObjectCreated (prefix scans/)
        │                                                ▼
        │                                  P3 Lambda: cspm-demo-remediator
        │                                     ├─► SNS topic cspm-demo-alerts → email
        │                                     ├─► fixes (only if MODE=remediate)
        │                                     └─► writes remediation-logs/<scan_id>.json
        ▼
 P2 Streamlit dashboard (reads scans/ + remediation-logs/)
 P1 Prowler = independent benchmark only (not part of the live pipeline)
```

## A4. Fixed names and conventions
- **Region:** `ap-south-1` (Mumbai) for everything regional. Stored in `shared/config.env` (single source of truth).
- **Prefix:** every resource we create starts with `cspm-demo-`.
- **Resources:**
  - Reports bucket (private, versioned, Block Public Access ON): `cspm-demo-reports-<ACCOUNT_ID>` (P1)
  - CloudTrail trail `cspm-demo-trail` + log bucket `cspm-demo-trail-logs-<ACCOUNT_ID>` (P1)
  - SNS topic `cspm-demo-alerts` (P3)
  - Lambda `cspm-demo-remediator`, role `cspm-demo-remediator-role` (P3)
  - AWS CLI profile for scanner: `cspm-scanner` (read-only + write to reports bucket `scans/` only) (P1 sets up permissions, P2 uses)
  - Deliberately vulnerable resources (P1): bucket `cspm-demo-vuln-bucket-<ACCOUNT_ID>`, security group `cspm-demo-vuln-sg`, IAM user `cspm-demo-vuln-user`
- **Tags on every deliberate resource:** `Project=cspm-demo`, `Deliberate=true`, `cspm-remediate=true`
- **Repo (GitHub, private):** `cloudguard-mini-cspm`
  ```
  shared/    config.env, findings.schema.json, CONTRACT.md      (P1 owns)
  lab/       create_lab.py, verify_lab.py, reset_lab.py, teardown_lab.py, prowler_baseline/   (P1)
  scanner/   scan.py, core.py, checks/, compare.py, dashboard/, tests/, requirements.txt      (P2)
  remediation/ handler.py, actions/, deploy.sh, rollback.py, tests/                          (P3)
  samples/   findings_before.json, findings_after.json, remediation_log.json                  (P2 creates)
  tests/     e2e_demo.py                                                                      (P1)
  docs/      STATUS.md, DEMO_RUNBOOK.md, report/, slides/                                    (shared)
  ```
- **Git rules:** one branch per person (`p1/...`, `p2/...`, `p3/...`), merge to `main` by pull request reviewed by one other member. **Never commit secrets** (`.env`, access keys, `*.pem`). Add them to `.gitignore` first.

## A5. Check catalogue and findings contract
Each check produces one finding per resource it inspects: `FAIL` if risky, `PASS` if fine (PASS items are needed for the score).

| check_id | What it detects | Severity | Auto-fix? | remediation_action |
|---|---|---|---|---|
| S3-001 | Bucket publicly accessible (Block Public Access not fully on AND public policy or ACL grant) | CRITICAL | Yes | `S3_ENABLE_BPA` |
| S3-002 | Bucket versioning disabled | LOW | Yes | `S3_ENABLE_VERSIONING` |
| EC2-001 | Security group allows 0.0.0.0/0 or ::/0 on port 22, 3389, or all ports | HIGH | Yes | `EC2_REVOKE_OPEN_INGRESS` |
| IAM-001 | IAM user has `AdministratorAccess` attached directly | HIGH | Yes | `IAM_DETACH_ADMIN_POLICY` |
| IAM-002 | IAM user has a console password but no MFA | HIGH | **No** (needs a human) | `NONE` |
| CT-001 | No active multi-region CloudTrail trail | MEDIUM | No | `NONE` |

**Expected on the lab (before):** 5 FAIL (S3-001, S3-002, EC2-001, IAM-001, IAM-002). **After auto-remediation:** only IAM-002 FAIL. **After the human fixes IAM-002** (deleting the demo user's console login profile): 0 FAIL.

**Scoring (deterministic):** weights CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1. `score = round(100 × (sum of weights of PASS findings) / (sum of weights of all findings))`. Counts per severity are for FAIL findings only.

**Findings file** (`scans/<scan_id>.json`; `scan_id` = `YYYYMMDDTHHMMSSZ-<label>` where label is `before`, `after`, or `adhoc`):
```json
{
  "scan_id": "20261105T093000Z-before",
  "timestamp": "2026-11-05T09:30:00Z",
  "account_id": "123456789012",
  "region": "ap-south-1",
  "label": "before",
  "summary": {"score": 41, "total": 12, "failed": 5,
              "by_severity": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 0, "LOW": 1}},
  "findings": [
    {"id": "S3-001#cspm-demo-vuln-bucket-123456789012",
     "check_id": "S3-001", "title": "S3 bucket is publicly accessible",
     "service": "s3", "resource_id": "cspm-demo-vuln-bucket-123456789012",
     "resource_arn": "arn:aws:s3:::cspm-demo-vuln-bucket-123456789012",
     "severity": "CRITICAL", "status": "FAIL",
     "description": "Public read is granted by bucket policy and Block Public Access is off.",
     "remediation_hint": "Enable all four Block Public Access settings.",
     "auto_remediable": true, "remediation_action": "S3_ENABLE_BPA"}
  ]
}
```
`shared/findings.schema.json` (JSON Schema) must match this exactly. Every scan is validated against it before upload.

**Remediation log** (`remediation-logs/<scan_id>.json`, written by P3):
```json
{"scan_id": "20261105T093000Z-before", "mode": "remediate",
 "started": "2026-11-05T09:30:04Z", "finished": "2026-11-05T09:30:09Z",
 "actions": [{"finding_id": "S3-001#...", "check_id": "S3-001", "resource_id": "...",
              "action": "S3_ENABLE_BPA",
              "result": "SUCCESS | DRY_RUN | SKIPPED_NOT_TAGGED | SKIPPED_NOT_AUTOMATABLE | ALREADY_COMPLIANT | FAILED",
              "before_state": {}, "detail": "..."}]}
```
KPI: **MTTR** = `finished` of the remediation log minus `timestamp` of the scan.

## A6. Remediation safety rules (non-negotiable)
1. Act only on resources tagged `cspm-remediate=true`. Re-check the tag in code even if IAM conditions also enforce it.
2. `MODE` environment variable on the Lambda: `alert-only` (default) → `dry-run` → `remediate`. Never default to `remediate`.
3. Only reversible configuration changes. **Never delete** resources or data. Save `before_state` for every action.
4. Never touch: the reports bucket, the CloudTrail bucket, the root account, or any IAM user other than `cspm-demo-vuln-user`.
5. The Lambda is triggered only by prefix `scans/`, and writes only to `remediation-logs/`, so it can never trigger itself. Reserved concurrency = 1.

## A7. Cost guardrails (all three agents enforce these)
- Allowed: S3, IAM, EC2 security groups (no instances), Lambda, SNS (email), CloudWatch Logs, CloudTrail (first management-events trail), optional EventBridge.
- **Forbidden unless all humans agree:** EC2 instances, NAT gateways, RDS, AWS Config, GuardDuty, Inspector, Security Hub, Macie, any paid marketplace item.
- P1 sets a $1 budget alert on day 0. Free-tier terms change: verify on the AWS Billing console, do not assume.
- Public bucket holds **only** a dummy file with harmless text. Never put real data or real credentials anywhere in this project.

## A8. Phases and gates
Fit these to your deadline (suggested days assume ~2 weeks; compress proportionally).

| Phase | Name | Suggested time | Gate to leave the phase |
|---|---|---|---|
| 0 | Kickoff and access | 0.5–1 day | **Gate 0:** each human can run `aws sts get-caller-identity` on the shared account; repo cloned; Part A read and agreed |
| 1 | Foundations (parallel) | 2 days | **Gate 1:** reports bucket + trail + scanner profile exist; sample findings files committed and valid; SNS confirmed and Lambda skeleton passes unit tests on samples |
| 2 | Core build (parallel) | 3 days | **Gate 2:** lab creates/verifies/tears down; scanner reports exactly the 5 expected FAILs on the real lab; each remediation action works on the lab one by one |
| 3 | Integration | 2 days | **Gate 3:** full pipeline works from a clean state **twice in a row**, with alert email received |
| 4 | Hardening and rehearsal | 1–2 days | **Gate 4:** reset-and-retake works; full run under 7 min; error cases tested; dry-run recording done |
| 5 | Report and slides | 2 days | **Gate 5:** report and slides complete and reviewed by all three |
| 6 | Recording, submission, teardown | 1 day | **Final gate:** video submitted, all AWS resources deleted, access keys deleted, billing checked |

**Status protocol:** at the end of each phase, your agent writes a *Handoff Note* (template below). Your human pastes it into `docs/STATUS.md` and into the group chat. Do not start the next phase until your human says "Gate N passed."
```
### Handoff — Phase N — P#
Done:
Artifacts (paths / URLs):
Contract changes proposed: none | ...
Blockers / needs from teammates:
Ready for next phase? yes / no
```

## A9. Report outline, video plan, ownership
**Report sections** (each owner writes theirs; P2 compiles the final document):
1 Introduction and problem (P1) · 2 Cloud concepts and syllabus mapping (P1) · 3 Architecture (P1) · 4 Lab design (P1) · 5 Scanner, scoring and dashboard (P2) · 6 Alerting and remediation, safety model (P3) · 7 Results: 7a before/after and KPIs (P2), 7b Prowler benchmark (P1) · 8 Security, IAM least privilege, cost analysis (P3) · 9 Limitations and future work (P2) · 10 Conclusion (P3) · References (everyone adds theirs).

**Slides:** each person builds slides for their own sections (~4–5 each); P3 assembles the final deck.

**Video (7–8 min, everyone speaks):** P1 0:00–2:30 (problem, architecture, lab, show vulnerable state) → P2 2:30–5:00 (live scan, findings, score, dashboard) → P3 5:00–7:30 (alert email, auto-remediation, re-scan, manual-fix case, KPIs) → 7:30–8:00 each member says one closing line. P1 edits and assembles the video.

## A10. Rules for the AI agent (apply to everything you do)
1. **Read Parts A and B fully, then reply with:** a 5-line summary of your understanding, questions about anything unclear, and your plan for the current phase. Only then start.
2. Work **one phase at a time**. Stop at the end of each phase, produce the Handoff Note, and wait for the human to say the gate has passed.
3. Mark every step as **[AGENT]** (you do it) or **[HUMAN]** (only the human can do it: signing up, MFA, clicking in the AWS console, entering secrets, confirming emails, recording the screen, anything needing a browser login). For [HUMAN] steps give exact click-by-click instructions and say how to verify success.
4. **Never ask the human to paste secrets** (access keys, passwords, tokens) into the chat. Tell them to use `aws configure --profile ...` or environment variables locally.
5. **Before any command that creates, changes, or deletes AWS resources,** show the command, say what it does and its cost impact, and ask for a go-ahead. Prefer `--dry-run` or read-only calls first.
6. After every step, **verify** with a read-only command and show the expected output.
7. Explain in plain language, as if the human is a student seeing this service for the first time. The human will have to explain it on camera.
8. Keep a running log of commands you ran (`docs/logs/<role>_commands.md`); it helps the report.
9. If something in the real AWS behaviour differs from this file (service names, CLI flags, console layout, Lambda runtime versions, Prowler options), say so, check the current official documentation, and suggest a fix. Do not guess silently.
10. Do not expand scope. Stretch ideas are only for after Gate 3.


---
# PART B — P3 WORK PLAN

## B0. Your deliverables
1. SNS topic `cspm-demo-alerts` with a confirmed email subscription.
2. Lambda `cspm-demo-remediator` with least-privilege role `cspm-demo-remediator-role`.
3. Four remediation actions + safety framework (modes, tag check, before_state, logging).
4. S3 event wiring (reports bucket `scans/` → Lambda), `deploy.sh`, tests, optional `rollback.py`.
5. Report sections 6, 8, 10; slides for them; final slide-deck assembly; video segment 5:00–7:30 plus closing.

## Phase 0 — Kickoff and access
- **[AGENT]** Set up Python 3.11+, venv, `remediation/requirements-dev.txt` (`boto3`, `pytest`, `moto`). Check which Python runtimes AWS Lambda currently supports (official docs) and pick the newest stable one.
- **[HUMAN]** Wait for P1's invitation to the AWS account and GitHub repo. Sign in, set password and **MFA**, create your own access key, then `aws configure --profile cspm-p3` locally (never paste the key into chat).
- **[AGENT]** Verify `aws sts get-caller-identity --profile cspm-p3`. Clone the repo; create branch `p3/remediation`.
- **Gate 0 check + Handoff note.**

## Phase 1 — Foundations
- **[AGENT]** Create SNS topic `cspm-demo-alerts` (show the command first). **[HUMAN]** subscribe your email (and optionally teammates'), then click the confirmation link in the email. Verify with `aws sns list-subscriptions-by-topic` (status must not be "PendingConfirmation").
- **[AGENT]** Write the **least-privilege IAM policy** for `cspm-demo-remediator-role` as a JSON file (`remediation/iam/policy.json`) and a trust policy for Lambda. Allow only:
  - Logs: create group/stream, put events (for its own log group).
  - S3: `GetObject` on `<reports>/scans/*`; `PutObject` on `<reports>/remediation-logs/*`.
  - SNS: `Publish` on the topic ARN only.
  - Remediation APIs: `s3:GetBucketTagging`, `s3:GetBucketPublicAccessBlock`, `s3:PutBucketPublicAccessBlock`, `s3:GetBucketVersioning`, `s3:PutBucketVersioning`, `ec2:DescribeSecurityGroups`, `ec2:RevokeSecurityGroupIngress`, `iam:ListUserTags`, `iam:ListAttachedUserPolicies`, `iam:DetachUserPolicy`.
  - Add tag-based `Condition` blocks (`aws:ResourceTag/cspm-remediate = true`) wherever AWS supports it for that action; the code still checks tags itself.
  Explain each permission in one line (these explanations go into report section 8).
- **[AGENT]** Create the Lambda skeleton `remediation/handler.py`:
  - Parse the S3 event, fetch and parse the findings JSON, validate with `shared/findings.schema.json`.
  - Read `MODE` env var (default `alert-only`); reject unknown values.
  - Build and publish the SNS alert (subject like `[CloudGuard] Score 41/100 - 1 CRITICAL, 3 HIGH`; body: score, counts, top 3 findings, mode, scan_id).
  - Write a basic remediation log (no actions yet).
- **[AGENT]** Unit tests with `moto` and P2's `samples/findings_before.json` (until P2 delivers, use the example in A5). Cover: valid file, invalid JSON, wrong mode, file under the wrong prefix (ignored).
- **Gate 1 check + Handoff note.**

## Phase 2 — Core build: remediation actions
Create `remediation/actions/` with one module per action code from A5. Every action implements the same pattern:
`check tag → read current state (before_state) → if already compliant: ALREADY_COMPLIANT → if MODE=dry-run: DRY_RUN → apply change → re-read to verify → return result with detail`. Wrap each action in try/except so one failure never stops the others.

| Action code | What it does | Notes |
|---|---|---|
| `S3_ENABLE_BPA` | Turn on all four Block Public Access settings on the bucket | Do not delete the policy. Record the old policy status in `before_state` |
| `S3_ENABLE_VERSIONING` | Enable versioning | Cannot be fully undone (can only suspend); mention in report |
| `EC2_REVOKE_OPEN_INGRESS` | Revoke only the specific `0.0.0.0/0` / `::/0` rule(s) for port 22/3389/all | Record the exact rule so it can be restored |
| `IAM_DETACH_ADMIN_POLICY` | Detach `AdministratorAccess` from `cspm-demo-vuln-user` only | Hard-code the allowed user name as an extra safety net |

- Findings with `auto_remediable=false` (IAM-002, CT-001) are logged as `SKIPPED_NOT_AUTOMATABLE` and highlighted in the alert as "needs a human".
- Untagged resources are logged `SKIPPED_NOT_TAGGED`.
- Deliberate protection list in code: reports bucket, trail log bucket, root, any IAM user other than the demo user → always skipped, even if someone tags them.
- **[AGENT]** Tests per action with `moto`: tagged vs untagged, already compliant, dry-run, failure path.
- **[HUMAN]** After P1's lab exists (Gate 2), run each action **locally** against the lab through a small `remediation/run_local.py --findings <file> --mode dry-run|remediate` (same code path as Lambda). Verify each change in the AWS console. Use `reset_lab.py` (P1) between tries.
- **Gate 2 check + Handoff note.**

## Phase 3 — Integration: deploy and wire up
- **[AGENT]** Write `remediation/deploy.sh` (AWS CLI; idempotent where possible): create/update role, zip and deploy the Lambda (timeout 60 s, memory 256 MB, env `MODE=alert-only`, `REPORTS_BUCKET`, `TOPIC_ARN`), set **reserved concurrency = 1**, add S3 invoke permission for the Lambda, and configure the **S3 notification** on the reports bucket for `s3:ObjectCreated:*` with prefix `scans/` and suffix `.json`.
- **[HUMAN]** Approve and run the deploy. (P1 may need to grant `s3:PutBucketNotification` if it fails.)
- **[AGENT]** Integration tests in this order, each time resetting the lab first:
  1. `MODE=alert-only`: upload a P2 scan → email arrives, log shows all actions skipped, nothing changed.
  2. `MODE=dry-run`: log shows `DRY_RUN` for 4 actions, nothing changed.
  3. `MODE=remediate`: 4 fixes applied, IAM-002 flagged "needs a human"; P2's `after` scan shows only IAM-002 FAIL.
  Switch modes with `aws lambda update-function-configuration`. Show CloudWatch Logs for debugging.
- **[AGENT]** Add **MTTR** to the remediation log and the email (`finished − scan timestamp`).
- **Gate 3 check + Handoff note.**

## Phase 4 — Hardening
- **[AGENT]** Loop safety test: confirm writing `remediation-logs/...` does **not** trigger the Lambda; invoke counts stay minimal.
- **[AGENT]** Failure tests: malformed scan file, S3 get error, SNS failure, an action raising an exception, timeouts. Lambda must log clearly and never crash silently.
- **[AGENT]** Review the IAM policy against what CloudTrail/CloudWatch shows is actually used; remove anything unnecessary.
- **[AGENT, optional]** `remediation/rollback.py <remediation-log>` that restores `before_state` for EC2 and IAM actions (S3 BPA too if simple). Useful for retakes and a strong report point.
- **[AGENT]** Prepare the manual-fix moment for the video: explain why IAM-002 cannot be auto-fixed (a human must decide to add MFA or remove console access), then give the exact command/console steps to remove the demo user's console login profile. **[HUMAN]** practise it.
- **[HUMAN]** Practise your live segment: show alert email, show mode switch, show remediation, show after-scan. ≤ 2:30.
- **Gate 4 check + Handoff note.**

## Phase 5 — Report and slides
- **[AGENT]** Help draft your report sections:
  - 6: Lambda design, event flow, modes, action table, safety rules from A6, example email and remediation log.
  - 8: IAM least privilege explanation (permission-by-permission), shared responsibility, cost analysis table (service, usage, expected cost; include the real bill), and risk discussion (what could go wrong with auto-remediation and how it is limited).
  - 10: conclusion: what was built, KPIs achieved (score before/after, MTTR), learning outcomes.
- **[HUMAN]** Make 4–5 slides and **assemble the final deck** from P1's and P2's slides: consistent theme, one architecture slide, one demo-flow slide, one results slide, one syllabus-mapping slide, one summary slide.
- **Gate 5 check + Handoff note.**

## Phase 6 — Recording and cleanup
- **[HUMAN]** Record segment 5:00–7:30 (plus your closing line). Send raw recording to P1.
- **[AGENT]** Write `remediation/teardown.sh`: remove S3 notification, delete Lambda, role, policies, log group, SNS topic and subscriptions. **[HUMAN]** run it after submission is safe (coordinate with P1's checklist), delete your access key and local profile.
- **Final gate + Handoff note.**

## Definition of done for P3
Email alert arrives; three modes behave exactly as specified; four fixes verified on the real lab; safety rules proven by tests; IAM policy minimal; report, slides, and teardown complete.

## Dependencies on teammates
- From P1: reports bucket, permissions, lab (Phase 1–2), `reset_lab.py` for repeat tests.
- From P2: sample and real findings files and schema validation (Phase 1–3).
- You provide: action codes behaviour and the remediation log (Phase 2) which P2's dashboard and P1's E2E test consume.

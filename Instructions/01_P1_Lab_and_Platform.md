# CloudGuard Mini-CSPM — File 1 of 3 — P1: LAB & PLATFORM

**Paste this whole file into your AI agent first.** Then say: *"Follow Section A10. Start with your summary and Phase 0 plan."*

You are the AI assistant of **P1 (Lab & Platform)**. Your human owns the AWS account, the repo, the shared infrastructure, the deliberately vulnerable lab, the Prowler benchmark, the end-to-end tests, the demo runbook and the final teardown. Teammates: P2 (Scanner & Dashboard) and P3 (Alert & Remediation).

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
# PART B — P1 WORK PLAN

## B0. Your deliverables
1. AWS account secured, $1 budget alert, IAM users for P2 and P3 with sensible permissions.
2. GitHub repo with the layout from A4, `shared/config.env`, `shared/findings.schema.json`, `docs/STATUS.md`.
3. Shared infra: reports bucket, CloudTrail trail + log bucket, `cspm-scanner` permissions.
4. Lab scripts: `create_lab.py`, `verify_lab.py`, `reset_lab.py`, `teardown_lab.py`.
5. Prowler baseline and a comparison with P2's scanner.
6. `tests/e2e_demo.py` and `docs/DEMO_RUNBOOK.md`.
7. Report sections 1, 2, 3, 4, 7b; slides for those; video segment 0:00–2:30; video editing; final teardown.

## Phase 0 — Kickoff and access
- **[HUMAN]** Create or choose the AWS account. Enable MFA on the root user, then stop using root for daily work. Create an admin IAM user for yourself and enable MFA on it.
- **[HUMAN]** Billing → Budgets: create a **$1 monthly cost budget** with email alerts at 80% and 100%. Also turn on "Receive Free Tier usage alerts" in Billing preferences.
- **[HUMAN]** Create a private GitHub repo `cloudguard-mini-cspm`; add P2 and P3 as collaborators.
- **[AGENT]** Help install and verify: AWS CLI v2, Python 3.11+, Git. Verify with `aws --version`, `python --version`, `aws sts get-caller-identity`.
- **[AGENT]** Create the repo scaffold from A4: folders, `.gitignore` (include `.env`, `*.pem`, `*.key`, `.aws/`, `__pycache__/`), `README.md`, `shared/config.env` (`AWS_REGION=ap-south-1`, `PREFIX=cspm-demo`), `docs/STATUS.md`, `docs/logs/`. Write `shared/findings.schema.json` exactly matching A5, plus a short `shared/CONTRACT.md` that points to Part A.
- **[AGENT]** Draft the IAM permissions for teammates, then ask your approval:
  - P2 user: `SecurityAudit` + `ViewOnlyAccess` managed policies, plus a small inline policy allowing `s3:PutObject`/`s3:GetObject`/`s3:ListBucket` only on the reports bucket (`scans/*` for put).
  - P3 user: needs Lambda, SNS, CloudWatch Logs, S3 bucket notification, and creating the Lambda's role. Prefer `PowerUserAccess` plus an inline policy that allows `iam:CreateRole/PutRolePolicy/AttachRolePolicy/PassRole/GetRole` only on roles named `cspm-demo-*`. (Note: `PowerUserAccess` excludes IAM, hence the extra policy.)
  - Both users: console login and **MFA required** (create the users, let each teammate set their own password and MFA).
- **[HUMAN]** Create the two IAM users per the agreed policies; send each teammate their sign-in URL. Teammates create their own access keys and run `aws configure --profile cspm-<name>`. Keys are never shared in chat.
- **Gate 0 check:** each human runs `aws sts get-caller-identity --profile ...` and sees the same account ID. Handoff note.

## Phase 1 — Foundations
- **[AGENT]** Write `lab/bootstrap_infra.py` (boto3, idempotent, supports `--dry-run`) that creates:
  - `cspm-demo-reports-<ACCOUNT_ID>`: Block Public Access ON (all four), versioning ON, default encryption SSE-S3, lifecycle rule to expire objects after 30 days (keeps storage near zero).
  - CloudTrail `cspm-demo-trail` (multi-region, management events only) with log bucket `cspm-demo-trail-logs-<ACCOUNT_ID>` (BPA ON, correct bucket policy for CloudTrail). Confirm with the human it is the **first trail** so it stays in the free allowance.
- **[AGENT]** Grant the `cspm-scanner` capability: confirm P2's IAM user can run read calls and put to `scans/`. Test with `aws s3 cp` of a dummy file and delete it.
- **[HUMAN]** Run the bootstrap after reviewing the dry-run output. Confirm in the console that the bucket and trail exist.
- **[AGENT]** Install Prowler in a virtual environment (pip or Docker; check the current install instructions) and run `prowler --help` to record the exact flags for this version in `lab/prowler_baseline/NOTES.md`. Do not run it against the account yet.
- **Outputs for others:** repo with schema, config and STATUS file; reports bucket name; confirmation that P2/P3 permissions work.
- **Gate 1 check + Handoff note.**

## Phase 2 — Core build: the vulnerable lab
Build four scripts with a shared helper module. All must be **idempotent**, support `--dry-run`, tag resources per A4, and print what they will do before doing it.

1. `create_lab.py`
   - **S3:** bucket `cspm-demo-vuln-bucket-<ACCOUNT_ID>`; versioning left OFF; bucket-level Block Public Access OFF; bucket policy granting public `s3:GetObject` **only** on `public-demo/hello.txt`; upload that file with the text "demo only, not sensitive". First **check the account-level Block Public Access setting** and tell the human if it must be disabled for the demo. If it must, make the human decide, and note in the runbook to re-enable it at teardown.
   - **EC2 SG:** in the default VPC create `cspm-demo-vuln-sg` with inbound TCP 22 from `0.0.0.0/0`. **No instance is ever attached.** (Security groups are free.)
   - **IAM:** user `cspm-demo-vuln-user`, attach `AdministratorAccess` directly, create a console login profile with a **random 24-character password that is never printed, logged or stored** (so nobody can ever sign in). No access keys. Tag the user.
2. `verify_lab.py`: independent read-only checks (plain boto3, not P2's scanner) that print a table: each of the 5 expected FAILs present yes/no.
3. `reset_lab.py`: returns the lab to the vulnerable state after remediation (for retakes). Must handle "already vulnerable" safely.
4. `teardown_lab.py`: deletes **only** resources tagged `Project=cspm-demo` and `Deliberate=true` (empty and delete the bucket, delete SG, detach policy and delete login profile and user). Shows a list and asks for confirmation. Never touches the reports/trail buckets (separate `--include-infra` flag, used only in Phase 6).
- **[HUMAN]** Review each script's dry-run output before approving real runs. Confirm in the console that the lab looks as expected (public bucket warning shown, SG rule visible, IAM user with admin).
- **Prowler baseline (after the lab exists):** run Prowler read-only, limited to services `s3 ec2 iam cloudtrail` and the region, with output saved to `lab/prowler_baseline/results/` (this folder is git-ignored; commit only a short summary `PROWLER_SUMMARY.md`). Map which Prowler checks correspond to S3-001, S3-002, EC2-001, IAM-001, IAM-002, CT-001.
- **Gate 2 check + Handoff note** (include the exact commands to create/verify/reset/teardown).

## Phase 3 — Integration
- **[AGENT]** Write `tests/e2e_demo.py` that orchestrates from a clean state: `reset_lab` → P2's `scan.py --label before --upload` → wait for P3's Lambda (poll for `remediation-logs/<scan_id>.json`) → `scan.py --label after --upload` → P2's `compare.py` → print scores, MTTR and which findings remain. Fail loudly with clear messages. It must be runnable by anyone on the team.
- **[AGENT]** Help diagnose cross-team problems (permissions, wrong bucket names, region mismatches). Keep a running "known issues" list in `docs/STATUS.md`.
- **[AGENT]** Compare Prowler's baseline with P2's `before` findings. Produce `docs/prowler_comparison.md`: table of check, Prowler result, CloudGuard result, match yes/no, notes on differences (this is the validation part of the report).
- **Gate 3 check:** E2E run succeeds **twice in a row** from clean state. Handoff note.

## Phase 4 — Hardening and rehearsal
- **[AGENT]** Write `docs/DEMO_RUNBOOK.md`: exact commands, what to show on screen, who speaks, timings (matching A9), what to do if a step fails, and the reset command for retakes. Include a pre-recording checklist (terminal font size, hide credentials/account ID if desired, close notifications, email inbox ready for the SNS alert).
- **[AGENT]** Verify teardown safety on a dry run; verify `reset_lab.py` works 3 times in a row.
- **[HUMAN]** Run a full dry-run recording as a group call, timing each segment. Target total ≤ 7:30.
- **[AGENT]** Review the AWS bill/cost explorer view with the human; confirm no unexpected services.
- **Gate 4 check + Handoff note.**

## Phase 5 — Report and slides
- **[AGENT]** Help draft your report sections (1, 2, 3, 4, 7b) in plain, student-level English with your human's edits. Content hints:
  - 1: why misconfiguration causes most cloud breaches; objective; scope.
  - 2: shared responsibility model, service models, how the project maps to the syllabus items in A1.
  - 3: the architecture diagram from A3 (ask the agent to create a clean diagram), data flow, why serverless and event-driven.
  - 4: the lab design table (resource, misconfiguration, risk, which check finds it), safety measures (dummy data, no access keys, discarded password, tag-based teardown).
  - 7b: Prowler comparison table and discussion (agreements, differences, why a custom scanner still makes sense for a controlled demo).
- **[HUMAN]** Make 4–5 slides for your sections. Review P2/P3 sections for consistency of terms and names.
- **Gate 5 check + Handoff note.**

## Phase 6 — Recording, submission, teardown
- **[HUMAN]** Record segment 0:00–2:30 per the runbook; edit all three segments into one video (≤ 8 min). Check audio levels and that every member is clearly heard.
- **[AGENT]** Write `docs/TEARDOWN_CHECKLIST.md` and walk the human through it **after the final submission is safe**:
  1. P3 and P2 confirm their own resources/keys are deleted.
  2. `teardown_lab.py` then `--include-infra` (empty buckets first, delete trail).
  3. **[HUMAN]** Delete teammates' IAM users and all access keys; re-enable any account-level Block Public Access that was disabled.
  4. **[HUMAN]** Check Billing → Bills the next day to confirm zero or near-zero charges; keep the $1 budget until then.
- **Final gate + Handoff note.**

## Definition of done for P1
Lab can be created, verified, reset and removed by one command each; E2E script passes twice; runbook rehearsed; report/slides sections delivered; AWS account clean.

## Dependencies on teammates
- From P2: `scan.py` CLI, `compare.py`, sample findings (Phase 1), real scan on the lab (Phase 2).
- From P3: working Lambda and the log format (Phase 2–3).
- You provide: reports bucket and permissions (Phase 1), lab (Phase 2), E2E harness and runbook (Phase 3–4).

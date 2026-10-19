# CloudGuard Mini-CSPM — File 2 of 3 — P2: SCANNER & DASHBOARD

**Paste this whole file into your AI agent first.** Then say: *"Follow Section A10. Start with your summary and Phase 0 plan."*

You are the AI assistant of **P2 (Scanner & Dashboard)**. Your human builds the security scanner (the checks and the score), the findings JSON that everyone depends on, the dashboard, and the before/after comparison. Teammates: P1 (Lab & Platform, owns AWS account and repo) and P3 (Alert & Remediation).

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
# PART B — P2 WORK PLAN

## B0. Your deliverables
1. `scanner/` package: `core.py` (finding builder, scoring, schema validation), `checks/` (6 checks), `scan.py` CLI, `compare.py`.
2. Sample files in `samples/`: `findings_before.json`, `findings_after.json`, `remediation_log.json` (P3 needs them early).
3. Unit tests that run offline (mocked AWS) plus an integration test on the real lab.
4. Streamlit dashboard: score, severity counts, findings table, before/after comparison, remediation log viewer.
5. Report sections 5, 7a, 9; slides for them; video segment 2:30–5:00; compile the final report document.

## Phase 0 — Kickoff and access
- **[AGENT]** Help set up: Python 3.11+, a virtual environment, and `scanner/requirements.txt` (`boto3`, `jsonschema`, `streamlit`, `pandas`, `plotly`, `pytest`, `moto`). Verify imports work.
- **[HUMAN]** Wait for P1's invitation to the AWS account and GitHub repo. Sign in, set your password and **MFA**, create your own access key (IAM → your user → Security credentials), then run `aws configure --profile cspm-scanner` locally. Never paste the key into chat.
- **[AGENT]** Verify: `aws sts get-caller-identity --profile cspm-scanner` returns the shared account ID. Clone the repo, create branch `p2/scanner`.
- **Gate 0 check + Handoff note.**

## Phase 1 — Foundations (finish this early: P3 depends on it)
- **[AGENT]** Implement `scanner/core.py`:
  - `make_finding(...)` that fills the exact fields from A5.
  - `compute_summary(findings)` implementing the scoring formula and severity counts exactly as in A5.
  - `validate(scan_dict)` using `shared/findings.schema.json` (from P1).
  - `new_scan_id(label)` → `YYYYMMDDTHHMMSSZ-<label>`.
- **[AGENT]** Write pytest unit tests for scoring with hand-calculated cases (all pass → 100; the 5-FAIL lab case; mixed severities). Show the human the arithmetic so they can explain it on camera.
- **[AGENT]** Create **realistic sample files** in `samples/`: `findings_before.json` (5 FAIL + a few PASS), `findings_after.json` (only IAM-002 FAIL), `remediation_log.json` matching A5. Validate them against the schema.
- **[HUMAN]** Open a PR with the samples; tell P3 and P1 immediately (their work depends on these).
- **Gate 1 check + Handoff note.**

## Phase 2 — Core build: the checks
Create `scanner/checks/<service>.py`, each exposing `run(session, region) -> list[Finding]`. Use a botocore `Config(retries={"max_attempts": 8, "mode": "standard"})`. Handle expected API errors (no policy, no BPA config, access denied) without crashing: record the problem as a warning in the scan output and continue.

| Check | Logic hints |
|---|---|
| S3-001 | For each bucket: read bucket-level Block Public Access (error "NoSuchPublicAccessBlockConfiguration" means not configured); read `get_bucket_policy_status().IsPublic`; read ACL grants to `AllUsers`/`AuthenticatedUsers`. FAIL if public via policy/ACL **and** BPA not fully on. Include the reason in `description`. |
| S3-002 | `get_bucket_versioning().Status` not `Enabled` → FAIL. |
| EC2-001 | `describe_security_groups` in the configured region; any ingress rule with `0.0.0.0/0` or `::/0` where the port range covers 22 or 3389, or protocol `-1`. One finding per security group (FAIL/PASS). Ignore nothing silently; the default SG gets checked too. |
| IAM-001 | For each user: `list_attached_user_policies` contains `AdministratorAccess`. (Optional: also report admin via groups as a separate warning, not a FAIL, to keep scope small.) |
| IAM-002 | For each user: has a login profile (`get_login_profile`; "NoSuchEntity" = no console access) and `list_mfa_devices` is empty → FAIL. Users without console access → PASS. |
| CT-001 | `describe_trails` + `get_trail_status`: at least one multi-region trail with `IsLogging=True` → PASS. |

Remediation fields (`remediation_hint`, `auto_remediable`, `remediation_action`) must follow the table in A5 exactly, because P3's code switches on those action codes.

- **[AGENT]** Write `scan.py` CLI: `--profile`, `--region` (default from `shared/config.env`), `--label before|after|adhoc`, `--out results/<scan_id>.json` (this folder is git-ignored), `--upload` (puts to `s3://cspm-demo-reports-<ACCOUNT_ID>/scans/<scan_id>.json`), `--no-validate` for debugging only. Exit code 0 on success; print a colour-coded console summary (score, counts, top findings).
- **[AGENT]** Offline tests with `moto` for each check (one compliant and one non-compliant resource each).
- **[HUMAN]** After P1 finishes the lab (Gate 2), run the scan on the real lab. Confirm exactly the 5 expected FAILs.
- **[AGENT]** If results differ, debug with read-only calls and explain why.
- **Gate 2 check + Handoff note.**

## Phase 3 — Integration: dashboard and comparison
- **[AGENT]** `scanner/compare.py before.json after.json`: prints score delta, list of fixed findings, list of remaining findings, and optionally MTTR if a remediation log is supplied. Output both console text and `results/comparison.json` (used by the dashboard).
- **[AGENT]** `scanner/dashboard/app.py` (Streamlit). Data source selectable: local `results/` folder or S3 reports bucket (using the `cspm-scanner` profile). Views:
  1. Latest scan: score gauge, severity counts, findings table with filters (severity, service, status).
  2. Before vs After: two score gauges, delta, "fixed" and "still open" lists.
  3. Remediation log viewer: action, result, before_state (from `remediation-logs/`).
  4. KPI strip: posture score, critical open count, MTTR.
  Keep the design simple and readable at 1080p for the screencast: large fonts, good contrast, no scrolling needed for the main story.
- **[AGENT]** Optional: `scanner/export_html.py` to make a static HTML report for the report's appendix.
- **[HUMAN]** Run the dashboard and test it with the real before/after scans produced during the E2E run.
- **Gate 3 check + Handoff note.**

## Phase 4 — Hardening
- **[AGENT]** Verify least privilege: the scanner must work with only `SecurityAudit` + `ViewOnlyAccess` + put-to-`scans/`. If a call needs more, find the narrowest fix and tell P1.
- **[AGENT]** Accuracy review: compare against P1's Prowler comparison. List false positives/negatives and fix or document them.
- **[AGENT]** Edge cases: empty account, many buckets, a bucket in another region, a user with no policies, throttling. Add tests. Make console error messages friendly.
- **[HUMAN]** Practise the live segment: run scan, explain two findings, open dashboard. Keep it ≤ 2:30.
- **Gate 4 check + Handoff note.**

## Phase 5 — Report and slides
- **[AGENT]** Help draft your report sections:
  - 5: design of the scanner (modules, flow chart), check catalogue table (from A5 with logic explained), scoring formula with a worked example, dashboard screenshots.
  - 7a: before/after results: tables and screenshots, the score improvement, the KPI table (score, number of CRITICAL, MTTR), comparison to the SLO "score ≥ 90%".
  - 9: limitations (single region, a small number of checks, no continuous monitoring, point-in-time scan, false positives risk) and future work (scheduled scans via EventBridge, more services, multi-account, compliance mapping such as CIS).
- **[HUMAN]** Make 4–5 slides. **Compile the final report** (one document, consistent headings, numbered figures, references, table of contents) from all three people's sections. Give P1/P3 a deadline for their sections two days earlier.
- **Gate 5 check + Handoff note.**

## Phase 6 — Recording and submission
- **[HUMAN]** Record segment 2:30–5:00 per `docs/DEMO_RUNBOOK.md`. Send raw recording to P1 for editing.
- **[HUMAN]** Submit per course instructions (agree with teammates who uploads what). Then delete your access key and AWS profile locally (`aws configure` file) after P1's teardown checklist.
- **Final gate + Handoff note.**

## Definition of done for P2
Six checks correct on the lab and tested offline; scores reproducible by hand; dashboard tells the before/after story; final report compiled.

## Dependencies on teammates
- From P1: schema file, reports bucket, permissions (Phase 0–1), working lab (Phase 2).
- From P3: remediation log format and working Lambda (Phase 2–3) for dashboard and MTTR.
- You provide: samples and schema validation (Phase 1), scan CLI (Phase 2), compare + dashboard (Phase 3).

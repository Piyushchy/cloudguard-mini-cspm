# CloudGuard Mini-CSPM — Demo Video Runbook

This runbook contains the exact script, timings, screen displays, and commands for the 7–8 minute team demonstration video.

---

## Pre-Recording Checklist
- [ ] Terminal font size enlarged (minimum 18pt for crisp 1080p recording).
- [ ] Close all personal notifications, Slack/Discord, and browser tabs except AWS Console and Dashboard.
- [ ] Ensure terminal is in `d:\ACC\cloudguard-mini-cspm` with `.venv` active.
- [ ] Email client open and ready to show SNS alert delivery.
- [ ] Run `python lab/reset_lab.py` to ensure clean initial vulnerable state.

---

## Segment 1: P1 (Lab & Platform) — 0:00 to 2:30

**Speaker**: P1  
**Key Topic**: Problem statement, cloud architecture, and vulnerable lab setup.

### Script & Actions:
1. **0:00 – 0:45 (Slide 1 & Architecture)**:
   - *"Welcome to CloudGuard. In modern cloud environments, over 80% of data breaches stem from simple misconfigurations under the Shared Responsibility Model."*
   - Show architecture diagram: Scanner $\rightarrow$ S3 Reports Bucket $\rightarrow$ SNS & Remediator Lambda $\rightarrow$ Dashboard.
2. **0:45 – 1:45 (AWS Console Demo)**:
   - Open AWS Console in `ap-south-1` (Mumbai).
   - Show `cspm-demo-vuln-bucket`: Block Public Access is OFF, public policy on `hello.txt`.
   - Show `cspm-demo-vuln-sg`: Port 22 open to `0.0.0.0/0`.
   - Show `cspm-demo-vuln-user`: Direct `AdministratorAccess` and console password with NO MFA.
3. **1:45 – 2:30 (Terminal Verification)**:
   - Run:
     ```bash
     python lab/verify_lab.py
     ```
   - Show the 6/6 table confirming the 5 active vulnerabilities and 1 compliant CloudTrail.
   - Hand off: *"Now P2 will run our custom scanner to discover and score these misconfigurations."*

---

## Segment 2: P2 (Scanner & Dashboard) — 2:30 to 5:00

**Speaker**: P2  
**Key Topic**: Scanner execution, scoring algorithm, and Streamlit dashboard.

### Script & Actions:
1. **2:30 – 3:30 (Scanner CLI)**:
   - Run:
     ```bash
     python -m scanner.scan --profile cspm-scanner --label before --upload
     ```
   - Explain the scoring formula:
     $$\text{Score} = \text{round}\left(100 \times \frac{\sum \text{Weights of PASS}}{\sum \text{Weights of ALL}}\right)$$
   - Show the initial score: **~51–61%** (failing our SLO of $\ge 90\%$).
   - Point out the uploaded scan in S3 (`cspm-demo-reports-.../scans/`).
2. **3:30 – 5:00 (Interactive Dashboard)**:
   - Open Streamlit dashboard:
     ```bash
     streamlit run scanner/dashboard/app.py
     ```
   - Walk through:
     - Gauge score visual.
     - Severity breakdown: 1 CRITICAL, 5 HIGH, 2 LOW.
     - Filtering table by service and status.
   - Hand off: *"The scan report has triggered our event-driven alert and auto-remediation pipeline, which P3 will demonstrate."*

---

## Segment 3: P3 (Alert & Remediation) — 5:00 to 7:30

**Speaker**: P3  
**Key Topic**: Serverless SNS alerting, Lambda auto-remediation, rescan, and human-in-the-loop.

### Script & Actions:
1. **5:00 – 5:45 (SNS Alert & Remediation)**:
   - Show email inbox: Open SNS alert notification containing scan score and critical findings.
   - Show CloudWatch / Lambda logs for `cspm-demo-remediator`.
   - Explain safety rules: checks `cspm-remediate=true` tag, preserves `before_state`, reversible actions.
2. **5:45 – 6:45 (Rescan & Score Delta)**:
   - Run after scan:
     ```bash
     python -m scanner.scan --profile cspm-scanner --label after --upload
     ```
   - Run comparison:
     ```bash
     python -m scanner.compare results/<before>.json results/<after>.json --log results/<log>.json
     ```
   - Show score jump from ~61% to **89%**! Show MTTR (Mean Time to Remediate) in seconds.
3. **6:45 – 7:30 (Human-in-the-Loop Fix)**:
   - Highlight remaining FAIL: `IAM-002` (Console login without MFA cannot be safely automated).
   - Manually delete the demo user login profile in AWS Console or CLI:
     ```bash
     aws iam delete-login-profile --user-name cspm-demo-vuln-user
     ```
   - Rescan: Posture score hits **100%**!

---

## Segment 4: Team Closing — 7:30 to 8:00

- **P1**: *"CloudGuard proves that security posture management and guardrails can be lightweight, automated, and free-tier compliant."*
- **P2**: *"Deterministic scoring gives teams quantifiable KPIs and continuous visibility into configuration drift."*
- **P3**: *"Event-driven serverless architecture reduces MTTR from days to seconds while keeping safety non-negotiable."*

---

## Troubleshooting & Retakes

If anything goes wrong during rehearsal:
```bash
# 1. Reset lab back to initial state in 5 seconds
python lab/reset_lab.py

# 2. Verify state
python lab/verify_lab.py
```

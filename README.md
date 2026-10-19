# CloudGuard Mini-CSPM

[![AWS Free-Tier](https://img.shields.io/badge/AWS-Free--Tier%20Compliant-orange?logo=amazon-aws)](https://aws.amazon.com/free/)
[![Python 3.13](https://img.shields.io/badge/Python-3.13-blue?logo=python)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?logo=streamlit)](https://cloudguard-mini-cspm-v5mqmdzncdp9ftwux6gdci.streamlit.app/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An end-to-end, lightweight **Cloud Security Posture Management (CSPM)** platform built natively on AWS and Python. 

CloudGuard Mini-CSPM demonstrates the complete lifecycle of cloud security under the AWS Shared Responsibility Model: **discovering** security misconfigurations, **scoring** organizational risk posture, **alerting** stakeholders in real time, and safely **auto-remediating** vulnerabilities with automated guardrails and audit trails.

---

## 📑 Table of Contents

- [Overview & Architecture](#-overview--architecture)
- [Key Features](#-key-features)
- [Security Check Catalogue & Scoring](#-security-check-catalogue--scoring)
- [Project Components](#-project-components)
  - [P1: Foundation & Vulnerable Lab](#p1-foundation--vulnerable-lab-platform)
  - [P2: Scanner & Streamlit Dashboard](#p2-scanner--interactive-dashboard)
  - [P3: Serverless Alerting & Automated Remediation](#p3-event-driven-alerting--automated-remediation)
- [Repository Structure](#-repository-structure)
- [Quick Start Guide](#-quick-start-guide)
  - [1. Offline Demo (No AWS Required)](#1-offline-demo-no-aws-required)
  - [2. Live AWS Pipeline Execution](#2-live-aws-pipeline-execution)
- [Demo Progression (51% $\rightarrow$ 89% $\rightarrow$ 100%)](#-demo-progression)
- [Safety & Guardrails](#-safety-guardrails)
- [Documentation & Runbooks](#-documentation--runbooks)

---

## 🏗 Overview & Architecture

Modern cloud breaches overwhelmingly originate from simple resource misconfigurations. CloudGuard Mini-CSPM creates a closed-loop security automation pipeline:

```
                     ┌────────────────────────────────────────┐
                     │          Vulnerable AWS Lab            │
                     │  (S3 BPA Off, Open SG, Admin IAM...)   │
                     └──────────────────┬─────────────────────┘
                                        │
                                  1. Scan Lab
                                        ▼
                     ┌────────────────────────────────────────┐
                     │         Custom CSPM Scanner            │
                     │  (Multi-service Python 3.13 CLI)       │
                     └──────────────────┬─────────────────────┘
                                        │
                          2. Upload JSON Finding Report
                                        ▼
                     ┌────────────────────────────────────────┐
                     │       S3 Central Reports Bucket        │
                     │   (s3://.../scans/<scan_id>.json)      │
                     └──────────────────┬─────────────────────┘
                                        │
                            3. S3 Event ObjectCreated
                                        ▼
                     ┌────────────────────────────────────────┐
                     │     AWS Lambda Remediator Engine       │
                     │    (Python 3.13, Guardrail Checks)     │
                     └─────────┬────────────────────┬─────────┘
                               │                    │
              4. Publish Alert │                    │ 5. Safe Auto-Fix & Audit
                               ▼                    ▼
        ┌────────────────────────────┐    ┌────────────────────────────┐
        │       Amazon SNS           │    │    S3 Remediation Logs     │
        │  (cspm-demo-alerts Email)  │    │ (before/after state diff)  │
        └────────────────────────────┘    └─────────────┬──────────────┘
                                                        │
                                    6. Rescan & Compare │
                                                        ▼
                                          ┌────────────────────────────┐
                                          │    Streamlit Dashboard     │
                                          │  (Score, MTTR, Findings)   │
                                          └────────────────────────────┘
```

---

## ✨ Key Features

- **Multi-Service Scanner**: Fast, agentless discovery across Amazon S3, EC2, IAM, and CloudTrail.
- **Quantitative Risk Scoring**: Normalized 0–100 weighted posture scoring algorithm prioritizing CRITICAL and HIGH severity findings.
- **Event-Driven Serverless Pipeline**: Zero-polling AWS Lambda triggered immediately when scanner uploads results to S3.
- **Enterprise Safety Guardrails**:
  - Requires explicit opt-in tag (`cspm-remediate=true`).
  - Immutable protected list preventing modifications to root/admin accounts and platform infra.
  - Complete `before_state` logging for full auditability and one-command rollback.
- **Interactive Visual Dashboard**: Real-time Streamlit dashboard featuring risk gauges, severity breakdowns, finding search, and before/after comparison with MTTR (Mean Time to Remediate) tracking.
- **Benchmark Aligned**: Validated against industry-standard benchmarks (Prowler v5).

---

## 🎯 Security Check Catalogue & Scoring

| Check ID | Target Resource | Misconfiguration Description | Severity | Weight | Auto-Remediable? | Remediation Action |
|:---|:---|:---|:---:|:---:|:---:|:---|
| **S3-001** | S3 Bucket | Publicly accessible bucket (BPA off & public policy/ACL) | **CRITICAL** | 10 | Yes | `S3_ENABLE_BPA` |
| **S3-002** | S3 Bucket | Object versioning disabled | **LOW** | 1 | Yes | `S3_ENABLE_VERSIONING` |
| **EC2-001** | EC2 Security Group | Ingress rule open to `0.0.0.0/0` on port 22, 3389, or all | **HIGH** | 7 | Yes | `EC2_REVOKE_OPEN_INGRESS` |
| **IAM-001** | IAM User | Direct `AdministratorAccess` policy attached | **HIGH** | 7 | Yes | `IAM_DETACH_ADMIN_POLICY` |
| **IAM-002** | IAM User | Console password enabled without MFA configured | **HIGH** | 7 | No *(Human Fix)* | *Manual / Supervised* |
| **CT-001** | AWS Account | CloudTrail missing active multi-region logging | **MEDIUM** | 4 | No | *Platform Baseline* |

### Risk Scoring Formula
$$\text{Security Posture Score} = \text{round}\left(100 \times \frac{\sum \text{Weights of PASS}}{\sum \text{Weights of ALL}}\right)$$

---

## 🧩 Project Components

### P1: Foundation & Vulnerable Lab (`lab/`)
- **Infrastructure Bootstrap**: Creates central reports bucket, audit logs bucket, and encrypted multi-region CloudTrail (`lab/bootstrap_infra.py`).
- **Vulnerable Lab Provisioning**: Provisions realistic, isolated test resources tagged with `cspm-remediate=true` (`lab/create_lab.py`).
- **Audit & Validation**: Automated verification script validating 6/6 lab conditions before testing (`lab/verify_lab.py`).
- **Teammate IAM Profiles**: Least-privilege IAM policies and credential generation for scanner and remediator roles (`lab/setup_teammate_iam.py`).
- **Prowler Baseline**: Prowler v5 benchmark summary and cross-reference documentation (`lab/prowler_baseline/`).
- **Teardown & Reset**: Complete one-step reset for repeatable demonstrations (`lab/reset_lab.py`, `lab/teardown_lab.py`).

### P2: Scanner & Interactive Dashboard (`scanner/`)
- **Core Checks Engine**: Independent check modules for S3, EC2, IAM, and CloudTrail with error isolation (`scanner/checks/`).
- **CLI Runner**: Python CLI tool with support for AWS profiles, custom labels, local caching, and automated S3 report upload (`scanner/scan.py`).
- **Comparison Engine**: Calculates posture delta, fixed vs. new vs. persistent findings, and MTTR (`scanner/compare.py`).
- **Streamlit Web Application**: Rich visual dashboard displaying posture gauges, timeline trends, and severity distributions (`scanner/dashboard/app.py`). Hosted online on [Streamlit Community Cloud](https://cloudguard-mini-cspm-v5mqmdzncdp9ftwux6gdci.streamlit.app/).
- **Mock Lab Engine**: Local `moto`-backed simulation allowing end-to-end testing without AWS credentials (`scanner/demo_lab.py`, `scanner/demo_local.py`).

### P3: Event-Driven Alerting & Automated Remediation (`remediation/`)
- **Serverless Remediator**: AWS Lambda function running Python 3.13 (`remediation/handler.py`).
- **Real-Time Alerting**: Dispatches security posture summary alerts to Amazon SNS topic (`cspm-demo-alerts`) delivering instant email notifications.
- **Remediation Actions**: Dedicated handler modules for BPA enablement, versioning, ingress revocation, and policy detachment (`remediation/actions/`).
- **Rollback Tooling**: Standalone rollback CLI allowing instant reversal of any automated change via captured S3 audit logs (`remediation/rollback.py`).
- **Deployment & Teardown**: Automated deployment script configuring Lambda, IAM execution role, and S3 bucket notification triggers (`remediation/deploy.py`, `remediation/teardown.py`).

---

## 📁 Repository Structure

```text
cloudguard-mini-cspm/
├── .github/                       # CI workflows & issue templates
├── Instructions/                  # Original phase project requirements
├── docs/                          # Runbooks, logs, and documentation
│   ├── DEMO_RUNBOOK.md            # Exact video presentation & demo script
│   ├── STATUS.md                  # Project status and phase handoff logs
│   ├── TEARDOWN_CHECKLIST.md      # AWS resource teardown verification checklist
│   └── logs/                      # Execution logs for P1, P2, and P3
├── lab/                           # P1: Platform & vulnerable lab automation
│   ├── bootstrap_infra.py         # Bucket & CloudTrail creation
│   ├── create_lab.py              # Vulnerable resource deployment
│   ├── verify_lab.py              # Pre-flight audit verification
│   ├── reset_lab.py               # Lab reset script
│   ├── teardown_lab.py            # Clean lab teardown
│   ├── setup_teammate_iam.py      # IAM roles for scanner & remediator
│   └── prowler_baseline/          # Prowler v5 benchmark comparisons
├── remediation/                   # P3: Alerting & automated remediation
│   ├── actions/                   # Specific remediation action handlers
│   ├── iam/                       # Least-privilege IAM policies for Lambda
│   ├── tests/                     # Unit and integration tests for Lambda
│   ├── handler.py                 # Core AWS Lambda handler entrypoint
│   ├── dispatcher.py              # Multi-mode action dispatcher
│   ├── safety.py                  # Tag checks and protective guardrails
│   ├── deploy.py / deploy.sh      # Automated Lambda deployment
│   ├── rollback.py                # Remediation rollback CLI
│   └── teardown.py / teardown.sh  # Lambda and SNS cleanup
├── samples/                       # Example scan results and remediation logs
├── scanner/                       # P2: Security scanner & dashboard
│   ├── checks/                    # S3, EC2, IAM, CloudTrail checks
│   ├── dashboard/                 # Streamlit web dashboard
│   ├── core.py                    # Schema validation, findings builder, scoring
│   ├── scan.py                    # Scanner CLI tool
│   ├── compare.py                 # Posture diff and MTTR calculator
│   └── demo_local.py              # Offline demo runner
├── shared/                        # Shared project contracts and config
│   ├── CONTRACT.md                # Naming conventions, tags, and check contracts
│   ├── config.env                 # Environment variables and resource IDs
│   └── findings.schema.json       # JSON Schema contract for scan findings
├── tests/                         # Integration tests
│   └── e2e_demo.py                # Full end-to-end automated pipeline test
├── requirements.txt               # Production & Streamlit dependencies
├── run_demo.bat / run_demo.sh     # One-click offline demo launchers
└── README.md                      # Project documentation (this file)
```

---

## 🚀 Quick Start Guide

### 1. Offline Demo (No AWS Required)

You can run the full scanner, simulation, and dashboard locally without an AWS account:

```bash
# Windows
run_demo.bat

# Linux / macOS
./run_demo.sh
```

Or step by step:

```bash
# 1. Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r scanner/requirements.txt

# 3. Run unit tests
pytest

# 4. Run local simulation (Fake Lab -> Scan -> Auto-Fix -> Rescan -> Compare)
python -m scanner.demo_local

# 5. Launch the Streamlit dashboard
streamlit run scanner/dashboard/app.py
```

---

### 2. Live AWS Pipeline Execution

Ensure your AWS CLI profile is configured (`aws configure --profile <your-profile>`).

#### Step A: Provision Platform & Vulnerable Lab (P1)
```bash
python lab/bootstrap_infra.py
python lab/create_lab.py
python lab/verify_lab.py
```

#### Step B: Deploy Remediation Lambda & SNS Alerts (P3)
```bash
python remediation/deploy.py
```

#### Step C: Run Initial Scan (P2)
```bash
python -m scanner.scan --profile cspm-scanner --label before --upload
```
*Note: Uploading the scan to S3 triggers the Lambda remediator automatically.*

#### Step D: Rescan After Auto-Remediation & Compare
```bash
python -m scanner.scan --profile cspm-scanner --label after --upload
python -m scanner.compare results/<before_scan>.json results/<after_scan>.json --log results/<log>.json
```

#### Step E: Launch Dashboard
```bash
streamlit run scanner/dashboard/app.py
```

#### Step F: Clean Up All Resources
```bash
python remediation/teardown.py
python lab/teardown_lab.py
```

---

## 📈 Demo Progression

The CloudGuard pipeline demonstrates clear, quantifiable security improvement:

```text
  Initial Vulnerable Lab State
  ┌────────────────────────────────────────────────────────┐
  │ Score: 51% (Failing SLO >= 90%)                        │
  │ Failures: S3-001, S3-002, EC2-001, IAM-001, IAM-002     │
  └───────────────────────────┬────────────────────────────┘
                              │
                    Automated Remediation (Lambda)
                              ▼
  Post Auto-Remediation State
  ┌────────────────────────────────────────────────────────┐
  │ Score: 89% (MTTR: ~12 seconds)                         │
  │ Resolved: S3-001, S3-002, EC2-001, IAM-001             │
  │ Remaining: IAM-002 (Console login without MFA)         │
  └───────────────────────────┬────────────────────────────┘
                              │
                   Human-in-the-Loop Manual Fix
                              ▼
  Final Secured State
  ┌────────────────────────────────────────────────────────┐
  │ Score: 100% (Clean Posture)                            │
  │ Zero active critical or high misconfigurations         │
  └────────────────────────────────────────────────────────┘
```

---

## 🛡 Safety & Guardrails

Automated remediation in production environments can cause unintended downtime if not rigorously controlled. CloudGuard Mini-CSPM adheres to 4 core safety principles:

1. **Explicit Opt-in**: The remediator will *only* touch resources tagged with `cspm-remediate=true`.
2. **Immutable Protection List**: Hardcoded protection preventing remediation from ever altering administrative roles, root accounts, production VPCs, or platform audit buckets.
3. **Audit Trail Capture**: Full `before_state` JSON captured and stored in S3 prior to executing any destructive or modifying API call.
4. **Reversible Operations**: Dedicated CLI tool (`python remediation/rollback.py <log_id>`) can immediately restore previous configurations.

---

## 📖 Documentation & Runbooks

- [Demo Runbook](docs/DEMO_RUNBOOK.md): Script, screen transitions, and command sequence for presentations.
- [Shared Contract](shared/CONTRACT.md): Project conventions, tagging standards, and finding schemas.
- [Status Tracker](docs/STATUS.md): Milestones, handoff logs, and gate completion records.
- [Teardown Checklist](docs/TEARDOWN_CHECKLIST.md): Verification steps to guarantee 100% clean AWS resource deletion.

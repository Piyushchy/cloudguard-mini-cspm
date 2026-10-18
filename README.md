# CloudGuard Mini-CSPM - P2 (Scanner & Dashboard)

A security scanner for AWS that finds misconfigurations, scores them, and shows the
before/after story on a dashboard. This folder is everything P2 owns.

## Run it right now (no AWS account needed)

**Windows:** double-click `run_demo.bat`   **Mac/Linux:** `./run_demo.sh`

It creates a virtual environment, installs the packages, runs the tests, builds a
*fake* AWS lab (using `moto`), scans it, simulates the fixes, scans again, and opens
the dashboard at http://localhost:8501.

Or step by step:
```
python -m venv .venv
.venv\Scripts\activate            (Mac/Linux: source .venv/bin/activate)
pip install -r scanner/requirements.txt
python -m pytest                              # 62 tests, ~30 s
python -m scanner.demo_local                  # fake lab -> scan -> fix -> scan -> compare
streamlit run scanner/dashboard/app.py        # dashboard (reads results/ or samples/)
```

## Against the real AWS lab (once P1 has given you access)
```
aws configure --profile cspm-scanner          # keys go here, never in chat
python -m scanner.scan --profile cspm-scanner --label before --upload
python -m scanner.scan --profile cspm-scanner --label after  --upload
python -m scanner.compare results/<before>.json results/<after>.json --log <log>.json
```
Scans are saved to `results/` (git-ignored). `--upload` puts them in
`s3://cspm-demo-reports-<ACCOUNT_ID>/scans/`.

## What is where
| Path | What it is |
|---|---|
| `scanner/core.py` | finding builder, scoring formula, scan IDs, schema validation |
| `scanner/checks/` | the 6 checks: `s3.py` (S3-001/002), `ec2.py` (EC2-001), `iam.py` (IAM-001/002), `cloudtrail.py` (CT-001) |
| `scanner/scan.py` | the scanner command line tool |
| `scanner/compare.py` | before/after comparison and MTTR |
| `scanner/dashboard/app.py` | Streamlit dashboard |
| `scanner/demo_lab.py`, `demo_local.py` | FAKE lab + simulated fixes for offline demos (the real ones are P1's lab and P3's Lambda) |
| `samples/` | example scan and remediation-log files for P1 and P3 |
| `shared/` | `findings.schema.json` and `config.env` - **drafts**; P1 owns the real ones |

## Scoring
`score = round(100 x sum(weights of PASS) / sum(weights of all))`, with CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1.
Lab before: 33/65 -> 51. After auto-fix: 58/65 -> 89. After the human fixes IAM-002: 100.

## Decisions to confirm with P1 and P3
1. Halves round **up** (Python's `round(12.5)` gives 12, which is confusing by hand).
2. Security-group `resource_id` is the group id (`sg-...`), because P3 needs it to revoke rules.
3. CT-001 has one finding per account (`resource_id` = account id) so its id is the same before and after.
4. PASS findings carry the same `auto_remediable`/`remediation_action` as FAIL ones, so P3 must act only on `status == "FAIL"`.
5. Scanner warnings (e.g. AccessDenied) are shown on the console only; the contract has no field for them.

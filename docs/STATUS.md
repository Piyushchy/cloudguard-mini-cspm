# CloudGuard Mini-CSPM — Project Status Tracker

## Phase Status Summary

| Phase | Description | Owner | Status | Gate Criteria |
|---|---|---|---|---|
| **Phase 0** | Kickoff & Access Setup | All / P1 | **COMPLETED (Gate 0 Passed)** | All humans verified via `aws sts get-caller-identity`, repo cloned, Part A agreed. |
| **Phase 1** | Foundations (Reports bucket, CloudTrail, IAM) | Parallel / P1 | **COMPLETED (Gate 1 Passed)** | Reports bucket, trail, scanner profile exist; sample findings committed. |
| **Phase 2** | Core Build (Vulnerable lab & remediation Lambda) | Parallel / P1 | **IN PROGRESS (Lab verified)** | Lab created & verified; scanner reports 5 FAILs; remediation verified. |
| **Phase 3** | Integration (E2E pipeline test) | All | PENDING | Clean run twice in a row: scan $\rightarrow$ alert $\rightarrow$ fix $\rightarrow$ rescan. |
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

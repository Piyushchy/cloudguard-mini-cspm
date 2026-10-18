"""Before/after comparison.

CLI:  python -m scanner.compare samples/findings_before.json samples/findings_after.json \
          --log samples/remediation_log.json --out results/comparison.json
The dashboard imports compare() directly.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

SLO_SCORE = 90  # service-level objective: posture score >= 90%


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def mttr_seconds(scan: dict, log: dict | None) -> float | None:
    """MTTR = remediation log 'finished' minus scan 'timestamp' (contract A5)."""
    if not log:
        return None
    return (_ts(log["finished"]) - _ts(scan["timestamp"])).total_seconds()


def compare(before: dict, after: dict, log: dict | None = None) -> dict:
    b = {f["id"]: f for f in before["findings"]}
    a = {f["id"]: f for f in after["findings"]}

    fixed = [b[i] for i in b
             if b[i]["status"] == "FAIL" and a.get(i, {}).get("status") == "PASS"]
    still_open = [a[i] for i in a if a[i]["status"] == "FAIL" and
                  (i in b and b[i]["status"] == "FAIL")]
    new_issues = [a[i] for i in a if a[i]["status"] == "FAIL" and
                  not (i in b and b[i]["status"] == "FAIL")]

    sb, sa = before["summary"]["score"], after["summary"]["score"]
    return {
        "before_scan_id": before["scan_id"],
        "after_scan_id": after["scan_id"],
        "score_before": sb,
        "score_after": sa,
        "score_delta": sa - sb,
        "meets_slo": sa >= SLO_SCORE,
        "slo": SLO_SCORE,
        "critical_before": before["summary"]["by_severity"]["CRITICAL"],
        "critical_after": after["summary"]["by_severity"]["CRITICAL"],
        "failed_before": before["summary"]["failed"],
        "failed_after": after["summary"]["failed"],
        "mttr_seconds": mttr_seconds(before, log),
        "fixed": fixed,
        "still_open": still_open,
        "new_issues": new_issues,
    }


def render_text(c: dict) -> str:
    lines = [
        f"Score: {c['score_before']} -> {c['score_after']}  ({c['score_delta']:+d})   "
        f"SLO >= {c['slo']}: {'MET' if c['meets_slo'] else 'NOT MET'}",
        f"Failed findings: {c['failed_before']} -> {c['failed_after']}   "
        f"CRITICAL: {c['critical_before']} -> {c['critical_after']}",
    ]
    if c["mttr_seconds"] is not None:
        lines.append(f"MTTR: {c['mttr_seconds']:.0f} s")
    for title, key in (("Fixed", "fixed"), ("Still open", "still_open"), ("NEW issues", "new_issues")):
        lines.append(f"\n{title} ({len(c[key])}):")
        lines += [f"  - [{f['severity']}] {f['id']}" for f in c[key]] or ["  (none)"]
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Compare two CloudGuard scans")
    p.add_argument("before")
    p.add_argument("after")
    p.add_argument("--log", help="remediation log JSON (enables MTTR)")
    p.add_argument("--out", default="results/comparison.json")
    args = p.parse_args(argv)

    load = lambda path: json.loads(Path(path).read_text("utf-8"))
    result = compare(load(args.before), load(args.after), load(args.log) if args.log else None)
    print(render_text(result))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", "utf-8")
    print(f"\nWrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

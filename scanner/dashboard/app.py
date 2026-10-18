"""CloudGuard dashboard (Streamlit).

Run from the repo root:   streamlit run scanner/dashboard/app.py
Reads scan JSON files from a local folder (default: results/ if it has scans,
otherwise samples/). S3 as a data source comes later, once P1's bucket exists.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from scanner.compare import SLO_SCORE, compare

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COLOR = {"CRITICAL": "#d62728", "HIGH": "#ff7f0e", "MEDIUM": "#e0b000", "LOW": "#1f77b4"}

st.set_page_config(page_title="CloudGuard CSPM", page_icon="🛡️", layout="wide")
st.markdown(
    """
    <style>
      html, body, [class*="css"] { font-size: 19px; }
      [data-testid="stMetricValue"] { font-size: 2.6rem; }
      [data-testid="stMetricLabel"] p { font-size: 1.1rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ------------------------------------------------------------------ data
def _read(path: Path):
    try:
        return json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


@st.cache_data(show_spinner=False)
def load_folder(folder: str, _stamp: float):
    """Return (scans, logs) found in folder (searched recursively)."""
    scans, logs = {}, {}
    for p in sorted(Path(folder).rglob("*.json")):
        d = _read(p)
        if not isinstance(d, dict):
            continue
        if "findings" in d and "summary" in d and "scan_id" in d:
            scans[d["scan_id"]] = d
        elif "actions" in d and "scan_id" in d:
            logs[d["scan_id"]] = d
    return scans, logs


def default_folder() -> str:
    results = ROOT / "results"
    if results.is_dir() and any(results.rglob("*.json")):
        return str(results)
    return str(ROOT / "samples")


def folder_stamp(folder: str) -> float:
    p = Path(folder)
    return max((f.stat().st_mtime for f in p.rglob("*.json")), default=0.0) if p.is_dir() else 0.0


# --------------------------------------------------------------- widgets
def gauge(score: int, title: str) -> go.Figure:
    color = "#2ca02c" if score >= SLO_SCORE else "#ff7f0e" if score >= 50 else "#d62728"
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={"text": title, "font": {"size": 26}},
        number={"font": {"size": 64}, "suffix": "%"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": color},
            "threshold": {"line": {"color": "black", "width": 5}, "value": SLO_SCORE},
        },
    ))
    fig.update_layout(height=320, margin=dict(l=30, r=30, t=70, b=10))
    return fig


def findings_df(scan: dict) -> pd.DataFrame:
    rows = [{
        "Status": f["status"], "Severity": f["severity"], "Check": f["check_id"],
        "Service": f["service"], "Resource": f["resource_id"], "Description": f["description"],
        "Auto-fix": "Yes" if f["auto_remediable"] else "No", "Hint": f["remediation_hint"],
    } for f in scan["findings"]]
    df = pd.DataFrame(rows)
    if not df.empty:
        df["_s"] = df["Severity"].map({s: i for i, s in enumerate(SEV_ORDER)})
        df["_f"] = (df["Status"] != "FAIL").astype(int)
        df = df.sort_values(["_f", "_s", "Check"]).drop(columns=["_s", "_f"])
    return df


def color_status(row):
    if row["Status"] == "FAIL":
        return ["background-color: rgba(214,39,40,0.18)"] * len(row)
    return [""] * len(row)


def label_of(sid: str, scans: dict) -> str:
    s = scans[sid]
    return f"{s['label']} - {s['timestamp']} (score {s['summary']['score']})"


# ------------------------------------------------------------------ page
st.title("🛡️ CloudGuard - Cloud Security Posture")

with st.sidebar:
    st.header("Data source")
    folder = st.text_input("Local folder with scan JSON files", value=default_folder())
    if st.button("Reload"):
        st.cache_data.clear()
    st.caption(f"Posture SLO: score ≥ {SLO_SCORE}%")

if not Path(folder).is_dir():
    st.error(f"Folder not found: {folder}")
    st.stop()

scans, logs = load_folder(folder, folder_stamp(folder))
if not scans:
    st.warning(f"No scan files found in {folder}. Run a scan first, or point to the samples/ folder.")
    st.stop()

ids = sorted(scans, reverse=True)                       # newest first (ids start with a timestamp)
latest_id = ids[0]


def newest(label: str):
    return next((i for i in ids if scans[i]["label"] == label), None)


before_id = newest("before")
after_id = next((i for i in ids if scans[i]["label"] == "after"
                 and (before_id is None or i > before_id)), newest("after"))

# KPI strip - uses the before/after pair when we have one, otherwise the latest scan
cmp = None
if before_id and after_id:
    log = logs.get(before_id)
    cmp = compare(scans[before_id], scans[after_id], log)

headline = scans[after_id] if after_id else scans[latest_id]
k1, k2, k3, k4 = st.columns(4)
k1.metric("Posture score", f"{headline['summary']['score']}%",
          delta=f"{cmp['score_delta']:+d} vs before" if cmp else None)
k2.metric("Critical open", headline["summary"]["by_severity"]["CRITICAL"])
k3.metric("Failed checks", f"{headline['summary']['failed']} / {headline['summary']['total']}")
k4.metric("MTTR", f"{cmp['mttr_seconds']:.0f} s" if cmp and cmp["mttr_seconds"] is not None else "n/a")
st.divider()

tab1, tab2, tab3 = st.tabs(["Latest scan", "Before vs After", "Remediation log"])

# ---- Tab 1: one scan
with tab1:
    sid = st.selectbox("Scan", ids, format_func=lambda i: label_of(i, scans), key="scan_pick")
    s = scans[sid]
    left, right = st.columns([1, 1])
    with left:
        st.plotly_chart(gauge(s["summary"]["score"], "Posture score"), use_container_width=True)
    with right:
        sev = s["summary"]["by_severity"]
        fig = go.Figure(go.Bar(
            x=SEV_ORDER, y=[sev[k] for k in SEV_ORDER],
            marker_color=[SEV_COLOR[k] for k in SEV_ORDER], text=[sev[k] for k in SEV_ORDER],
            textposition="outside"))
        fig.update_layout(title="Failed findings by severity", height=320,
                          margin=dict(l=20, r=20, t=60, b=10), yaxis=dict(dtick=1, rangemode="tozero"))
        st.plotly_chart(fig, use_container_width=True)

    df = findings_df(s)
    c1, c2, c3 = st.columns(3)
    f_status = c1.multiselect("Status", ["FAIL", "PASS"], default=["FAIL"])
    f_sev = c2.multiselect("Severity", SEV_ORDER, default=SEV_ORDER)
    f_svc = c3.multiselect("Service", sorted(df["Service"].unique()), default=sorted(df["Service"].unique()))
    view = df[df["Status"].isin(f_status) & df["Severity"].isin(f_sev) & df["Service"].isin(f_svc)]
    st.dataframe(view.style.apply(color_status, axis=1), use_container_width=True, hide_index=True)
    st.caption(f"Showing {len(view)} of {len(df)} findings - account {s['account_id']} - {s['region']}")

# ---- Tab 2: before/after
with tab2:
    if len(scans) < 2:
        st.info("Need at least two scans (a 'before' and an 'after') for this view.")
    else:
        p1, p2 = st.columns(2)
        b_id = p1.selectbox("Before scan", ids, index=ids.index(before_id) if before_id else len(ids) - 1,
                            format_func=lambda i: label_of(i, scans), key="b_pick")
        a_id = p2.selectbox("After scan", ids, index=ids.index(after_id) if after_id else 0,
                            format_func=lambda i: label_of(i, scans), key="a_pick")
        c = compare(scans[b_id], scans[a_id], logs.get(b_id))

        g1, g2, g3 = st.columns([2, 1, 2])
        g1.plotly_chart(gauge(c["score_before"], "Before"), use_container_width=True)
        g2.markdown("<br><br>", unsafe_allow_html=True)
        g2.metric("Change", f"{c['score_delta']:+d} pts")
        g2.markdown("✅ **SLO met**" if c["meets_slo"] else f"⚠️ **SLO not met** (target {c['slo']}%)")
        g3.plotly_chart(gauge(c["score_after"], "After"), use_container_width=True)

        fx, so = st.columns(2)
        with fx:
            st.subheader(f"✅ Fixed ({len(c['fixed'])})")
            for f in c["fixed"]:
                st.markdown(f"- **{f['check_id']}** `{f['resource_id']}` - {f['severity']}")
            if not c["fixed"]:
                st.caption("Nothing fixed between these scans.")
        with so:
            st.subheader(f"🔴 Still open ({len(c['still_open'])})")
            for f in c["still_open"]:
                st.markdown(f"- **{f['check_id']}** `{f['resource_id']}` - {f['severity']}  \n"
                            f"  _{f['remediation_hint']}_")
            if not c["still_open"]:
                st.caption("Nothing left open. 🎉")
        if c["new_issues"]:
            st.error(f"{len(c['new_issues'])} NEW issue(s) appeared: "
                     + ", ".join(f["id"] for f in c["new_issues"]))

# ---- Tab 3: remediation log
with tab3:
    if not logs:
        st.info("No remediation logs found in this folder yet.")
    else:
        lid = st.selectbox("Remediation log (by scan)", sorted(logs, reverse=True), key="log_pick")
        lg = logs[lid]
        st.write(f"**Mode:** `{lg['mode']}`   **Started:** {lg['started']}   **Finished:** {lg['finished']}")
        rows = [{
            "Check": a["check_id"], "Resource": a["resource_id"], "Action": a["action"],
            "Result": a["result"], "Detail": a["detail"],
            "Before state": json.dumps(a["before_state"]),
        } for a in lg["actions"]]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        ok = sum(a["result"] == "SUCCESS" for a in lg["actions"])
        st.caption(f"{ok} of {len(lg['actions'])} actions succeeded; the rest were skipped or need a human.")

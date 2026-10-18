import json
from pathlib import Path

import pytest

from scanner import compare as cmp

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "samples"


def load(name):
    return json.loads((SAMPLES / name).read_text("utf-8"))


def test_compare_before_after_with_log():
    c = cmp.compare(load("findings_before.json"), load("findings_after.json"),
                    load("remediation_log.json"))
    assert (c["score_before"], c["score_after"], c["score_delta"]) == (51, 89, 38)
    assert c["meets_slo"] is False                      # 89 < 90
    assert {f["check_id"] for f in c["fixed"]} == {"S3-001", "S3-002", "EC2-001", "IAM-001"}
    assert [f["check_id"] for f in c["still_open"]] == ["IAM-002"]
    assert c["new_issues"] == []
    assert c["critical_before"] == 1 and c["critical_after"] == 0
    assert c["mttr_seconds"] == 9


def test_compare_without_log_has_no_mttr():
    c = cmp.compare(load("findings_before.json"), load("findings_after.json"))
    assert c["mttr_seconds"] is None


def test_compare_detects_new_issue():
    before, after = load("findings_before.json"), load("findings_after.json")
    after["findings"][0]["status"] = "FAIL"             # CT-001 regresses
    c = cmp.compare(before, after)
    assert [f["check_id"] for f in c["new_issues"]] == ["CT-001"]


def test_cli_writes_comparison_json(tmp_path, capsys):
    out = tmp_path / "comparison.json"
    rc = cmp.main([str(SAMPLES / "findings_before.json"), str(SAMPLES / "findings_after.json"),
                   "--log", str(SAMPLES / "remediation_log.json"), "--out", str(out)])
    assert rc == 0
    assert json.loads(out.read_text())["score_delta"] == 38
    assert "51 -> 89" in capsys.readouterr().out


def test_dashboard_renders_without_errors():
    pytest.importorskip("streamlit")
    pytest.importorskip("plotly")
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(ROOT / "scanner" / "dashboard" / "app.py"), default_timeout=60)
    at.run()
    assert not at.exception, at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Posture score"] == "89%"
    assert metrics["Critical open"] == "0"
    assert metrics["MTTR"] == "9 s"

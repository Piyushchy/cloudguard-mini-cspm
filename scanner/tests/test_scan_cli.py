import json

from scanner import demo_lab, scan as scan_cli


def test_cli_writes_validated_file_and_exits_zero(session, tmp_path, monkeypatch, capsys):
    demo_lab.build_lab(session)
    monkeypatch.setattr(scan_cli.boto3, "Session", lambda **kw: session)
    out = tmp_path / "x.json"
    rc = scan_cli.main(["--label", "before", "--out", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["label"] == "before" and data["summary"]["failed"] == 5
    assert "Posture score" in capsys.readouterr().out


def test_cli_upload_puts_object_under_scans_prefix(session, tmp_path, monkeypatch):
    demo_lab.build_lab(session)            # creates cspm-demo-reports-123456789012
    monkeypatch.setattr(scan_cli.boto3, "Session", lambda **kw: session)
    rc = scan_cli.main(["--label", "before", "--out", str(tmp_path / "x.json"), "--upload"])
    assert rc == 0
    keys = [o["Key"] for o in session.client("s3").list_objects_v2(
        Bucket="cspm-demo-reports-123456789012", Prefix="scans/")["Contents"]]
    assert len(keys) == 1 and keys[0].endswith("-before.json")


def test_cli_missing_profile_is_friendly(tmp_path, capsys):
    rc = scan_cli.main(["--profile", "does-not-exist", "--out", str(tmp_path / "x.json")])
    assert rc == 2
    assert "aws configure --profile does-not-exist" in capsys.readouterr().out


def test_config_env_is_parsed():
    cfg = scan_cli.load_config()
    assert cfg["AWS_REGION"] == "ap-south-1"

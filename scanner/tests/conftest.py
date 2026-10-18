import os

import pytest

# Fake credentials BEFORE moto/boto3 are used, so nothing can reach a real account.
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing",
                  AWS_DEFAULT_REGION="ap-south-1")
os.environ.pop("AWS_PROFILE", None)


@pytest.fixture(autouse=True)
def _fast_moto(monkeypatch):
    """Loading AWS-managed policies costs ~1 s per test. Off by default; demo_lab.build_lab
    and the tests that need AdministratorAccess switch it on for themselves."""
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "false")


@pytest.fixture
def session():
    """A boto3 session talking to a fresh, empty fake AWS account (123456789012)."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        yield boto3.Session(region_name="ap-south-1")

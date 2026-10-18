"""Small helpers shared by all checks."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

CONFIG = Config(retries={"max_attempts": 8, "mode": "standard"})


def client(session, service: str, region: str):
    return session.client(service, region_name=region, config=CONFIG)


def err_code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "Unknown")


def get_account_id(session) -> str:
    return session.client("sts", config=CONFIG).get_caller_identity()["Account"]

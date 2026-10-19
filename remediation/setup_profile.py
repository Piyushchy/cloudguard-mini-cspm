"""Helper script to configure AWS profile 'cspm-p3' locally without requiring AWS CLI.
Prompts for Access Key and Secret Key locally in the terminal (never committed or exposed).
"""

import configparser
import os
import sys
from pathlib import Path


def main():
    print("=== AWS Profile Setup: cspm-p3 ===")
    print("This will write credentials to ~/.aws/credentials and ~/.aws/config\n")

    access_key = input("Enter AWS Access Key ID (from P1's DM): ").strip()
    if not access_key:
        print("Error: Access Key ID cannot be empty.")
        sys.exit(1)

    secret_key = input("Enter AWS Secret Access Key (from P1's DM): ").strip()
    if not secret_key:
        print("Error: Secret Access Key cannot be empty.")
        sys.exit(1)

    region = input("Enter Region [ap-south-1]: ").strip() or "ap-south-1"

    aws_dir = Path.home() / ".aws"
    aws_dir.mkdir(parents=True, exist_ok=True)

    creds_path = aws_dir / "credentials"
    config_path = aws_dir / "config"

    # Update credentials file
    creds = configparser.ConfigParser()
    if creds_path.exists():
        creds.read(creds_path)
    if "cspm-p3" not in creds:
        creds["cspm-p3"] = {}
    creds["cspm-p3"]["aws_access_key_id"] = access_key
    creds["cspm-p3"]["aws_secret_access_key"] = secret_key

    with open(creds_path, "w", encoding="utf-8") as f:
        creds.write(f)

    # Update config file
    config = configparser.ConfigParser()
    if config_path.exists():
        config.read(config_path)
    config_section = "profile cspm-p3"
    if config_section not in config:
        config[config_section] = {}
    config[config_section]["region"] = region
    config[config_section]["output"] = "json"

    with open(config_path, "w", encoding="utf-8") as f:
        config.write(f)

    print(f"\n[OK] Successfully configured profile 'cspm-p3' in {creds_path}")

    # Verify with boto3
    print("\nVerifying identity via boto3...")
    try:
        import boto3

        session = boto3.Session(profile_name="cspm-p3")
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print("\n=== STS Identity Verification Successful ===")
        print(f"Account ID: {identity.get('Account')}")
        print(f"UserId:     {identity.get('UserId')}")
        print(f"Arn:        {identity.get('Arn')}")
        print("============================================")
    except Exception as e:
        print(f"\n[WARNING] Boto3 verification failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

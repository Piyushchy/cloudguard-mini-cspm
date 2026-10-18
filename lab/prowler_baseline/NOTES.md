# Prowler CLI Reference & Usage Notes

Recorded for P1 (Lab & Platform) Phase 1 and Phase 2 benchmarking.

## Prowler Version
- **Installed Version**: Prowler v5.45.0
- **Runtime**: Python 3.13 (`.venv`)

## Execution Command Syntax for AWS

In Prowler v5, the provider subcommand must precede the options:
```bash
prowler aws [options]
```

### Key Options for Baseline Scans

- **Authentication & Target**:
  - `--profile <PROFILE_NAME>`: Specifies the AWS CLI profile (e.g. `cspm-p1`).
  - `--region <REGION>`: Limits scan to a specific region (e.g. `ap-south-1`).
- **Scoping to Project Services**:
  - `-s s3 ec2 iam cloudtrail`: Restricts inspection strictly to the four services in our CSPM scope.
- **Specific Checks**:
  - `-c <check_name>`: Runs specific checks (e.g. `-c s3_bucket_level_public_access_block ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22`).
- **Output Formats & Directory**:
  - `-o lab/prowler_baseline/results/`: Specifies the output directory (git-ignored).
  - `-M json csv html`: Generates JSON, CSV, and HTML reports.

### Example Baseline Command (to run in Phase 2 benchmarking)
```bash
prowler aws --profile cspm-p1 --region ap-south-1 -s s3 ec2 iam cloudtrail -o lab/prowler_baseline/results/
```

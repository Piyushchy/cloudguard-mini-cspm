#!/usr/bin/env bash
# Deploy CloudGuard Remediator Lambda Pipeline
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
REPO_ROOT="$(dirname "$DIR")"

echo "=== CloudGuard P3: Deploying Alert & Remediation Pipeline ==="
python "$DIR/deploy.py" "$@"

#!/usr/bin/env bash
# Teardown CloudGuard P3 Alert & Remediation Infrastructure
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
python "$DIR/teardown.py" "$@"

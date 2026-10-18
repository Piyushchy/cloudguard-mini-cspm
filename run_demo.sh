#!/usr/bin/env bash
# One-click offline demo for Mac/Linux. Needs Python 3.11+. No AWS account needed.
set -e
cd "$(dirname "$0")"
[ -x .venv/bin/python ] || python3 -m venv .venv
. .venv/bin/activate
python -m pip install -q -r scanner/requirements.txt
python -m pytest -q
python -m scanner.demo_local --open

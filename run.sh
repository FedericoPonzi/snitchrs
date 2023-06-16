#!/usr/bin/env bash
set -euo pipefail
python -m venv ui/.venv
source ui/.venv/bin/activate
pip3 install -r ui/requirements.txt


RUST_LOG=debug cargo xtask run | python3 ui/main.py
deactivate

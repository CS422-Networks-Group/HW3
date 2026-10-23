#!/usr/bin/env bash
# Build and register dgcc, run every experiment, and write all tables and plots.
#   scripts/run_all.sh [main.py options]      e.g. scripts/run_all.sh --n 5 --reps 3
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}

make -C bpf
grep -qw dgcc /proc/sys/net/ipv4/tcp_available_congestion_control || sudo make -C bpf load
"$PY" src/main.py "$@"

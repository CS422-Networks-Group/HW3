#!/usr/bin/env bash
# Build and register dgcc, run every experiment, and regenerate all tables and plots.
#   scripts/run_all.sh [main.py options]      e.g. scripts/run_all.sh --n 5 --reps 3
# Results go to $OUT (default: results). Steps that need root use sudo.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=${OUT:-results}
PY=${PY:-.venv/bin/python}

make -C bpf
if ! grep -qw dgcc /proc/sys/net/ipv4/tcp_available_congestion_control; then
    sudo make -C bpf load
fi
for algorithm in dgcc cubic reno bbr; do
    grep -qw "$algorithm" /proc/sys/net/ipv4/tcp_allowed_congestion_control ||
        sudo sysctl -w net.ipv4.tcp_allowed_congestion_control="reno cubic bbr dgcc"
done

mkdir -p "$OUT"
# kernel-side event counters before and after, to show which dgcc branches ran
sudo make -s -C bpf stats > "$OUT/bpf_stats_before.json"
"$PY" src/main.py --out "$OUT" "$@"
sudo make -s -C bpf stats > "$OUT/bpf_stats_after.json"
"$PY" scripts/bpf_stats.py "$OUT/bpf_stats_before.json" "$OUT/bpf_stats_after.json" | tee "$OUT/bpf_stats.txt"

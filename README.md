# CS 422 HW3: eBPF congestion control (Option 1)

`dgcc` ([`bpf/dgcc.bpf.c`](bpf/dgcc.bpf.c)) is our HW2 Q3(b) algorithm as an eBPF `tcp_congestion_ops`. The HW2
client ([`src/main.py`](src/main.py)) compares it with CUBIC, Reno, and BBR. The report is
[`report/REPORT.pdf`](report/REPORT.pdf).

## Requirements

- Linux kernel ≥ 5.6 with `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_DEBUG_INFO_BTF`, and the `tcp_bbr` module
  (tested on `6.6.87.2-microsoft-standard-WSL2`, Ubuntu 24.04)
- Python 3.12

```
sudo apt install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic make python3-venv
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

## Build and load

```
make -C bpf
sudo make -C bpf load       # registers dgcc, loads tcp_bbr, allows all four algorithms
sudo make -C bpf unload
```

## Run

```
scripts/run_all.sh [input_csv] [options]   # builds and loads dgcc if needed, then runs src/main.py
```

| option | default | meaning |
|---|---|---|
| `input_csv` | `data/listed_iperf3_servers.csv` | server list (`IP/HOST`, `PORT` columns) |
| `--n` | 5 | destinations that must complete every test |
| `--reps` | 3 | repetitions of each algorithm per destination |
| `--time` | 10 | test duration (s) |
| `--interval` | 0.25 | sampling interval (s) |
| `--algorithms` | `dgcc cubic reno bbr` | algorithms to compare |
| `--retries` | 1 | retries for a failed test |
| `--max-attempts` | 40 | servers tried before reporting a shortfall |
| `--seed` | random | server shuffle seed |
| `--out` | `results` | output directory |

The report's results (`results/`) came from `scripts/run_all.sh` with the defaults.

# CS 422 HW3: eBPF congestion control (Option 1)

`dgcc` ([`bpf/dgcc.bpf.c`](bpf/dgcc.bpf.c)) is our HW2 Q3(b) algorithm as an eBPF `tcp_congestion_ops`. The HW2
client ([`src/main.py`](src/main.py)) compares it with CUBIC, Reno, and BBR. The report is
[`report/REPORT.pdf`](report/REPORT.pdf).

## Requirements

- Linux kernel ≥ 5.6 with `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_DEBUG_INFO_BTF`, and the `tcp_bbr` module
  (tested on `6.6.87.2-microsoft-standard-WSL2`, Ubuntu 24.04)
- Python 3.12 and internet access (the tests run against public iperf3 servers)

## Running the experiments

Run every command from the repository root.

1. Install the build tools and Python dependencies (once):

   ```
   sudo apt install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic make python3-venv
   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
   ```

2. Build dgcc and load it into the kernel (once per boot):

   ```
   make -C bpf
   sudo make -C bpf load
   cat /proc/sys/net/ipv4/tcp_available_congestion_control   # should list: reno cubic bbr dgcc
   ```

   `load` registers dgcc, loads `tcp_bbr`, and allows the Python client to select all four algorithms.

3. Run all experiments and generate the tables and plots:

   ```
   scripts/run_all.sh
   ```

   With the defaults this runs dgcc, CUBIC, Reno, and BBR 3 times each against 5 servers (60 tests of 10 s, about
   15 minutes). It writes the raw data, summary tables, and PDF plots to `results/` (overwriting the committed
   results) and PNG copies of the plots to `report/figures/`. The report's results came from this command.

   Options can be appended, e.g. `scripts/run_all.sh --n 3 --reps 2 --out my_results`:

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

4. Unload dgcc when done:

   ```
   sudo make -C bpf unload
   ```

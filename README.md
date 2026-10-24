# CS 422 HW3: eBPF congestion control (Option 1)

`dgcc` ("delay + goodput congestion control") is the algorithm our team designed in HW2 Q3(b), implemented as a
BPF `struct_ops` `tcp_congestion_ops` ([`bpf/dgcc.bpf.c`](bpf/dgcc.bpf.c)). The HW2 iperf3-compatible Python
client ([`src/main.py`](src/main.py)) selects it on the data socket with `setsockopt(TCP_CONGESTION, "dgcc")`
and compares it with the kernel's CUBIC, Reno, and BBR.

## Requirements

| | version used |
|---|---|
| Kernel | `6.6.87.2-microsoft-standard-WSL2` (Ubuntu 24.04 on WSL2) |
| Kernel features | `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_DEBUG_INFO_BTF=y` (`/sys/kernel/btf/vmlinux`), `CONFIG_TCP_CONG_BBR=m` for the BBR baseline. BPF `tcp_congestion_ops` needs kernel >= 5.6; the `cong_control` hook is `(sk, rs)` up to 6.9 and `(sk, ack, flag, rs)` from 6.10; `bpf/Makefile` picks the right one from `vmlinux.h`. |
| Build | `clang`/`llvm` 18, `libbpf-dev` 1.3, `bpftool` from `linux-tools-generic` |
| Python | 3.12, `pandas==3.0.6`, `matplotlib==3.11.2` (`requirements.txt`) |

```
sudo apt install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic make python3-venv
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

## Build, load, unload

```
make -C bpf                 # bpftool btf dump -> bpf/vmlinux.h, clang -target bpf -> bpf/dgcc.bpf.o
sudo make -C bpf load       # modprobe tcp_bbr; bpftool struct_ops register; allow "reno cubic bbr dgcc"
cat /proc/sys/net/ipv4/tcp_available_congestion_control    # ... dgcc
sudo make -C bpf unload     # bpftool struct_ops unregister name dgcc
```

`load` sets `net.ipv4.tcp_allowed_congestion_control` so the unprivileged Python client can select every
algorithm.

## Running the experiments

```
scripts/run_all.sh                      # build + load if needed, run all tests, write tables + plots to results/
scripts/run_all.sh --n 5 --reps 3       # any src/main.py option can be appended
```

| option | meaning |
|---|---|
| `input_csv` | server list with `IP/HOST` and `PORT` columns (default `data/listed_iperf3_servers.csv`) |
| `--n` | destinations that must complete every repetition of every algorithm (default 5) |
| `--reps` | repetitions of each algorithm per destination (default 3) |
| `--time` | duration of each test in seconds (default 10) |
| `--interval` | sampling interval for goodput and `TCP_INFO` (default 0.25 s) |
| `--algorithms` | algorithms to compare (default `dgcc cubic reno bbr`) |
| `--retries` | extra tries for a failed test before the destination is dropped (default 1) |
| `--max-attempts` | servers tried before reporting a shortfall (default 40) |
| `--seed` | seed for the server shuffle (saved in `run_metadata.json`) |
| `--out` | output directory (default `results`) |

## Outputs (`results/`)

PNG copies of the plots go to `report/figures/` for the report.

| file | contents |
|---|---|
| `tcp_stats.csv` | one row per sample: run id, destination, rep, position in the test order, algorithm, goodput, decoded `TCP_INFO` |
| `runs.csv` | one row per test: mean goodput, srtt, queueing delay, retransmitted segments, RTO flag, goodput / CUBIC |
| `summary.csv` | goodput min / median / mean / p95 and srtt per destination and algorithm |
| `aggregate.csv` | per algorithm over all destinations and reps: goodput, srtt, queueing delay, retransmissions per test, tests with an RTO |
| `run_metadata.json` | session, kernel, seed, destinations, test order, and every test attempted (start time, ok / failed + error) |
| `tcp_stats_timeseries_<alg>.pdf` | snd_cwnd, RTT, retransmitted segments, and goodput over time at the representative destination |
| `tcp_stats_scatter_<alg>.pdf` | snd_cwnd, srtt, and retransmitted segments vs goodput at the same destination |

Percentiles use pandas' default linear interpolation between closest ranks (numpy `linear`, Hyndman–Fan type 7).
Queueing delay is srtt − min_rtt per sample.

## Implementation notes

| hook in `bpf/dgcc.bpf.c` | role |
|---|---|
| `dgcc_init` | initial state: cwnd = 4, start-up mode, empty estimates |
| `dgcc_cong_control` | every ACK: per-round min RTT and losses, start-up growth, end-of-round detection, bounds, pacing rate |
| `dgcc_round` | once per round trip: the pseudocode's measure / loss / start-up / normal-operation / bounds steps |
| `dgcc_set_state` | on `TCP_CA_Loss` (RTO): cwnd = 4, back to start-up |
| `dgcc_undo_cwnd` | the kernel found a loss spurious: forget the round's losses, restore the pre-cut cwnd |
| `dgcc_ssthresh` | required by the kernel; returns `snd_ssthresh` unchanged, since dgcc sets it itself |

- dgcc implements `cong_control` rather than `cong_avoid`, so it owns `snd_cwnd` and the kernel's PRR / slow-start
  code is not applied (the same arrangement BBR uses).
- A round ends when an ACK's `rs->prior_delivered` reaches the `tp->delivered` value saved at the start of the round,
  i.e. a packet sent after the round began has been acknowledged (the same test as BBR).
- Because `cong_control` replaces the kernel's pacing update, dgcc sets `sk_pacing_rate` to 2 × cwnd / srtt in
  start-up and 1.2 × cwnd / srtt otherwise (the ratios of `tcp_update_pacing_rate()`). No `fq` qdisc was used, so
  pacing is not enforced.
- Per-socket state is `struct dgcc` in `icsk_ca_priv` (64 of the 104 available bytes).
- Why the changes from the pseudocode: per-ACK start-up growth avoids a 2 × cwnd burst at the round boundary; the
  one-round hold is needed because srtt is an EWMA that still shows the old queue after a cut, and recovery from one
  loss often spans two rounds; the 2 × BDP cap is skipped in start-up because the round's goodput reflects the previous
  round's cwnd, so the cap would stop start-up early.
- `bpf/Makefile` calls `/usr/lib/linux-tools/<version>/bpftool` directly, because Ubuntu's `/usr/sbin/bpftool` wrapper
  refuses to run when no `linux-tools` package matches the running (WSL2) kernel.

## Data collection

- `TCP_INFO` is read with `getsockopt()` on the data socket and decoded as Linux `struct tcp_info` up to
  `tcpi_snd_wnd` (232 bytes, kernel ≥ 5.4; `struct` format `=8B24I4Q6IQ3Q2I2Q2I2I`). Cumulative counters
  (`bytes_acked`, `total_retrans`, `data_segs_out`) are differenced between reads and divided by the measured elapsed
  time; the actual interval is longer than 0.25 s when a `sendall()` blocks. Units are in the column names.
- A destination is kept only if all of its tests succeed. A failed test is retried once after 2 s, because many
  servers briefly refuse a new test right after the previous one ends. In session `20261022T233436`, 12 servers were
  tried to get 5. At the 5 kept destinations, 38 tests failed once (20 connection resets, 18 refusals) and all
  succeeded on retry. 7 servers were dropped: 5 reported "busy" twice, 1 refused twice, and 1 (217.18.95.142) reset
  twice on its 6th test, so its 5 completed tests were discarded.

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

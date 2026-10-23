import argparse
import pandas as pd
import socket
import ipaddress
import json
import os
import platform
import random
import struct
import time
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

#dgcc is the BPF struct_ops algorithm in bpf/dgcc.bpf.c; the others are the kernel's built-in modules
DEFAULT_CONGESTION_ALGORITHMS = ("dgcc", "cubic", "reno", "bbr")
ALGORITHM_COLORS = {"dgcc": "tab:red", "cubic": "tab:blue", "reno": "tab:green", "bbr": "tab:purple"}

#linux struct tcp_info (include/uapi/linux/tcp.h), decoded up to tcpi_snd_wnd (232 bytes, kernel 5.4+)
#8 u8 header fields, 24 u32, then the u64/u32 extensions in kernel order. "=" = native byte order, no padding
TCP_INFO_FMT = "=8B24I4Q6IQ3Q2I2Q2I2I"
TCP_INFO_FIELDS = (
    "state ca_state retransmits probes backoff options wscale flags "
    "rto ato snd_mss rcv_mss unacked sacked lost retrans fackets "
    "last_data_sent last_ack_sent last_data_recv last_ack_recv "
    "pmtu rcv_ssthresh rtt rttvar snd_ssthresh snd_cwnd advmss reordering "
    "rcv_rtt rcv_space total_retrans "
    "pacing_rate max_pacing_rate bytes_acked bytes_received "
    "segs_out segs_in notsent_bytes min_rtt data_segs_in data_segs_out "
    "delivery_rate busy_time rwnd_limited sndbuf_limited delivered delivered_ce "
    "bytes_sent bytes_retrans dsack_dups reord_seen rcv_ooopack snd_wnd"
).split()
TCP_INFO_LEN = struct.calcsize(TCP_INFO_FMT)
assert len(TCP_INFO_FIELDS) == len(struct.unpack(TCP_INFO_FMT, bytes(TCP_INFO_LEN)))

#read and decode TCP_INFO from a live socket into a dict of raw kernel values
def tcp_info(sock) -> dict:
    raw = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, TCP_INFO_LEN)
    if len(raw) < TCP_INFO_LEN:
        raise RuntimeError(f"kernel tcp_info is {len(raw)} bytes, need {TCP_INFO_LEN}")
    return dict(zip(TCP_INFO_FIELDS, struct.unpack(TCP_INFO_FMT, raw[:TCP_INFO_LEN])))

#build one sample from two successive tcp_info reads taken dt seconds apart
#cumulative kernel counters are differenced to get per-interval values
def tcp_sample(info, prev, timestamp, t, dt) -> dict:
    retrans = info["total_retrans"] - prev["total_retrans"]
    segs_out = info["data_segs_out"] - prev["data_segs_out"]
    return {
        "timestamp_unix_s": timestamp,
        "time_s": t,
        "interval_s": dt,
        "goodput_bps": (info["bytes_acked"] - prev["bytes_acked"]) * 8 / dt,
        "snd_cwnd_segs": info["snd_cwnd"],
        "snd_mss_bytes": info["snd_mss"],
        "cwnd_bytes": info["snd_cwnd"] * info["snd_mss"],
        "snd_ssthresh_segs": info["snd_ssthresh"],
        "srtt_ms": info["rtt"] / 1000,
        "rttvar_ms": info["rttvar"] / 1000,
        "min_rtt_ms": info["min_rtt"] / 1000,
        "rto_ms": info["rto"] / 1000,
        #loss proxy: segments retransmitted during this interval, and as a fraction of data segments sent
        "retrans_segs": retrans,
        "retrans_rate": retrans / segs_out if segs_out else 0.0,
        "retrans_bytes": info["bytes_retrans"] - prev["bytes_retrans"],
        "total_retrans_segs": info["total_retrans"],
        "lost_segs": info["lost"],
        "rto_backoffs": info["retransmits"],
        "ca_state": info["ca_state"],
        "pacing_rate_bps": info["pacing_rate"] * 8,
        "delivery_rate_bps": info["delivery_rate"] * 8,
        "delivery_rate_app_limited": info["flags"] & 1,
        "bytes_acked": info["bytes_acked"],
        "bytes_sent": info["bytes_sent"],
        "unacked_segs": info["unacked"],
        "notsent_bytes": info["notsent_bytes"],
        "snd_wnd_bytes": info["snd_wnd"],
    }

#check whether a value is an ip address or a host name
def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

#processing the csv for use by the functions
def process_csv(csv_file: str) -> pd.DataFrame:
    #read the csv
    df = pd.read_csv(csv_file)

    #read each row in csv and resolve host names to ips
    for index, row in df.iterrows():
        ip_or_host = row["IP/HOST"]
        if not is_ip_address(ip_or_host):
            try:
                ip_or_host = socket.gethostbyname(ip_or_host)
            except socket.gaierror:
                continue
            #setting the df values
            df.loc[index, "IP/HOST"] = ip_or_host
    return df


def set_congestion_control(sock, requested: str) -> str:
    """Set and verify the congestion-control algorithm on a TCP data socket."""
    if not hasattr(socket, "TCP_CONGESTION"):
        raise RuntimeError("TCP_CONGESTION is unavailable; run this program on Linux or WSL2")
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, requested.encode())
    except OSError as e:
        raise RuntimeError(
            f"congestion-control algorithm '{requested}' is unavailable: {e}. "
            "Check /proc/sys/net/ipv4/tcp_available_congestion_control and "
            "tcp_allowed_congestion_control (dgcc needs `sudo make -C bpf load`)"
        ) from e
    active = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, 16).split(b"\0")[0].decode()
    if active != requested:
        raise RuntimeError(f"requested congestion control '{requested}', but kernel selected '{active}'")
    return active


def validate_congestion_algorithms(algorithms):
    """Fail before running experiments if the local kernel cannot select an algorithm."""
    for algorithm in algorithms:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            set_congestion_control(sock, algorithm)


def run_test(server, port, experiment_time, interval, congestion_algorithm):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(10)
    client.connect((server, port))
    params = {"tcp": True, "omit": 0, "time": experiment_time, "num": 0,
          "blockcount": 0, "parallel": 1, "len": 131072,
          "pacing_timer": 1000, "client_version": "3.22"}

    #step 1: generate and send cookie of 36 bytes + 1 null byte
    alphabet = b"abcdefghijklmnopqrstuvwxyz234567"
    cookie = b""
    for b in os.urandom(36):
        cookie += bytes([alphabet[b % 32]])
    cookie += b"\x00"
    client.sendall(cookie)

    #step 2: read PARAM_EXCHANGE (9)
    if client.recv(1) != bytes([9]):
        raise RuntimeError("server busy or closed connection")

    #step 3: send json string preview + json bytes
    body = json.dumps(params).encode()
    client.sendall(len(body).to_bytes(4, "big"))
    client.sendall(body)

    #step 4: read CREATE_STREAMS (10)
    if client.recv(1) != bytes([10]):
        raise RuntimeError("server rejected parameters")

    #step 5: open a second connection to send data, with the requested congestion control set before connect
    new_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_client.settimeout(10)
    set_congestion_control(new_client, congestion_algorithm)
    new_client.connect((server, port))
    new_client.sendall(cookie)

    #step 6: read TEST_START (1) and TEST_RUNNING (2)
    if client.recv(1) != bytes([1]) or client.recv(1) != bytes([2]):
        raise RuntimeError("test failed to start")

    #step 7: send data for the experiment duration, sampling goodput and tcp stats from the data socket every interval
    buf = bytes(131072)
    samples = []
    start = last_time = time.monotonic()
    prev = tcp_info(new_client)
    while time.monotonic() - start < experiment_time:
        new_client.sendall(buf)
        now = time.monotonic()
        if now - last_time >= interval:
            info = tcp_info(new_client)
            samples.append(tcp_sample(info, prev, time.time(), now - start, now - last_time))
            last_time, prev = now, info
    #record the algorithm the established connection actually used, read back from the kernel after the transfer
    algorithm = new_client.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, 16).split(b"\0")[0].decode()

    #step 8: send TEST_END (4), read EXCHANGE_RESULTS (13)
    client.sendall(bytes([4]))
    if client.recv(1) != bytes([13]):
        raise RuntimeError("server did not start results exchange")

    #step 9: send our results
    results = {"cpu_util_total": 0, "cpu_util_user": 0, "cpu_util_system": 0,
               "sender_has_retransmits": 1,
               "streams": [{"id": 1, "bytes": prev["bytes_acked"], "retransmits": prev["total_retrans"],
                            "jitter": 0, "errors": 0, "packets": 0}]}
    body = json.dumps(results).encode()
    client.sendall(len(body).to_bytes(4, "big"))
    client.sendall(body)

    #step 10: read the server's results (4-byte length, then that many bytes)
    n = int.from_bytes(client.recv(4), "big")
    server_results = b""
    while len(server_results) < n:
        chunk = client.recv(n - len(server_results))
        if not chunk:
            raise ConnectionError("server closed connection")
        server_results += chunk

    #step 11: read DISPLAY_RESULTS (14), send IPERF_DONE (16)
    client.recv(1)
    client.sendall(bytes([16]))

    new_client.close()
    client.close()
    if algorithm != congestion_algorithm:
        raise RuntimeError(f"data socket ended on '{algorithm}', expected '{congestion_algorithm}'")
    return algorithm, samples


def parse_args():
    parser = argparse.ArgumentParser(
        description="iperf3-compatible client comparing dgcc (eBPF) with cubic, reno, and bbr"
    )
    parser.add_argument(
        "input_csv",
        nargs="?",
        default="data/listed_iperf3_servers.csv",
        help="Path to a CSV file containing an IP/HOST column with the addresses to test "
             "(default: data/listed_iperf3_servers.csv)."
    )
    parser.add_argument(
        "--n",
        type=int,
        default=5,
        help="Number of destinations that must complete every repetition of every algorithm (default: 5)",
    )
    parser.add_argument(
        "--reps",
        type=int,
        default=3,
        help="repetitions of every algorithm per destination (default: 3)"
    )
    parser.add_argument(
        "--time",
        type=int,
        default=10,
        help="time to run each iperf3 test (default: 10s)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.25,
        help="goodput / tcp stats sampling interval in seconds (default: 0.25)"
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=40,
        help="max number of servers to try (default: 40)"
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="extra tries for a failed test (e.g. server busy) before giving up on a destination (default: 1)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="seed for the server shuffle (default: random; the value used is saved in run_metadata.json)"
    )
    parser.add_argument(
        "--out",
        default="results",
        help="directory for CSVs and PDF plots (default: results)"
    )
    parser.add_argument(
        "--representative",
        default=None,
        help="destination (ip:port) for the tcp stats plots (default: the one with median mean goodput)"
    )
    parser.add_argument(
        "--algorithms",
        nargs="+",
        default=list(DEFAULT_CONGESTION_ALGORITHMS),
        help="congestion-control algorithms to compare (default: dgcc cubic reno bbr)"
    )
    parser.add_argument(
        "--replot",
        action="store_true",
        help="skip the measurements; rebuild the tables and plots from <out>/tcp_stats.csv"
    )
    return parser.parse_args()

#test order for one repetition: the algorithm list rotated by one position per repetition, so every
#algorithm runs first, second, ... equally often and slow drifts in path conditions do not favor one
def rep_order(algorithms, rep):
    k = (rep - 1) % len(algorithms)
    return algorithms[k:] + algorithms[:k]

#run every repetition of every algorithm against one destination; the destination only counts if all succeed
def run_destination(ip, port, args, algorithms, session, server_attempt, attempts):
    destination = f"{ip}:{port}"
    rows = []
    for rep in range(1, args.reps + 1):
        for position, algorithm in enumerate(rep_order(algorithms, rep), start=1):
            run_id = f"{session}-{server_attempt:02d}-r{rep}-{algorithm}"
            for attempt in range(args.retries + 1):
                started = time.time()
                try:
                    active_algorithm, samples = run_test(ip, port, args.time, args.interval, algorithm)
                except (OSError, RuntimeError) as e:
                    attempts.append({"run_id": run_id, "destination": destination, "rep": rep,
                                     "position": position, "algorithm": algorithm, "start_unix_s": started,
                                     "status": "failed", "error": str(e)})
                    print(f"failed: {destination} rep {rep} ({algorithm}: {e})")
                    #iperf3 servers accept one test at a time; give the previous one a moment to clear
                    time.sleep(2)
                    continue
                for s in samples:
                    rows.append({"run_id": run_id, "destination": destination, "rep": rep,
                                 "position": position, "algorithm": active_algorithm, **s})
                attempts.append({"run_id": run_id, "destination": destination, "rep": rep,
                                 "position": position, "algorithm": active_algorithm, "start_unix_s": started,
                                 "status": "ok"})
                print(f"ok: {destination} rep {rep} #{position} ({active_algorithm})")
                break
            else:
                return None
    return rows

#pick one shared destination whose algorithm-balanced mean goodput is the median across destinations
def pick_representative(data: pd.DataFrame) -> str:
    means = (data.groupby(["destination", "algorithm"])["goodput_bps"].mean()
             .groupby("destination").mean().sort_values())
    return means.index[(len(means) - 1) // 2]

#percentiles use pandas' default linear interpolation between the closest ranks (numpy "linear" / Hyndman-Fan 7)
def q(p):
    f = lambda s: s.quantile(p)
    f.__name__ = f"p{int(p * 100)}"
    return f

#per-destination and per-algorithm throughput / rtt statistics
def summarize(data: pd.DataFrame, algorithms, out: str) -> pd.DataFrame:
    data = data.assign(goodput_mbps=data["goodput_bps"] / 1e6,
                       queue_delay_ms=(data["srtt_ms"] - data["min_rtt_ms"]).clip(lower=0))

    #per destination and algorithm, pooled over repetitions
    summary = data.groupby(["destination", "algorithm"]).agg(
        runs=("run_id", "nunique"),
        goodput_min=("goodput_mbps", "min"), goodput_median=("goodput_mbps", "median"),
        goodput_mean=("goodput_mbps", "mean"), goodput_p95=("goodput_mbps", q(0.95)),
        srtt_median=("srtt_ms", "median"), srtt_mean=("srtt_ms", "mean"), srtt_p95=("srtt_ms", q(0.95)),
        min_rtt=("min_rtt_ms", "min"), retrans_segs=("retrans_segs", "sum"))
    summary["retrans_segs_per_run"] = summary.pop("retrans_segs") / summary["runs"]
    summary.round(3).to_csv(os.path.join(out, "summary.csv"))

    #per run: mean goodput, and goodput relative to the destination's cubic mean (removes the path's capacity)
    runs = data.groupby(["run_id", "destination", "algorithm"]).agg(
        goodput_mean=("goodput_mbps", "mean"), srtt_mean=("srtt_ms", "mean"),
        queue_delay_mean=("queue_delay_ms", "mean"), retrans_segs=("retrans_segs", "sum"),
        rto=("rto_backoffs", lambda s: int((s > 0).any()))).reset_index()
    if "cubic" in algorithms:
        cubic_mean = runs[runs["algorithm"] == "cubic"].groupby("destination")["goodput_mean"].mean()
        runs["goodput_vs_cubic"] = runs["goodput_mean"] / runs["destination"].map(cubic_mean)
    runs.round(4).to_csv(os.path.join(out, "runs.csv"), index=False)

    #aggregate over all destinations and repetitions
    agg = data.groupby("algorithm").agg(
        samples=("goodput_mbps", "size"),
        goodput_mean=("goodput_mbps", "mean"), goodput_std=("goodput_mbps", "std"),
        goodput_p5=("goodput_mbps", q(0.05)), goodput_median=("goodput_mbps", "median"),
        goodput_p95=("goodput_mbps", q(0.95)),
        srtt_mean=("srtt_ms", "mean"), srtt_median=("srtt_ms", "median"), srtt_p95=("srtt_ms", q(0.95)),
        queue_delay_mean=("queue_delay_ms", "mean"), queue_delay_median=("queue_delay_ms", "median"),
        queue_delay_p95=("queue_delay_ms", q(0.95)),
        retrans_rate_mean=("retrans_rate", "mean"))
    by_run = runs.groupby("algorithm")
    agg.insert(0, "runs", by_run.size())
    agg["run_goodput_mean"] = by_run["goodput_mean"].mean()
    agg["run_goodput_std"] = by_run["goodput_mean"].std()
    agg["retrans_segs_per_run"] = by_run["retrans_segs"].mean()
    agg["runs_with_rto"] = by_run["rto"].sum()
    if "goodput_vs_cubic" in runs:
        agg["goodput_vs_cubic_mean"] = by_run["goodput_vs_cubic"].mean()
    agg = agg.reindex([a for a in algorithms if a in agg.index])
    agg.round(3).to_csv(os.path.join(out, "aggregate.csv"))
    print(agg.round(2).T)
    return runs

def save(fig, out, name):
    fig.savefig(os.path.join(out, f"{name}.pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(out, f"{name}.png"), bbox_inches="tight", dpi=130)
    plt.close(fig)

#q2(b)(i) repeated for every algorithm: one column per algorithm, one row per metric, each row on one y scale
def plot_timeseries(rep_data: pd.DataFrame, algorithms, out: str):
    dest = rep_data["destination"].iloc[0]
    fig, axes = plt.subplots(4, len(algorithms), figsize=(3.6 * len(algorithms), 10),
                             sharex=True, sharey="row", squeeze=False)
    reps = sorted(rep_data["rep"].unique())
    for col, algorithm in enumerate(algorithms):
        for rep in reps:
            d = rep_data[(rep_data["algorithm"] == algorithm) & (rep_data["rep"] == rep)].sort_values("time_s")
            if d.empty:
                continue
            color = plt.cm.tab10(rep - 1)
            t = d["time_s"]
            axes[0, col].plot(t, d["snd_cwnd_segs"], color=color, label=f"rep {rep}")
            axes[1, col].plot(t, d["srtt_ms"], color=color)
            axes[1, col].plot(t, d["min_rtt_ms"], "--", color=color, lw=0.8)
            axes[2, col].plot(t, d["retrans_segs"], "o-", color=color, ms=3, lw=0.8)
            axes[3, col].plot(t, d["goodput_bps"] / 1e6, color=color)
        axes[0, col].set_title(algorithm, color=ALGORITHM_COLORS.get(algorithm, "black"), fontweight="bold")
        axes[3, col].set_xlabel("time (s)")
    axes[0, 0].set_ylabel("snd_cwnd (segments)")
    axes[1, 0].set_ylabel("RTT (ms)\nsrtt solid, min_rtt dashed")
    axes[2, 0].set_ylabel("retransmitted\nsegments / interval")
    axes[3, 0].set_ylabel("goodput (Mbit/s)")
    axes[0, -1].legend(loc="upper right", fontsize=8)
    for ax in axes.flat:
        ax.grid(alpha=0.3)
    fig.suptitle(f"TCP stats over time: {dest} (all algorithms, shared y scale per row)")
    fig.tight_layout()
    save(fig, out, "tcp_stats_timeseries")

#q2(b)(ii) repeated for every algorithm: one row per algorithm, same x scale per column and same y scale everywhere
def plot_scatter(rep_data: pd.DataFrame, algorithms, out: str, duration: float):
    dest = rep_data["destination"].iloc[0]
    fig, axes = plt.subplots(len(algorithms), 3, figsize=(13, 3.2 * len(algorithms)),
                             sharex="col", sharey=True, squeeze=False, layout="constrained")
    cols =[("snd_cwnd_segs", "snd_cwnd (segments)"), ("srtt_ms", "srtt (ms)"),
            ("retrans_segs", "retransmitted segments / interval")]
    for row, algorithm in enumerate(algorithms):
        d = rep_data[rep_data["algorithm"] == algorithm]
        for col, (field, label) in enumerate(cols):
            ax = axes[row, col]
            sc = ax.scatter(d[field], d["goodput_bps"] / 1e6, c=d["time_s"], cmap="viridis",
                            vmin=0, vmax=duration, s=14)
            ax.grid(alpha=0.3)
            if row == len(algorithms) - 1:
                ax.set_xlabel(label)
        axes[row, 0].set_ylabel(f"{algorithm}\ngoodput (Mbit/s)", color=ALGORITHM_COLORS.get(algorithm, "black"),
                                fontweight="bold")
    fig.colorbar(sc, ax=axes, label="time (s)", shrink=0.5)
    fig.suptitle(f"TCP stats vs goodput: {dest} (all repetitions, shared scales)")
    save(fig, out, "tcp_stats_scatter")

#aggregate comparison: per-destination mean goodput / srtt with error bars over repetitions,
#and distributions of per-run normalized goodput and per-sample queueing delay
def plot_aggregate(data: pd.DataFrame, runs: pd.DataFrame, algorithms, out: str):
    dests = list(runs.groupby("destination")["goodput_mean"].mean().sort_values(ascending=False).index)
    width = 0.8 / len(algorithms)
    fig, axes = plt.subplots(2, 1, figsize=(max(8, 1.8 * len(dests)), 7), sharex=True)
    for i, algorithm in enumerate(algorithms):
        r = runs[runs["algorithm"] == algorithm].groupby("destination")
        x = [j + (i - (len(algorithms) - 1) / 2) * width for j in range(len(dests))]
        for ax, field in zip(axes, ["goodput_mean", "srtt_mean"]):
            ax.bar(x, r[field].mean().reindex(dests), width, yerr=r[field].std().reindex(dests),
                   capsize=2, label=algorithm, color=ALGORITHM_COLORS.get(algorithm))
    axes[0].set_ylabel("mean goodput (Mbit/s)")
    axes[1].set_ylabel("mean srtt (ms)")
    axes[1].set_xticks(range(len(dests)), dests, rotation=20, ha="right")
    axes[0].legend(ncol=len(algorithms), fontsize=8)
    axes[0].set_title("Per-destination means over repetitions (error bar = std across runs)")
    for ax in axes:
        ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    save(fig, out, "aggregate_by_destination")

    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    queue = (data["srtt_ms"] - data["min_rtt_ms"]).clip(lower=0)
    if "goodput_vs_cubic" in runs:
        axes[0].boxplot([runs.loc[runs["algorithm"] == a, "goodput_vs_cubic"] for a in algorithms],
                        tick_labels=algorithms)
        axes[0].axhline(1, color="gray", lw=0.8, ls="--")
        axes[0].set_ylabel("run mean goodput / destination's cubic mean")
    axes[1].boxplot([queue[data["algorithm"] == a] for a in algorithms], tick_labels=algorithms,
                    showfliers=False)
    axes[1].set_ylabel("queueing delay: srtt - min_rtt (ms)")
    axes[0].set_title("Normalized goodput per run")
    axes[1].set_title("Queueing delay per sample (outliers hidden)")
    for ax in axes:
        ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    save(fig, out, "aggregate_boxplot")

def analyze(data: pd.DataFrame, algorithms, out: str, representative: str | None, duration: float):
    algorithms = [a for a in algorithms if a in set(data["algorithm"])]
    runs = summarize(data, algorithms, out)
    plot_aggregate(data, runs, algorithms, out)

    #repeat the tcp stats plots for every algorithm at the same representative destination
    rep = representative or pick_representative(data)
    if rep not in set(data["destination"]):
        print(f"representative {rep} has no samples, skipping tcp stats plots")
        return
    print(f"representative destination: {rep}")
    rep_data = data[data["destination"] == rep]
    plot_timeseries(rep_data, algorithms, out)
    plot_scatter(rep_data, algorithms, out, duration)

#main test runner
def main():
    args = parse_args()
    # Preserve the requested order while preventing duplicate runs/plots.
    algorithms = list(dict.fromkeys(args.algorithms))
    os.makedirs(args.out, exist_ok=True)
    if args.replot:
        meta_path = os.path.join(args.out, "run_metadata.json")
        duration = json.load(open(meta_path))["time_s"] if os.path.exists(meta_path) else args.time
        analyze(pd.read_csv(os.path.join(args.out, "tcp_stats.csv")), algorithms, args.out,
                args.representative, duration)
        return
    try:
        validate_congestion_algorithms(algorithms)
    except RuntimeError as e:
        raise SystemExit(f"error: {e}") from e
    df = process_csv(args.input_csv)

    #try random servers until n complete all repetitions of all algorithms or we run out of attempts
    session = time.strftime("%Y%m%dT%H%M%S")
    seed = args.seed if args.seed is not None else random.randrange(2**32)
    rows = []
    attempts = []
    destinations = []
    for server_attempt, (_, row) in enumerate(df.sample(frac=1, random_state=seed).head(args.max_attempts).iterrows(),
                                              start=1):
        if len(destinations) == args.n:
            break
        ip, port = row["IP/HOST"], int(str(row["PORT"]).split("-")[0])
        destination_rows = run_destination(ip, port, args, algorithms, session, server_attempt, attempts)
        if destination_rows is None:
            print(f"discarding incomplete destination: {ip}:{port}")
            continue
        rows.extend(destination_rows)
        destinations.append(f"{ip}:{port}")

    if len(destinations) < args.n:
        print(f"shortfall: only {len(destinations)} of {args.n} servers succeeded")

    #record the run setup, host kernel, test order, and every test attempted
    meta = {"session": session, "kernel": platform.release(), "seed": seed, "requested": args.n,
            "succeeded": len(destinations), "destinations": destinations, "algorithms": algorithms,
            "reps": args.reps, "test_order": {rep: rep_order(algorithms, rep) for rep in range(1, args.reps + 1)},
            "time_s": args.time, "interval_s": args.interval, "retries": args.retries, "attempts": attempts}
    with open(os.path.join(args.out, "run_metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)
    if not rows:
        return

    #save raw samples: full tcp stats, and the goodput-only view
    data = pd.DataFrame(rows)
    data.to_csv(os.path.join(args.out, "tcp_stats.csv"), index=False)
    data[["run_id", "destination", "rep", "algorithm", "time_s", "goodput_bps"]].to_csv(
        os.path.join(args.out, "goodput.csv"), index=False)

    analyze(data, algorithms, args.out, args.representative, args.time)


if __name__ == "__main__":
    main()

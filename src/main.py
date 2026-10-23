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


def active_congestion_control(sock) -> str:
    """Return the congestion-control algorithm the kernel is using on a socket."""
    return sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, 16).split(b"\0")[0].decode()


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
    active = active_congestion_control(sock)
    if active != requested:
        raise RuntimeError(f"requested congestion control '{requested}', but kernel selected '{active}'")
    return active


def validate_congestion_algorithms(algorithms):
    """Fail before running experiments if the local kernel cannot select an algorithm."""
    for algorithm in algorithms:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            set_congestion_control(sock, algorithm)


#read exactly n bytes; recv() may return fewer, and returns b"" once the peer closes
def recv_exact(sock, n) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("server closed connection")
        data += chunk
    return data


def run_test(server, port, experiment_time, interval, congestion_algorithm):
    #both sockets are closed on every exit path, including a failed or rejected test
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client, \
         socket.socket(socket.AF_INET, socket.SOCK_STREAM) as new_client:
        return iperf3_test(client, new_client, server, port, experiment_time, interval, congestion_algorithm)


def iperf3_test(client, new_client, server, port, experiment_time, interval, congestion_algorithm):
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
    algorithm = active_congestion_control(new_client)

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
    recv_exact(client, int.from_bytes(recv_exact(client, 4), "big"))

    #step 11: read DISPLAY_RESULTS (14), send IPERF_DONE (16)
    client.recv(1)
    client.sendall(bytes([16]))

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
def summarize(data: pd.DataFrame, algorithms, out: str):
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
    #a timeout shows as ca_state TCP_CA_Loss (4), or as nonzero RTO back-offs if the sample lands before recovery
    data = data.assign(rto=((data["ca_state"] == 4) | (data["rto_backoffs"] > 0)).astype(int))
    runs = data.groupby(["run_id", "destination", "algorithm"]).agg(
        goodput_mean=("goodput_mbps", "mean"), srtt_mean=("srtt_ms", "mean"),
        queue_delay_mean=("queue_delay_ms", "mean"), retrans_segs=("retrans_segs", "sum"),
        rto=("rto", "max")).reset_index()
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

#pdf to the output directory with the other results, png copy to report/figures for the report (as in HW2)
FIGURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "report", "figures")

def save(fig, out, name):
    fig.savefig(os.path.join(out, f"{name}.pdf"), bbox_inches="tight")
    os.makedirs(FIGURES, exist_ok=True)
    fig.savefig(os.path.join(FIGURES, f"{name}.png"), bbox_inches="tight", dpi=130)
    plt.close(fig)

#q2(b) for one algorithm at the representative destination, one line per repetition;
#lims holds axis ranges shared by every algorithm's figures so they can be compared directly
def plot_tcp_stats(d_data: pd.DataFrame, algorithm: str, out: str, duration: float, lims: dict):
    dest = d_data["destination"].iloc[0]

    #(i) time series: cwnd, rtt, loss proxy, goodput
    fig, axes = plt.subplots(4, 1, figsize=(8, 10), sharex=True)
    for rep, d in d_data.groupby("rep"):
        d = d.sort_values("time_s")
        t, color = d["time_s"], plt.cm.tab10(rep - 1)
        axes[0].plot(t, d["snd_cwnd_segs"], color=color, label=f"rep {rep}")
        axes[1].plot(t, d["srtt_ms"], color=color)
        axes[1].plot(t, d["min_rtt_ms"], "--", color=color, lw=0.8)
        axes[2].plot(t, d["retrans_segs"], "o-", color=color, ms=3, lw=0.8)
        axes[3].plot(t, d["goodput_bps"] / 1e6, color=color)
    for ax, field, label in zip(axes, ["snd_cwnd_segs", "srtt_ms", "retrans_segs", "goodput_mbps"],
                                ["snd_cwnd (segments)", "RTT (ms)\nsrtt solid, min_rtt dashed",
                                 "retransmitted\nsegments / interval", "goodput (Mbit/s)"]):
        ax.set_ylim(lims[field])
        ax.set_ylabel(label)
        ax.grid(alpha=0.3)
    axes[0].legend(loc="upper right", fontsize=8)
    axes[3].set_xlim(lims["time_s"])
    axes[3].set_xlabel("time (s)")
    fig.suptitle(f"TCP stats over time: {dest} ({algorithm})")
    fig.tight_layout()
    save(fig, out, f"tcp_stats_timeseries_{algorithm}")

    #(ii) scatter: cwnd, rtt, loss signal vs goodput, colored by time
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.5), sharey=True)
    for ax, field, label in zip(axes, ["snd_cwnd_segs", "srtt_ms", "retrans_segs"],
                                ["snd_cwnd (segments)", "srtt (ms)", "retransmitted segments / interval"]):
        sc = ax.scatter(d_data[field], d_data["goodput_bps"] / 1e6, c=d_data["time_s"], cmap="viridis",
                        vmin=0, vmax=duration, s=18)
        ax.set_xlim(lims[field])
        ax.set_xlabel(label)
        ax.grid(alpha=0.3)
    axes[0].set_ylim(lims["goodput_mbps"])
    axes[0].set_ylabel("goodput (Mbit/s)")
    fig.colorbar(sc, ax=axes, label="time (s)")
    fig.suptitle(f"TCP stats vs goodput: {dest} ({algorithm}, all repetitions)")
    save(fig, out, f"tcp_stats_scatter_{algorithm}")

#q1(c): goodput over time at every destination for one algorithm, one line per repetition
def plot_goodput(data: pd.DataFrame, algorithm: str, out: str, lims: dict):
    a_data = data[data["algorithm"] == algorithm]
    destinations = list(dict.fromkeys(data["destination"]))
    fig, axes = plt.subplots(len(destinations), 1, figsize=(8, 2.5 * len(destinations)), sharex=True, squeeze=False,
                             layout="constrained")
    for ax, destination in zip(axes[:, 0], destinations):
        for rep, d in a_data[a_data["destination"] == destination].groupby("rep"):
            d = d.sort_values("time_s")
            ax.plot(d["time_s"], d["goodput_bps"] / 1e6, color=plt.cm.tab10(rep - 1), label=f"rep {rep}")
        ax.set_title(destination)
        ax.set_ylabel("Mbit/s")
        ax.set_ylim(lims["goodput_mbps"])
        ax.grid(alpha=0.3)
    axes[0, 0].legend(loc="lower right", fontsize=8)
    axes[-1, 0].set_xlim(lims["time_s"])
    axes[-1, 0].set_xlabel("time (s)")
    fig.suptitle(f"Goodput over time ({algorithm})")
    save(fig, out, f"goodput_{algorithm}")

def analyze(data: pd.DataFrame, algorithms, out: str, duration: float):
    algorithms = [a for a in algorithms if a in set(data["algorithm"])]
    summarize(data, algorithms, out)

    #repeat the tcp stats plots for every algorithm at the same representative destination
    rep = pick_representative(data)
    print(f"representative destination: {rep}")
    rep_data = data[data["destination"] == rep]
    lims = {"time_s": (0, data["time_s"].max()),
            "goodput_mbps": (0, data["goodput_bps"].max() / 1e6 * 1.05),
            "snd_cwnd_segs": (0, rep_data["snd_cwnd_segs"].max() * 1.05),
            "retrans_segs": (0, max(rep_data["retrans_segs"].max(), 1) * 1.05),
            "srtt_ms": (rep_data["min_rtt_ms"].min() * 0.95, rep_data["srtt_ms"].max() * 1.05)}
    for algorithm in algorithms:
        plot_goodput(data, algorithm, out, lims)
        plot_tcp_stats(rep_data[rep_data["algorithm"] == algorithm], algorithm, out, duration, lims)

#main test runner
def main():
    args = parse_args()
    # Preserve the requested order while preventing duplicate runs/plots.
    algorithms = list(dict.fromkeys(args.algorithms))
    os.makedirs(args.out, exist_ok=True)
    if args.replot:
        meta_path = os.path.join(args.out, "run_metadata.json")
        duration = args.time
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                duration = json.load(f)["time_s"]
        analyze(pd.read_csv(os.path.join(args.out, "tcp_stats.csv")), algorithms, args.out, duration)
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

    #raw samples: goodput and decoded tcp stats, one row per sampling interval
    data = pd.DataFrame(rows)
    data.to_csv(os.path.join(args.out, "tcp_stats.csv"), index=False)
    analyze(data, algorithms, args.out, args.time)


if __name__ == "__main__":
    main()

import argparse
import pandas as pd
import socket
import ipaddress
import json
import os
import platform
import struct
import time
import matplotlib.pyplot as plt

DEFAULT_CONGESTION_ALGORITHMS = ("cubic", "reno", "bbr")

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
            "Check /proc/sys/net/ipv4/tcp_available_congestion_control"
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

    #step 5: open a second connection to send data
    new_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_client.settimeout(10)
    algorithm = set_congestion_control(new_client, congestion_algorithm)
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
    return algorithm, samples


def parse_args():
    parser = argparse.ArgumentParser(
        description="iperf3-compatible goodput client"
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
        default=10,
        help="Number of destinations that must complete every requested algorithm (default: 10)",
    )
    parser.add_argument(
        "--time",
        type=int,
        default=60,
        help="time to run each iperf3 test (default: 60s)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="goodput sampling interval in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=30,
        help="max number of servers to try (default: 30)"
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
        choices=DEFAULT_CONGESTION_ALGORITHMS,
        default=list(DEFAULT_CONGESTION_ALGORITHMS),
        help="congestion-control algorithms to compare (default: cubic reno bbr)"
    )
    return parser.parse_args()

#pick one shared destination whose algorithm-balanced mean goodput is the median across destinations
def pick_representative(data: pd.DataFrame) -> str:
    means = (data.groupby(["destination", "algorithm"])["goodput_bps"].mean()
             .groupby("destination").mean().sort_values())
    return means.index[(len(means) - 1) // 2]

#q2(b): time series and scatter plots of tcp stats for one destination
def plot_tcp_stats(d_data: pd.DataFrame, out: str):
    d_data = d_data.sort_values("time_s")
    dest, algorithm = d_data["destination"].iloc[0], d_data["algorithm"].iloc[0]
    t = d_data["time_s"]
    goodput = d_data["goodput_bps"] / 1e6

    #(i) time series: cwnd, rtt, loss proxy, goodput
    fig, axes = plt.subplots(4, 1, figsize=(8, 10), sharex=True)
    axes[0].plot(t, d_data["snd_cwnd_segs"])
    axes[0].set_ylabel("snd_cwnd (segments)")
    axes[1].plot(t, d_data["srtt_ms"], label="srtt")
    axes[1].fill_between(t, d_data["srtt_ms"] - d_data["rttvar_ms"], d_data["srtt_ms"] + d_data["rttvar_ms"],
                         alpha=0.3, label="srtt ± rttvar")
    axes[1].plot(t, d_data["min_rtt_ms"], "--", label="min_rtt")
    axes[1].set_ylabel("RTT (ms)")
    axes[1].legend(loc="upper right", fontsize=8)
    axes[2].bar(t, d_data["retrans_segs"], width=d_data["interval_s"] * 0.8)
    axes[2].set_ylabel("retransmitted\nsegments / interval")
    axes[3].plot(t, goodput)
    axes[3].set_ylabel("goodput (Mbit/s)")
    axes[3].set_xlabel("time (s)")
    fig.suptitle(f"TCP stats over time: {dest} ({algorithm})")
    fig.tight_layout()
    fig.savefig(os.path.join(out, f"tcp_stats_timeseries_{algorithm}.pdf"))
    plt.close(fig)

    #(ii) scatter: cwnd, rtt, loss signal vs goodput, colored by time
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.5), sharey=True)
    for ax, col, label in zip(axes, ["snd_cwnd_segs", "srtt_ms", "retrans_segs"],
                              ["snd_cwnd (segments)", "srtt (ms)", "retransmitted segments / interval"]):
        sc = ax.scatter(d_data[col], goodput, c=t, cmap="viridis", s=18)
        ax.set_xlabel(label)
    axes[0].set_ylabel("goodput (Mbit/s)")
    fig.colorbar(sc, ax=axes, label="time (s)")
    fig.suptitle(f"TCP stats vs goodput: {dest} ({algorithm})")
    fig.savefig(os.path.join(out, f"tcp_stats_scatter_{algorithm}.pdf"), bbox_inches="tight")
    plt.close(fig)


def plot_goodput(data: pd.DataFrame, out: str, algorithm: str):
    """Plot goodput over time for every destination using one congestion algorithm."""
    algorithm_data = data[data["algorithm"] == algorithm]
    destinations = algorithm_data["destination"].unique()
    fig, axes = plt.subplots(len(destinations), 1, figsize=(8, 2.5 * len(destinations)), squeeze=False)
    for ax, destination in zip(axes[:, 0], destinations):
        d_data = algorithm_data[algorithm_data["destination"] == destination].sort_values("time_s")
        ax.plot(d_data["time_s"], d_data["goodput_bps"] / 1e6)
        ax.set_title(destination)
        ax.set_ylabel("Mbit/s")
    axes[-1, 0].set_xlabel("time (s)")
    fig.suptitle(f"Goodput over time ({algorithm})")
    fig.tight_layout()
    fig.savefig(os.path.join(out, f"goodput_{algorithm}.pdf"))
    plt.close(fig)

#main test runner
def main():
    args = parse_args()
    # Preserve the requested order while preventing duplicate runs/plots.
    algorithms = list(dict.fromkeys(args.algorithms))
    try:
        validate_congestion_algorithms(algorithms)
    except RuntimeError as e:
        raise SystemExit(f"error: {e}") from e
    df = process_csv(args.input_csv)

    #try random servers until n complete all algorithms or we run out of attempts
    session = time.strftime("%Y%m%dT%H%M%S")
    rows = []
    attempts = []
    successes = 0
    for server_attempt, (_, row) in enumerate(df.sample(frac=1).head(args.max_attempts).iterrows(), start=1):
        if successes == args.n:
            break
        ip, port = row["IP/HOST"], int(str(row["PORT"]).split("-")[0])
        destination = f"{ip}:{port}"
        destination_rows = []
        destination_succeeded = True
        for algorithm in algorithms:
            run_id = f"{session}-{server_attempt:02d}-{algorithm}"
            try:
                active_algorithm, samples = run_test(ip, port, args.time, args.interval, algorithm)
                for s in samples:
                    destination_rows.append({"run_id": run_id, "destination": destination,
                                             "algorithm": active_algorithm, **s})
                attempts.append({"run_id": run_id, "destination": destination, "status": "ok",
                                 "algorithm": active_algorithm})
                print(f"ok: {destination} ({active_algorithm})")
            except (OSError, RuntimeError) as e:
                attempts.append({"run_id": run_id, "destination": destination, "status": "failed",
                                 "algorithm": algorithm, "error": str(e)})
                print(f"failed: {destination} ({algorithm}: {e})")
                destination_succeeded = False
                break
        if destination_succeeded:
            rows.extend(destination_rows)
            successes += 1
        elif destination_rows:
            print(f"discarding incomplete destination: {destination}")

    if successes < args.n:
        print(f"shortfall: only {successes} of {args.n} servers succeeded")

    #record the run setup, host kernel, and every destination attempted
    os.makedirs(args.out, exist_ok=True)
    meta = {"session": session, "kernel": platform.release(), "requested": args.n, "succeeded": successes,
            "algorithms": algorithms, "time_s": args.time, "interval_s": args.interval, "attempts": attempts}
    with open(os.path.join(args.out, "run_metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)
    if not rows:
        return

    #save raw samples: full tcp stats, and the goodput-only view
    data = pd.DataFrame(rows)
    data.to_csv(os.path.join(args.out, "tcp_stats.csv"), index=False)
    data[["run_id", "destination", "algorithm", "time_s", "goodput_bps"]].to_csv(
        os.path.join(args.out, "goodput.csv"), index=False)


    #summary table (Mbit/s)
    g = data.groupby(["destination", "algorithm"])["goodput_bps"]
    summary = pd.DataFrame({"min": g.min(), "median": g.median(),
                            "mean": g.mean(), "p95": g.quantile(0.95)}) / 1e6
    summary.to_csv(os.path.join(args.out, "summary.csv"))
    print(summary)

    #repeat the goodput plot for each congestion-control algorithm
    destinations = data["destination"].unique()
    for algorithm in algorithms:
        plot_goodput(data, args.out, algorithm)

    #repeat the tcp stats plots for every algorithm at the same representative destination
    rep = args.representative or pick_representative(data)
    if rep not in destinations:
        print(f"representative {rep} has no samples, skipping tcp stats plots")
        return
    print(f"representative destination: {rep}")
    for algorithm in algorithms:
        d_data = data[(data["destination"] == rep) & (data["algorithm"] == algorithm)]
        if d_data.empty:
            print(f"representative {rep} has no {algorithm} samples, skipping its tcp stats plots")
            continue
        plot_tcp_stats(d_data, args.out)


if __name__ == "__main__":
    main()

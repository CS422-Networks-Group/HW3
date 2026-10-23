"""Print the change in dgcc's kernel event counters between two `bpftool -j map dump` outputs."""
import json
import sys

#same order as the enum in bpf/dgcc.bpf.c
NAMES = ["init", "rounds", "timeout", "loss_big", "loss_small", "startup_exit", "inc", "inc_slight",
         "delay_dec", "hold", "bdp_cap", "undo"]

def counters(path):
    dump = json.load(open(path))
    for entry in dump:
        for var in entry.get("formatted", {}).get("datasec", {}).get(".bss", entry.get("formatted", {}).get("value", {}).get(".bss", [])):
            if "dgcc_stats" in var:
                return var["dgcc_stats"]
    raise SystemExit(f"dgcc_stats not found in {path}")

before, after = counters(sys.argv[1]), counters(sys.argv[2])
for name, b, a in zip(NAMES, before, after):
    print(f"{name:>13}: {a - b}")

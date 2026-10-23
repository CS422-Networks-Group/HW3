"""Print the change in dgcc's kernel event counters between two `bpftool -j map dump` outputs.

usage: bpf_stats.py BEFORE.json AFTER.json   (or a single dump to print absolute counts)
"""
import json
import sys

#same order as the enum in bpf/dgcc.bpf.c
NAMES = ["init", "rounds", "timeout", "loss_big", "loss_small", "startup_exit", "inc", "inc_slight",
         "delay_dec", "hold", "bdp_cap", "undo"]

#bpftool's BTF-formatted dump nests the .bss variables a few levels deep; find dgcc_stats wherever it is
def find(node):
    if isinstance(node, dict):
        if "dgcc_stats" in node:
            return node["dgcc_stats"]
        node = list(node.values())
    if isinstance(node, list):
        for child in node:
            found = find(child)
            if found is not None:
                return found
    return None

def counters(path):
    found = find(json.load(open(path)))
    if found is None:
        raise SystemExit(f"dgcc_stats not found in {path}")
    return [int(v) for v in found]

after = counters(sys.argv[-1])
before = counters(sys.argv[1]) if len(sys.argv) > 2 else [0] * len(after)
for name, b, a in zip(NAMES, before, after):
    print(f"{name:>13}: {a - b}")

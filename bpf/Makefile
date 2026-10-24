# Build and (un)register the dgcc BPF struct_ops congestion control.
#   make            -> vmlinux.h + dgcc.bpf.o
#   sudo make load  -> register "dgcc", load tcp_bbr, allow reno cubic bbr dgcc for unprivileged sockets
#   sudo make unload

# Ubuntu's /usr/sbin/bpftool is a wrapper that only works when linux-tools matches the running
# kernel (never true on WSL2), so use the versioned binary from linux-tools-generic directly.
BPFTOOL ?= $(shell ls -1 /usr/lib/linux-tools/*/bpftool 2>/dev/null | sort -V | tail -n 1)
CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
ALLOWED := reno cubic bbr dgcc

.PHONY: all load unload clean check-bpftool

all: dgcc.bpf.o

check-bpftool:
	@test -x "$(BPFTOOL)" || { echo "bpftool not found: apt install linux-tools-generic, or pass BPFTOOL=/path"; exit 1; }

vmlinux.h: | check-bpftool
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Linux 6.10+ calls cong_control(sk, ack, flag, rs) instead of cong_control(sk, rs)
dgcc.bpf.o: dgcc.bpf.c vmlinux.h
	$(CLANG) -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -I. \
		$$(grep -q 'cong_control)(struct sock \*, u32, int' vmlinux.h && echo -DCONG_CONTROL_ACK_FLAG) \
		-c $< -o $@

load: dgcc.bpf.o check-bpftool
	modprobe tcp_bbr
	$(BPFTOOL) struct_ops register dgcc.bpf.o
	sysctl -w net.ipv4.tcp_allowed_congestion_control="$(ALLOWED)"
	cat /proc/sys/net/ipv4/tcp_available_congestion_control

unload: check-bpftool
	$(BPFTOOL) struct_ops unregister name dgcc

clean:
	rm -f dgcc.bpf.o vmlinux.h

// SPDX-License-Identifier: GPL-2.0
/*
 * dgcc: delay + goodput congestion control (CS 422 HW2 Q3(b) design), as a
 * BPF struct_ops tcp_congestion_ops for Linux 6.6.
 *
 * Once per round trip the algorithm compares the smoothed RTT with the
 * fastest recent RTT ("extra delay"), checks for losses and timeouts, and
 * measures the goodput of the round. It then
 *   - on timeout:           cwnd = MIN_CWND, back to start-up
 *   - on loss:              cwnd *= 0.6 if extra delay is large, else 0.9
 *   - in start-up:          double cwnd per round until extra delay is noticeable
 *   - below delay target:   cwnd += 2..8 segments (more when far below target),
 *                           only +1 if the last increase did not raise goodput
 *   - above delay target:   cwnd -= a fraction that grows with the excess (<= 1/2)
 * and keeps MIN_CWND <= cwnd <= 2 * BDP.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define MIN_CWND		4	/* segments */
#define MIN_INC			2	/* additive increase far below target -> MAX_INC */
#define MAX_INC			8
#define SLIGHT_INC		1	/* increase when the last one did not help goodput */
#define LOSS_BIG_PCT		60	/* cwnd kept on loss with large extra delay */
#define LOSS_SMALL_PCT		90	/* cwnd kept on loss with small extra delay */
#define MAX_DECREASE_PCT	50	/* delay-based decrease is never more than half */
#define TARGET_DIV		8	/* target extra delay = base_rtt / 8 ... */
#define TARGET_MIN_US		2000	/* ... clamped to [2 ms, 20 ms] */
#define TARGET_MAX_US		20000
#define BASE_RTT_WIN_US		10000000ULL	/* base RTT = min RTT over the last 10 s */
#define MAX_BW_WIN_ROUNDS	10	/* bandwidth estimate = max round goodput over 10 rounds */
#define BDP_CAP_MULT		2	/* cwnd <= 2 * max_bw * base_rtt */
#define USEC_PER_SEC		1000000ULL

/* TCP_CA_* states from include/net/tcp.h (not in vmlinux.h as an enum on every kernel) */
#define CA_OPEN		0
#define CA_LOSS		4

/* Per-socket state, stored in icsk_ca_priv (at most ICSK_CA_PRIV_SIZE = 104 bytes). */
struct dgcc {
	u64 round_start_us;		/* tcp_mstamp when the current round started */
	u64 base_stamp_us;		/* when base_rtt_us was last refreshed */
	u64 max_bw_bps;			/* max per-round goodput over the last MAX_BW_WIN_ROUNDS */
	u64 prev_goodput_bps;		/* goodput of the previous round */
	u32 next_rtt_delivered;		/* round ends once this packet count is acked */
	u32 round_start_delivered;	/* tp->delivered at round start */
	u32 base_rtt_us;		/* "base delay": fastest recent round trip */
	u32 round_min_rtt_us;		/* fastest RTT sample in the current round */
	u32 round_losses;		/* packets marked lost in the current round */
	u32 prior_cwnd;			/* cwnd before the last loss cut (for undo) */
	u32 max_bw_age;			/* rounds since max_bw_bps was set */
	u8 startup;			/* 1 while in start-up mode */
	u8 last_was_increase;		/* previous round ended with an additive increase */
	u8 hold;			/* rounds to skip decisions after a decrease */
};

/* Global event counters, readable with `bpftool map dump name dgcc_bpf.bss`. */
enum {
	ST_INIT,		/* sockets initialized */
	ST_ROUNDS,		/* rounds evaluated */
	ST_TIMEOUT,		/* RTO -> reset to start-up */
	ST_LOSS_BIG,		/* loss cut to 60% */
	ST_LOSS_SMALL,		/* loss cut to 90% */
	ST_STARTUP_EXIT,	/* start-up left because extra delay was noticeable */
	ST_INC,			/* additive increase */
	ST_INC_SLIGHT,		/* +1 because goodput did not rise */
	ST_DELAY_DEC,		/* delay-based decrease */
	ST_HOLD,		/* rounds skipped after a decrease */
	ST_BDP_CAP,		/* cwnd clamped to 2 * BDP */
	ST_UNDO,		/* spurious-loss undo */
	NR_STATS,
};
u64 dgcc_stats[NR_STATS] = {};

#define STAT(i) __sync_fetch_and_add(&dgcc_stats[i], 1)

static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

static __always_inline struct dgcc *ca_of(const struct sock *sk)
{
	return (void *)((struct inet_connection_sock *)sk)->icsk_ca_priv;
}

static __always_inline bool before(u32 seq1, u32 seq2)
{
	return (s32)(seq1 - seq2) < 0;
}

static __always_inline u32 srtt_us(const struct tcp_sock *tp)
{
	return tp->srtt_us >> 3;
}

static __always_inline void start_round(struct tcp_sock *tp, struct dgcc *ca)
{
	ca->next_rtt_delivered = tp->delivered;
	ca->round_start_delivered = tp->delivered;
	ca->round_start_us = tp->tcp_mstamp;
	ca->round_min_rtt_us = ~0U;
	ca->round_losses = 0;
}

/* Same ratios as the kernel's tcp_update_pacing_rate(): 2x in start-up, 1.2x otherwise.
 * Needed because a cong_control algorithm replaces the call that would set it. */
static __always_inline void set_pacing_rate(struct sock *sk, struct tcp_sock *tp, struct dgcc *ca)
{
	u32 srtt = srtt_us(tp);
	u64 rate;

	if (!srtt)
		return;
	rate = (u64)tp->snd_cwnd * tp->mss_cache * USEC_PER_SEC / srtt;
	rate = ca->startup ? rate * 2 : rate * 6 / 5;
	if (rate > sk->sk_max_pacing_rate)
		rate = sk->sk_max_pacing_rate;
	sk->sk_pacing_rate = rate;
}

SEC("struct_ops/dgcc_init")
void BPF_PROG(dgcc_init, struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dgcc *ca = ca_of(sk);

	/* "Start up with the minimum window size" */
	tp->snd_cwnd = MIN_CWND;
	ca->startup = 1;
	ca->last_was_increase = 0;
	ca->hold = 0;
	ca->base_rtt_us = 0;
	ca->base_stamp_us = 0;
	ca->max_bw_bps = 0;
	ca->max_bw_age = 0;
	ca->prev_goodput_bps = 0;
	ca->prior_cwnd = 0;
	start_round(tp, ca);
	STAT(ST_INIT);
}

/* Called on entry to recovery / RTO. cwnd is managed in cong_control, so leave ssthresh as
 * is (it is set when start-up ends and on each loss cut). */
SEC("struct_ops/dgcc_ssthresh")
u32 BPF_PROG(dgcc_ssthresh, struct sock *sk)
{
	return tcp_sk(sk)->snd_ssthresh;
}

/* The kernel decided the losses were spurious: forget them, and restore the pre-cut cwnd. */
SEC("struct_ops/dgcc_undo_cwnd")
u32 BPF_PROG(dgcc_undo_cwnd, struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dgcc *ca = ca_of(sk);
	u32 cwnd = tp->snd_cwnd;

	ca->round_losses = 0;
	if (ca->prior_cwnd > cwnd)
		cwnd = ca->prior_cwnd;
	ca->prior_cwnd = 0;
	STAT(ST_UNDO);
	return cwnd;
}

/* Step 2: "If the connection timed out: shrink window to minimum, go back to start-up mode." */
SEC("struct_ops/dgcc_set_state")
void BPF_PROG(dgcc_set_state, struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dgcc *ca = ca_of(sk);

	if (new_state != CA_LOSS)
		return;
	tp->snd_cwnd = MIN_CWND;
	ca->startup = 1;
	ca->last_was_increase = 0;
	ca->prior_cwnd = 0;
	/* the retransmissions that follow belong to this timeout, not to a new loss event */
	ca->hold = 1;
	start_round(tp, ca);
	STAT(ST_TIMEOUT);
}

/* End-of-round decision (pseudocode steps 1 and 3-6). Returns the new cwnd. */
static __always_inline u32 dgcc_round(struct sock *sk, struct tcp_sock *tp, struct dgcc *ca, u32 cwnd)
{
	u64 now = tp->tcp_mstamp;
	u64 dur = now - ca->round_start_us;
	u64 goodput = 0, cap;
	u32 srtt = srtt_us(tp), extra, target, inc, dec_pct;

	STAT(ST_ROUNDS);

	/* 1. measure: base delay, current delay, extra delay, goodput */
	if (ca->round_min_rtt_us != ~0U &&
	    (!ca->base_rtt_us || ca->round_min_rtt_us <= ca->base_rtt_us ||
	     now - ca->base_stamp_us > BASE_RTT_WIN_US)) {
		ca->base_rtt_us = ca->round_min_rtt_us;
		ca->base_stamp_us = now;
	}
	if (dur)
		goodput = (u64)(tp->delivered - ca->round_start_delivered) * tp->mss_cache * 8 *
			  USEC_PER_SEC / dur;
	if (goodput >= ca->max_bw_bps || ++ca->max_bw_age > MAX_BW_WIN_ROUNDS) {
		ca->max_bw_bps = goodput;
		ca->max_bw_age = 0;
	}
	extra = srtt > ca->base_rtt_us ? srtt - ca->base_rtt_us : 0;
	target = ca->base_rtt_us / TARGET_DIV;
	if (target < TARGET_MIN_US)
		target = TARGET_MIN_US;
	if (target > TARGET_MAX_US)
		target = TARGET_MAX_US;

	if (ca->hold) {
		/* srtt is an EWMA and still reflects the queue before the last decrease */
		ca->hold--;
		ca->last_was_increase = 0;
		STAT(ST_HOLD);
	} else if (ca->round_losses) {
		/* 3. loss: a real queue (large extra delay) or probably random loss */
		ca->prior_cwnd = cwnd;
		if (extra > target) {
			cwnd = cwnd * LOSS_BIG_PCT / 100;
			STAT(ST_LOSS_BIG);
		} else {
			cwnd = cwnd * LOSS_SMALL_PCT / 100;
			STAT(ST_LOSS_SMALL);
		}
		ca->startup = 0;
		ca->last_was_increase = 0;
		ca->hold = 1;
		tp->snd_ssthresh = cwnd < MIN_CWND ? MIN_CWND : cwnd;
	} else if (ca->startup) {
		/* 4. start-up: cwnd already doubled per ACK during this round; stop once queueing shows */
		if (extra >= target / 2) {
			ca->startup = 0;
			tp->snd_ssthresh = cwnd;
			STAT(ST_STARTUP_EXIT);
		}
	} else if (extra < target) {
		/* 5a. below target: grow more when far below target, less when close */
		inc = MIN_INC + (MAX_INC - MIN_INC) * (target - extra) / target;
		if (ca->last_was_increase && goodput <= ca->prev_goodput_bps) {
			inc = SLIGHT_INC;
			STAT(ST_INC_SLIGHT);
		} else {
			STAT(ST_INC);
		}
		cwnd += inc;
		ca->last_was_increase = 1;
	} else {
		/* 5b. above target: shrink by (extra - target) / (extra + target), at most 1/2 */
		dec_pct = 100 * (extra - target) / (extra + target);
		if (dec_pct > MAX_DECREASE_PCT)
			dec_pct = MAX_DECREASE_PCT;
		cwnd -= cwnd * dec_pct / 100;
		ca->last_was_increase = 0;
		ca->hold = 1;
		STAT(ST_DELAY_DEC);
	}

	/* 6. upper bound: about twice what the path can hold (not applied in start-up, where
	 * the bandwidth estimate lags cwnd by a round) */
	if (!ca->startup && ca->max_bw_bps && ca->base_rtt_us && tp->mss_cache) {
		cap = BDP_CAP_MULT * ca->max_bw_bps * ca->base_rtt_us / (8 * USEC_PER_SEC) / tp->mss_cache;
		if (cap < MIN_CWND)
			cap = MIN_CWND;
		if (cwnd > cap) {
			cwnd = cap;
			STAT(ST_BDP_CAP);
		}
	}

	ca->prev_goodput_bps = goodput;
	start_round(tp, ca);
	return cwnd;
}

SEC("struct_ops/dgcc_cong_control")
void BPF_PROG(dgcc_cong_control, struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dgcc *ca = ca_of(sk);
	u32 cwnd = tp->snd_cwnd;

	if (rs->rtt_us > 0 && (u32)rs->rtt_us < ca->round_min_rtt_us)
		ca->round_min_rtt_us = rs->rtt_us;
	if (rs->losses > 0)
		ca->round_losses += rs->losses;

	/* start-up doubles cwnd once per round trip; growing by the acked packets on every
	 * ACK reaches the same doubling without a burst at the round boundary */
	if (ca->startup && !ca->round_losses && rs->acked_sacked > 0)
		cwnd += rs->acked_sacked;

	/* a round ends once a packet sent after the round started is acked (same test as BBR,
	 * on valid rate samples only) */
	if (rs->delivered >= 0 && rs->interval_us > 0 &&
	    !before(rs->prior_delivered, ca->next_rtt_delivered))
		cwnd = dgcc_round(sk, tp, ca, cwnd);

	if (cwnd < MIN_CWND)
		cwnd = MIN_CWND;
	if (cwnd > tp->snd_cwnd_clamp)
		cwnd = tp->snd_cwnd_clamp;
	tp->snd_cwnd = cwnd;
	set_pacing_rate(sk, tp, ca);
}

SEC(".struct_ops")
struct tcp_congestion_ops dgcc = {
	.init		= (void *)dgcc_init,
	.ssthresh	= (void *)dgcc_ssthresh,
	.undo_cwnd	= (void *)dgcc_undo_cwnd,
	.set_state	= (void *)dgcc_set_state,
	.cong_control	= (void *)dgcc_cong_control,
	.name		= "dgcc",
};

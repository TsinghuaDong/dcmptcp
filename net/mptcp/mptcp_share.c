/*
 *	DCMPTCP SHARE implementation
 *
 *	Authors:
 *	Enhuan Dong <deh13@mails.tsinghua.edu.cn>
 *  Xiaoming Fu <fu@cs.uni-goettingen.de>
 *  Mingwei Xu <xumw@tsinghua.edu.cn>
 *  Yuan Yang <yyang@csnet1.cs.tsinghua.edu.cn>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <net/mptcp.h>


struct share {
    /* lia params*/
	u64	alpha;
	bool	forced_update;
    /* dctcp params*/
    u32 ce_state;
	u32 delayed_ack_reserved;
	u32 prior_rcv_nxt;
    /* share params */
    bool ecn_flag;
};

/****************************lia zone*********************************************/
static int alpha_scale_den = 10;
static int alpha_scale_num = 32;
static int alpha_scale = 12;

static inline int share_sk_can_send(const struct sock *sk)
{
	return mptcp_sk_can_send(sk) && tcp_sk(sk)->srtt_us;
}

static inline u64 mptcp_get_alpha(const struct sock *meta_sk)
{
	return ((struct share *)inet_csk_ca(meta_sk))->alpha;
}

static inline void mptcp_set_alpha(const struct sock *meta_sk, u64 alpha)
{
	((struct share *)inet_csk_ca(meta_sk))->alpha = alpha;
}

static inline u64 share_scale(u32 val, int scale)
{
	return (u64) val << scale;
}

static inline bool mptcp_get_forced(const struct sock *meta_sk)
{
	return ((struct share *)inet_csk_ca(meta_sk))->forced_update;
}

static inline void mptcp_set_forced(const struct sock *meta_sk, bool force)
{
	((struct share *)inet_csk_ca(meta_sk))->forced_update = force;
}

static void share_recalc_alpha(const struct sock *sk)
{
	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	const struct sock *sub_sk;
	int best_cwnd = 0, best_rtt = 0, can_send = 0;
	u64 max_numerator = 0, sum_denominator = 0, alpha = 1;

	if (!mpcb)
		return;

	/* Only one subflow left - fall back to normal reno-behavior
	 * (set alpha to 1)
	 */
	if (mpcb->cnt_established <= 1)
		goto exit;

	/* Do regular alpha-calculation for multiple subflows */

	/* Find the max numerator of the alpha-calculation */
	mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);
		u64 tmp;

		if (!share_sk_can_send(sub_sk))
			continue;

		can_send++;

		/* We need to look for the path, that provides the max-value.
		 * Integer-overflow is not possible here, because
		 * tmp will be in u64.
		 */
		tmp = div64_u64(share_scale(sub_tp->snd_cwnd,
				alpha_scale_num), (u64)sub_tp->srtt_us * sub_tp->srtt_us);

		if (tmp >= max_numerator) {
			max_numerator = tmp;
			best_cwnd = sub_tp->snd_cwnd;
			best_rtt = sub_tp->srtt_us;
		}
	}

	/* No subflow is able to send - we don't care anymore */
	if (unlikely(!can_send))
		goto exit;

	/* Calculate the denominator */
	mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);

		if (!share_sk_can_send(sub_sk))
			continue;

		sum_denominator += div_u64(
				share_scale(sub_tp->snd_cwnd,
						alpha_scale_den) * best_rtt,
						sub_tp->srtt_us);
	}
	sum_denominator *= sum_denominator;
	if (unlikely(!sum_denominator)) {
		pr_err("%s: sum_denominator == 0, cnt_established:%d\n",
		       __func__, mpcb->cnt_established);
		mptcp_for_each_sk(mpcb, sub_sk) {
			struct tcp_sock *sub_tp = tcp_sk(sub_sk);
			pr_err("%s: pi:%d, state:%d\n, rtt:%u, cwnd: %u",
			       __func__, sub_tp->mptcp->path_index,
			       sub_sk->sk_state, sub_tp->srtt_us,
			       sub_tp->snd_cwnd);
		}
	}

	alpha = div64_u64(share_scale(best_cwnd, alpha_scale_num), sum_denominator);

	if (unlikely(!alpha))
		alpha = 1;

exit:
	mptcp_set_alpha(mptcp_meta_sk(sk), alpha);
}

static void mptcp_ccc_init(struct sock *sk)
{
	if (mptcp(tcp_sk(sk))) {
		mptcp_set_forced(mptcp_meta_sk(sk), 0);
		mptcp_set_alpha(mptcp_meta_sk(sk), 1);
	}
	/* If we do not mptcp, behave like reno: return */
}

static void mptcp_ccc_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_LOSS)
		share_recalc_alpha(sk);
}

static void share_set_state(struct sock *sk, u8 ca_state)
{
	if (!mptcp(tcp_sk(sk)))
		return;

	mptcp_set_forced(mptcp_meta_sk(sk), 1);
}

static void share_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct mptcp_cb *mpcb = tp->mpcb;
	int snd_cwnd;

	if (!mptcp(tp)) {
		tcp_reno_cong_avoid(sk, ack, acked);
		return;
	}

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		/* In "safe" area, increase. */
		tcp_slow_start(tp, acked);
		share_recalc_alpha(sk);
		return;
	}

	if (mptcp_get_forced(mptcp_meta_sk(sk))) {
		share_recalc_alpha(sk);
		mptcp_set_forced(mptcp_meta_sk(sk), 0);
	}

	if (mpcb->cnt_established > 1) {
		u64 alpha = mptcp_get_alpha(mptcp_meta_sk(sk));

		/* This may happen, if at the initialization, the mpcb
		 * was not yet attached to the sock, and thus
		 * initializing alpha failed.
		 */
		if (unlikely(!alpha))
			alpha = 1;

		snd_cwnd = (int) div_u64 ((u64) share_scale(1, alpha_scale),
						alpha);

		/* snd_cwnd_cnt >= max (scale * tot_cwnd / alpha, cwnd)
		 * Thus, we select here the max value.
		 */
		if (snd_cwnd < tp->snd_cwnd)
			snd_cwnd = tp->snd_cwnd;
	} else {
		snd_cwnd = tp->snd_cwnd;
	}

	if (tp->snd_cwnd_cnt >= snd_cwnd) {
		if (tp->snd_cwnd < tp->snd_cwnd_clamp) {
			tp->snd_cwnd++;
			share_recalc_alpha(sk);
		}

		tp->snd_cwnd_cnt = 0;
	} else {
		tp->snd_cwnd_cnt++;
	}
}
/****************************lia zone end*********************************************/

/****************************dctcp zone*********************************************/
/* Minimal DCTP CE state machine:
 *
 * S:	0 <- last pkt was non-CE
 *	1 <- last pkt was CE
 */

static void dctcp_ce_state_0_to_1(struct sock *sk)
{
	struct share *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=0 to CE=1 and delayed
	 * ACK has not sent yet.
	 */
	if (!ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=0. */
		tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 1;

	tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
}

static void dctcp_ce_state_1_to_0(struct sock *sk)
{
	struct share *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=1 to CE=0 and delayed
	 * ACK has not sent yet.
	 */
	if (ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=1. */
		tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 0;

	tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
}

static void dctcp_update_ack_reserved(struct sock *sk, enum tcp_ca_event ev)
{
	struct share *ca = inet_csk_ca(sk);

	switch (ev) {
        case CA_EVENT_DELAYED_ACK:
            if (!ca->delayed_ack_reserved)
                ca->delayed_ack_reserved = 1;
            break;
        case CA_EVENT_NON_DELAYED_ACK:
            if (ca->delayed_ack_reserved)
                ca->delayed_ack_reserved = 0;
            break;
        default:
            /* Don't care for the rest. */
            break;
	}
}

static void dctcp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	switch (ev) {
        case CA_EVENT_ECN_IS_CE:
            dctcp_ce_state_0_to_1(sk);
            break;
        case CA_EVENT_ECN_NO_CE:
            dctcp_ce_state_1_to_0(sk);
            break;
        case CA_EVENT_DELAYED_ACK:
        case CA_EVENT_NON_DELAYED_ACK:
            dctcp_update_ack_reserved(sk, ev);
            break;
        default:
            /* Don't care for the rest. */
            break;
	}
}
/****************************dctcp zone end*********************************************/

static void share_init(struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    struct share *ca = inet_csk_ca(sk);

    mptcp_ccc_init(sk);
	if ((tp->ecn_flags & TCP_ECN_OK) ||
            (sk->sk_state == TCP_LISTEN ||
             sk->sk_state == TCP_CLOSE)) {
		ca->prior_rcv_nxt = tp->rcv_nxt;

		ca->delayed_ack_reserved = 0;
		ca->ce_state = 0;
        ca->ecn_flag = 1;
	} else {
        ca->ecn_flag = 0;
    }
}

static void share_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
    struct share *ca = inet_csk_ca(sk);
    if (ca->ecn_flag)
        dctcp_cwnd_event(sk, ev);
    mptcp_ccc_cwnd_event(sk, ev);
}

static u32 share_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
    mptcp_debug("%s:%#x pi: %d ssth called:%u\n", __func__,
                tp->mpcb->mptcp_loc_token, tp->mptcp->path_index, tp->mptcp->dcmptcp_cx);
	return max(tp->snd_cwnd >> 1U, 2U);
}

static struct tcp_congestion_ops share __read_mostly = {
	.init		= share_init,
	.cwnd_event	= share_cwnd_event,
	.ssthresh	= share_ssthresh,
	.cong_avoid	= share_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.set_state	= share_set_state,
	.flags		= TCP_CONG_NEEDS_ECN,
	.owner		= THIS_MODULE,
	.name		= "share",
};


static int __init share_register(void)
{
	BUILD_BUG_ON(sizeof(struct share) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&share);
}

static void __exit share_unregister(void)
{
	tcp_unregister_congestion_control(&share);
}

module_init(share_register);
module_exit(share_unregister);

MODULE_AUTHOR("Enhuan Dong");

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DCMPTCP SHARE");

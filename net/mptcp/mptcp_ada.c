/*
 *	MPTCP Scheduler to reduce FCT in data center networks for inter rack
 *	many-to-one traffic.
 *
 *	Design & Implementation:
 *	Enhuan Dong <deh13@mails.tsinghua.edu.cn>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <net/mptcp.h>

static int ADA_th = 100; /* Unit: KB */

#define START_MOD 0
#define ONESUBFLOW_MOD 1
#define DEFAULT_MOD 2


/* Struct to store the data of the control block */
struct ada_cb_data {
	/* ada scheduler's mode */
	u8 sched_mod;
	/* Threshold to change mode */
	u32 seq_threshold;
    /* The subflow used in ONESUBFLOW_MOD */
    struct tcp_sock *first_subflow;
};

/* Returns the control block data from a given meta socket */
static struct ada_cb_data *ada_get_cb_data(struct tcp_sock *tp)
{
	return (struct ada_cb_data *)&tp->mpcb->mptcp_sched[0];
}


/* In DEFAULT_MOD, ADA degrades to LowRTT. However, LowRTT employs private data 
 * to choose the next segment, so I can't just call mptcp_next_segment. This 
 * makes the code look ugly. ada_mptcp_rcv_buf_optimization, ada__mptcp_next_segment
 * and ada_default_next_segment are copied from mptcp_sched.c with minor modifications.
 * I need to think about how to make mptcp_next_segment and struct defsched_priv
 * accessible by other scheduler, like get_available_subflow.
 * Maybe I can put all these functions and struct defsched_priv into net/mptcp.h...
 */

static struct sk_buff *ada_onesubflow_next_segment(struct sock *meta_sk,
        int *reinject,
        struct sock **subsk,
        unsigned int *limit)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct ada_cb_data *cb_data = ada_get_cb_data(meta_tp);
	struct sk_buff *skb;

    *limit = 0;
    
	if (skb_queue_empty(&mpcb->reinject_queue) &&
            skb_queue_empty(&meta_sk->sk_write_queue))
		/* Nothing to send */
		return NULL;

	/* First try reinjections */
	skb = skb_peek(&mpcb->reinject_queue);
	if (skb && !(mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)) {
		*subsk = get_available_subflow(meta_sk, skb, false);
		if (!*subsk)
			return NULL;
		*reinject = 1;
		return skb;
	}
    
    *reinject = 0;
    skb = tcp_send_head(meta_sk);
    
    if (!skb)
		return NULL;
    
    if (!cb_data->first_subflow) {
        cb_data->first_subflow = mpcb->connection_list;
        if (!cb_data->first_subflow)
            return NULL;
    }
        
    *subsk = (struct sock *)(cb_data->first_subflow);
    if (!mptcp_is_available((struct sock *)cb_data->first_subflow, skb, false)) {
        *subsk = NULL;
        return NULL;
    } else {
        unsigned int mss_now;
        struct tcp_sock *subtp;
        u16 gso_max_segs;
        u32 max_len, max_segs, window, needed;
        
        subtp = tcp_sk(*subsk);
        mss_now = tcp_current_mss(*subsk);

        /* No splitting required, as we will only send one single segment */
        if (skb->len <= mss_now)
            return skb;

        /* The following is similar to tcp_mss_split_point, but
         * we do not care about nagle, because we will anyways
         * use TCP_NAGLE_PUSH, which overrides this.
         *
         * So, we first limit according to the cwnd/gso-size and then according
         * to the subflow's window.
         */

        gso_max_segs = (*subsk)->sk_gso_max_segs;
        if (!gso_max_segs) /* No gso supported on the subflow's NIC */
            gso_max_segs = 1;
        max_segs = min_t(unsigned int, tcp_cwnd_test(subtp, skb), gso_max_segs);
        if (!max_segs)
            return NULL;

        max_len = mss_now * max_segs;
        window = tcp_wnd_end(subtp) - subtp->write_seq;

        needed = min(skb->len, window);
        if (max_len <= skb->len)
            /* Take max_win, which is actually the cwnd/gso-size */
            *limit = max_len;
        else
            /* Or, take the window */
            *limit = needed;
        
        return skb;
    }
}

static struct sk_buff *ada_next_segment(struct sock *meta_sk,
                                       int *reinject,
                                       struct sock **subsk,
                                       unsigned int *limit)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct ada_cb_data *cb_data = ada_get_cb_data(meta_tp);
	struct sk_buff *skb = tcp_send_head(meta_sk);
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *tmp_sk = NULL;
	
	if (cb_data->sched_mod == START_MOD) {
		if (!skb)
			return NULL;
		
		cb_data->sched_mod = ONESUBFLOW_MOD;
		/* It should be okay to use TCP_SKB_CB(skb)->seq */
		cb_data->seq_threshold = meta_tp->snd_nxt + ADA_th * 1024;

		/* dcmptcp: debug */
		mptcp_debug("%s: mod %u th %u esfn:%u sfn:%u token %#x\n",
                    __func__ , cb_data->sched_mod, cb_data->seq_threshold,
                    mpcb->cnt_established, mpcb->cnt_subflows, mpcb->mptcp_loc_token);

		return ada_onesubflow_next_segment(meta_sk, reinject, subsk, limit);
	}

	if (cb_data->sched_mod == ONESUBFLOW_MOD) {
		if (!before(meta_tp->snd_nxt, cb_data->seq_threshold)) {
			mptcp_for_each_sk(mpcb, tmp_sk) {
				struct defsched_priv *sk_data = defsched_get_priv(tcp_sk(tmp_sk));
				sk_data->last_rbuf_opti = tcp_jiffies32; /* Real initialization */
				/* dcmptcp: debug */
				mptcp_debug("%s: alert pi:%u %p lr:%u esfn:%u sfn:%u token %#x\n",
                            __func__ , tcp_sk(tmp_sk)->mptcp->path_index,
                            sk_data, sk_data->last_rbuf_opti, mpcb->cnt_established,
                            mpcb->cnt_subflows, mpcb->mptcp_loc_token);
			}
			cb_data->sched_mod = DEFAULT_MOD;

			return mptcp_next_segment(meta_sk, reinject, subsk, limit);
		}

		return ada_onesubflow_next_segment(meta_sk, reinject, subsk, limit);			
	}

	/* DEFAULT_MOD */
	return mptcp_next_segment(meta_sk, reinject, subsk, limit);

}


static void ada_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct defsched_priv *sk_data = defsched_get_priv(tp);
	
	sk_data->last_rbuf_opti = tcp_jiffies32; /* Fake initialization */
}

static void ada_release(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ada_cb_data *cb_data = ada_get_cb_data(tp);

	/* Check if the next subflow would be the released one. If yes correct
	 * the pointer
	 */
	if (cb_data->first_subflow == tp)
		cb_data->first_subflow = NULL;
}

static struct sock *ada_get_subflow(struct sock *meta_sk,
                                   struct sk_buff *skb,
                                   bool zero_wnd_test)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct ada_cb_data *cb_data = ada_get_cb_data(meta_tp);

	if (cb_data->sched_mod == DEFAULT_MOD) {
		return get_available_subflow(meta_sk, skb, zero_wnd_test);
	} else {
        if (!cb_data->first_subflow) {
            cb_data->first_subflow = tcp_sk(meta_sk)->mpcb->connection_list;
        }
		return (struct sock *)cb_data->first_subflow;
	}
}

struct mptcp_sched_ops mptcp_sched_ada = {
	.get_subflow = ada_get_subflow,
	.next_segment = ada_next_segment,
	.release = ada_release,
	.init = ada_init,
	.name = "ada",
	.owner = THIS_MODULE,
};

static int __init ada_register(void)
{
	BUILD_BUG_ON(sizeof(struct defsched_priv) > MPTCP_SCHED_SIZE);
	BUILD_BUG_ON(sizeof(struct ada_cb_data) > MPTCP_SCHED_DATA_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_ada))
		return -1;

	return 0;
}

static void ada_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_ada);
}

module_init(ada_register);
module_exit(ada_unregister);

MODULE_AUTHOR("Enhuan Dong");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ADA MPTCP");
MODULE_VERSION("0.94");

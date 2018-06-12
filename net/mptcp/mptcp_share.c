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



static struct tcp_congestion_ops share __read_mostly = {
	.init		= share_init,
	.cwnd_event	= dctcp_cwnd_event,mptcp_ccc_cwnd_event
	.ssthresh	= share_ssthresh,
	.cong_avoid	= mptcp_ccc_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.set_state	= mptcp_ccc_set_state,
	.flags		= TCP_CONG_NEEDS_ECN,
	.owner		= THIS_MODULE,
	.name		= "share",
};

static struct tcp_congestion_ops share_lia __read_mostly = {
	.init		= mptcp_ccc_init,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= mptcp_ccc_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.cwnd_event	= mptcp_ccc_cwnd_event,
	.set_state	= mptcp_ccc_set_state,
	.owner		= THIS_MODULE,
	.name		= "share_lia",
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

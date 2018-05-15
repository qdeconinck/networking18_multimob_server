/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

/*
 * Should be based on tcp_sock->rcv_tstamp
 */

#include <linux/module.h>
#include <net/mptcp.h>


struct serversched_priv {
	u32	last_rbuf_opti;
};

static struct serversched_priv *serversched_get_priv(const struct tcp_sock *tp)
{
	return (struct serversched_priv *)&tp->mptcp->mptcp_sched[0];
}

static bool mptcp_is_def_unavailable(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return true;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return true;

	if (tp->pf)
		return true;

	return false;
}

static bool mptcp_is_temp_unavailable(struct sock *sk,
				      const struct sk_buff *skb,
				      bool zero_wnd_test)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int mss_now, space, in_flight;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been
		 * acked. (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return true;
		else if (tp->snd_una != tp->high_seq)
			return true;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return true;
	}

	/* If TSQ is already throttling us, do not send on this subflow. When
	 * TSQ gets cleared the subflow becomes eligible again.
	 */
	if (test_bit(TSQ_THROTTLED, &tp->tsq_flags))
		return true;

	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= tp->snd_cwnd)
		return true;

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	if (tp->write_seq - tp->snd_nxt > space)
		return true;

	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return true;

	mss_now = tcp_current_mss(sk);

	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (skb && !zero_wnd_test &&
	    after(tp->write_seq + min(skb->len, mss_now), tcp_wnd_end(tp)))
		return true;

	return false;
}

/* Is the sub-socket sk available to send the skb? */
static bool mptcp_is_available(struct sock *sk, const struct sk_buff *skb,
			       bool zero_wnd_test)
{
	return !mptcp_is_def_unavailable(sk) &&
	       !mptcp_is_temp_unavailable(sk, skb, zero_wnd_test);
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_dont_reinject_skb(const struct tcp_sock *tp, const struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}

static bool subflow_is_backup(const struct tcp_sock *tp)
{
	return tp->mptcp->rcv_low_prio || tp->mptcp->low_prio;
}

static bool subflow_is_active(const struct tcp_sock *tp)
{
	return !tp->mptcp->rcv_low_prio && !tp->mptcp->low_prio;
}

/* Generic function to iterate over used and unused subflows and to select the
 * best one
 */
static struct sock
*get_subflow_from_selectors(struct mptcp_cb *mpcb, struct sk_buff *skb,
			    bool (*selector)(const struct tcp_sock *),
			    bool zero_wnd_test, bool *force)
{
	struct sock *bestsk = NULL;
	u32 min_srtt = 0xffffffff;
	bool found_unused = false;
	bool found_unused_una = false;
	struct sock *sk;

	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);
		bool unused = false;

		/* First, we choose only the wanted sks */
		if (!(*selector)(tp))
			continue;

		if (!mptcp_dont_reinject_skb(tp, skb))
			unused = true;
		else if (found_unused)
			/* If a unused sk was found previously, we continue -
			 * no need to check used sks anymore.
			 */
			continue;

		if (mptcp_is_def_unavailable(sk))
			continue;

		if (mptcp_is_temp_unavailable(sk, skb, zero_wnd_test)) {
			if (unused)
				found_unused_una = true;
			continue;
		}

		if (unused) {
			if (!found_unused) {
				/* It's the first time we encounter an unused
				 * sk - thus we reset the bestsk (which might
				 * have been set to a used sk).
				 */
				min_srtt = 0xffffffff;
				bestsk = NULL;
			}
			found_unused = true;
		}

		if (tp->srtt_us < min_srtt) {
			min_srtt = tp->srtt_us;
			bestsk = sk;
		}
	}

	if (bestsk) {
		/* The force variable is used to mark the returned sk as
		 * previously used or not-used.
		 */
		if (found_unused)
			*force = true;
		else
			*force = false;
	} else {
		/* The force variable is used to mark if there are temporally
		 * unavailable not-used sks.
		 */
		if (found_unused_una)
			*force = true;
		else
			*force = false;
	}

	return bestsk;
}

static struct sock *get_server_available_subflow(struct mptcp_cb *mpcb,
				struct sk_buff *skb, bool zero_wnd_test, bool *found)
{
	struct sock *sk, *lastsk = NULL;
	struct tcp_sock *tp;
	u32 last_new_rcv_tstamp = 0;
	u32 last_new_rcv_regular_tstamp = 0;
	int best_high_rto = 0;
	int best_was_bad = 0;

	*found = false;
	/* First explore regular paths */
	mptcp_for_each_sk(mpcb, sk) {
		tp = tcp_sk(sk);
		if (!subflow_is_active(tp))
			continue;
		if (time_after((unsigned long)tp->mptcp_new_last_tstamp, (unsigned long)last_new_rcv_tstamp))
		{
			//printk(KERN_ALERT "Path index %d has the last timestamp: %d\n", tcp_sk(sk)->mptcp->path_index, tcp_sk(sk)->mptcp_new_last_tstamp);
			if (mptcp_is_def_unavailable(sk))
				continue;
			if (mptcp_dont_reinject_skb(tp, skb))
				continue;

			/* If the bestsk does not have high rto, but this one yes, don't consider it anymore */
			if (lastsk && !best_high_rto && tp->high_rto)
				continue;

			/* If the bestsk was not declared bad before, but this one yes, don't consider it anymore */
			if (lastsk && !best_was_bad && tp->was_bad)
				continue;

			last_new_rcv_regular_tstamp = tp->mptcp_new_last_tstamp;
			best_high_rto = tp->high_rto;
			best_was_bad = tp->was_bad;
			if (mptcp_is_temp_unavailable(sk, skb, zero_wnd_test))
				continue;
			*found = true;
			lastsk = sk;
			last_new_rcv_tstamp = tp->mptcp_new_last_tstamp;
		}
	}

	/* If there is a regular path that should be selected but its cwnd if full,
	 * avoid considering backup subflows having time lower than this one */
	if (!best_high_rto && !best_was_bad && time_after((unsigned long)last_new_rcv_regular_tstamp, (unsigned long)last_new_rcv_tstamp))
		last_new_rcv_tstamp = last_new_rcv_regular_tstamp;

	/* Then explore all paths */
	mptcp_for_each_sk(mpcb, sk) {
		tp = tcp_sk(sk);
		if (time_after((unsigned long)tp->mptcp_new_last_tstamp, (unsigned long)last_new_rcv_tstamp))
		{
			//printk(KERN_ALERT "Path index %d has the last timestamp: %d\n", tcp_sk(sk)->mptcp->path_index, tcp_sk(sk)->mptcp_new_last_tstamp);
			if (mptcp_is_def_unavailable(sk))
				continue;
			if (mptcp_dont_reinject_skb(tp, skb))
				continue;
			/* If the bestsk does not have high rto, but this one yes, don't consider it anymore */
			if (lastsk && !best_high_rto && tp->high_rto)
				continue;

			/* If the bestsk was not declared bad before, but this one yes, don't consider it anymore */
			if (lastsk && !best_was_bad && tp->was_bad)
				continue;

			best_high_rto = tp->high_rto;
			best_was_bad = tp->was_bad;

			*found = true;
			if (mptcp_is_temp_unavailable(sk, skb, zero_wnd_test))
				continue;

			lastsk = sk;
			last_new_rcv_tstamp = tcp_sk(sk)->mptcp_new_last_tstamp;
		}
	}

	return lastsk;
}

/* This is the scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the shortest RTT.
 * If all paths have full cong windows, we simply return NULL.
 *
 * Additionally, this function is aware of the backup-subflows.
 */
static struct sock *server_get_available_subflow(struct sock *meta_sk,
					  struct sk_buff *skb,
					  bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk;
	bool found;

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		sk = (struct sock *)mpcb->connection_list;
		if (!mptcp_is_available(sk, skb, zero_wnd_test))
			sk = NULL;
		return sk;
	}

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_is_available(sk, skb, zero_wnd_test))
				return sk;
		}
	}

	return get_server_available_subflow(mpcb, skb, zero_wnd_test, &found);

	//if (found)
	//{
	//	return sk;
	//}

	/* Find the best subflow */
	//sk = get_subflow_from_selectors(mpcb, skb, &subflow_is_active,
	//				zero_wnd_test, &force);
	//if (force)
		/* one unused active sk or one NULL sk when there is at least
		 * one temporally unavailable unused active sk
		 */
	//	return sk;

	//sk = get_subflow_from_selectors(mpcb, skb, &subflow_is_backup,
	//				zero_wnd_test, &force);
	//if (!force)
		/* one used backup sk or one NULL sk where there is no one
		 * temporally unavailable unused backup sk
		 *
		 * the skb passed through all the available active and backups
		 * sks, so clean the path mask
		 */
	//	TCP_SKB_CB(skb)->path_mask = 0;
	//return sk;
}

static struct sk_buff *mptcp_rcv_buf_optimization(struct sock *sk, int penal)
{
	struct sock *meta_sk;
	const struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sock *tp_it;
	struct sk_buff *skb_head;
	struct serversched_priv *dsp = serversched_get_priv(tp);

	if (tp->mpcb->cnt_subflows == 1)
		return NULL;

	meta_sk = mptcp_meta_sk(sk);
	skb_head = tcp_write_queue_head(meta_sk);

	if (!skb_head || skb_head == tcp_send_head(meta_sk))
		return NULL;

	/* If penalization is optional (coming from mptcp_next_segment() and
	 * We are not send-buffer-limited we do not penalize. The retransmission
	 * is just an optimization to fix the idle-time due to the delay before
	 * we wake up the application.
	 */
	if (!penal && sk_stream_memory_free(meta_sk))
		goto retrans;

	/* Only penalize again after an RTT has elapsed */
	if (tcp_time_stamp - dsp->last_rbuf_opti < usecs_to_jiffies(tp->srtt_us >> 3))
		goto retrans;

	/* Half the cwnd of the slow flow */
	mptcp_for_each_tp(tp->mpcb, tp_it) {
		if (tp_it != tp &&
		    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
			if (tp->srtt_us < tp_it->srtt_us && inet_csk((struct sock *)tp_it)->icsk_ca_state == TCP_CA_Open) {
				u32 prior_cwnd = tp_it->snd_cwnd;

				tp_it->snd_cwnd = max(tp_it->snd_cwnd >> 1U, 1U);

				/* If in slow start, do not reduce the ssthresh */
				if (prior_cwnd >= tp_it->snd_ssthresh)
					tp_it->snd_ssthresh = max(tp_it->snd_ssthresh >> 1U, 2U);

				dsp->last_rbuf_opti = tcp_time_stamp;
			}
			break;
		}
	}

retrans:

	/* Segment not yet injected into this path? Take it!!! */
	if (!(TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp->mptcp->path_index))) {
		bool do_retrans = false;
		mptcp_for_each_tp(tp->mpcb, tp_it) {
			if (tp_it != tp &&
			    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
				if (tp_it->snd_cwnd <= 4) {
					do_retrans = true;
					break;
				}

				if (4 * tp->srtt_us >= tp_it->srtt_us) {
					do_retrans = false;
					break;
				} else {
					do_retrans = true;
				}
			}
		}

		if (do_retrans && mptcp_is_available(sk, skb_head, false))
			return skb_head;
	}
	return NULL;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__mptcp_next_segment(struct sock *meta_sk, int *reinject)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		*reinject = 1;
	} else {
		skb = tcp_send_head(meta_sk);

		if (!skb && meta_sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &meta_sk->sk_socket->flags) &&
		    sk_stream_wspace(meta_sk) < sk_stream_min_wspace(meta_sk)) {
			struct sock *subsk = server_get_available_subflow(meta_sk, NULL,
								   false);
			if (!subsk)
				return NULL;

			skb = mptcp_rcv_buf_optimization(subsk, 0);
			if (skb)
				*reinject = -1;
		}
	}
	return skb;
}

static struct sk_buff *mptcp_server_next_segment(struct sock *meta_sk,
					  int *reinject,
					  struct sock **subsk,
					  unsigned int *limit)
{
	struct sk_buff *skb = __mptcp_next_segment(meta_sk, reinject);
	unsigned int mss_now;
	struct tcp_sock *subtp;
	u16 gso_max_segs;
	u32 max_len, max_segs, window, needed;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	*subsk = server_get_available_subflow(meta_sk, skb, false);
	if (!*subsk)
		return NULL;

	subtp = tcp_sk(*subsk);
	mss_now = tcp_current_mss(*subsk);

	if (!*reinject && unlikely(!tcp_snd_wnd_test(tcp_sk(meta_sk), skb, mss_now))) {
		skb = mptcp_rcv_buf_optimization(*subsk, 1);
		if (skb)
			*reinject = -1;
		else
			return NULL;
	}

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

static void serversched_init(struct sock *sk)
{
	struct serversched_priv *dsp = serversched_get_priv(tcp_sk(sk));

	dsp->last_rbuf_opti = tcp_time_stamp;
}

static struct mptcp_sched_ops mptcp_sched_server = {
	.get_subflow = server_get_available_subflow,
	.next_segment = mptcp_server_next_segment,
	.init = serversched_init,
	.name = "server",
	.owner = THIS_MODULE,
};

static int __init server_register(void)
{
	BUILD_BUG_ON(sizeof(struct serversched_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_server))
		return -1;

	return 0;
}

static void server_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_server);
}

module_init(server_register);
module_exit(server_unregister);

MODULE_AUTHOR("Quentin De Coninck");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SERVER SCHEDULER");
MODULE_VERSION("0.90");

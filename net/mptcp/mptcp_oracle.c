/* MPTCP Oracle */

#include <net/tcp.h>
#include <net/mptcp.h>

#include <linux/module.h>

#include <linux/interrupt.h>
#include <linux/hrtimer.h>
#include <linux/sched.h>

#define MULTIPLIER_VAL	1000000
#define MULTIPLIER_VOL	1000
#define ALPHA_DIV	1000

static LIST_HEAD(entry_list);

static struct hrtimer htimer;
static ktime_t kt_period;

static int timer_period_ms __read_mostly = 1000;
module_param(timer_period_ms, int, 0644);
MODULE_PARM_DESC(timer_period_ms, "Timer to update oracle info");

static int alpha __read_mostly = 500;
module_param(alpha, int, 0644);
MODULE_PARM_DESC(alpha, "Alpha value for EMA, divided by 1000");

static int sloss_threshold __read_mostly = 250;
module_param(sloss_threshold, int, 0644);
MODULE_PARM_DESC(sloss_threshold, "Threshold rate for smoothed loss, divided by 1000, <= 0 disable it");

static int sretrans_threshold __read_mostly = 500;
module_param(sretrans_threshold, int, 0644);
MODULE_PARM_DESC(sretrans_threshold, "Threshold rate for smoothed retransmissions, divided by 1000, <= 0 disable it");

static int rto_ms_threshold __read_mostly = 1500;
module_param(rto_ms_threshold, int, 0644);
MODULE_PARM_DESC(rto_ms_threshold, "Max RTO (in ms) on non-backup subflow before fast joining on backup, <= 0 disable it");

static int idle_periods_threshold __read_mostly = 0;
module_param(idle_periods_threshold, int, 0644);
MODULE_PARM_DESC(idle_periods_threshold, "Threshold of periods with path idle, <= 0 disable it");

static inline void pr_info_entry(const struct mptcp_oracle_entry *entry,
				 const char *func)
{
	switch (entry->ips.family)
	{
	case AF_INET:
		if (entry->dev)
			pr_info("%s: path between %pI4 and %pI4 on %s\n",
				func,
				&entry->ips.u.ip4.saddr,
				&entry->ips.u.ip4.daddr, entry->dev->name);
		else
			pr_info("%s: path between %pI4 and %pI4 no dev\n",
				func,
				&entry->ips.u.ip4.saddr,
				&entry->ips.u.ip4.saddr);
		break;
#ifdef CONFIG_IPV6
	case AF_INET6:
		if (entry->dev)
			pr_info("%s: path between %pI6 and %pI6 on %s\n",
				func,
				&entry->ips.u.ip6.saddr,
				&entry->ips.u.ip6.daddr, entry->dev->name);
		else
			pr_info("%s: path between %pI6 abd %pI6 no dev\n",
				func,
				&entry->ips.u.ip6.saddr,
				&entry->ips.u.ip6.daddr);
		break;
#endif
	}
}

static bool is_loopback_v4_connection(struct flowi4 *fl4)
{
	return ipv4_is_loopback(fl4->saddr) || ipv4_is_loopback(fl4->daddr);
}

#ifdef CONFIG_IPV6
static bool is_loopback_v6_connection(struct flowi6 *fl6)
{
	return (ipv6_addr_cmp(&fl6->saddr, &in6addr_loopback) == 0)
		|| (ipv6_addr_cmp(&fl6->daddr, &in6addr_loopback) == 0);
}
#endif

static bool is_loopback_connection(struct flowi *fl, unsigned short family)
{
	switch (family)
	{
	case AF_INET:
		return is_loopback_v4_connection(&fl->u.ip4);
		break;
#ifdef CONFIG_IPV6
	case AF_INET6:
		return is_loopback_v6_connection(&fl->u.ip6);
		break;
#endif
	default:
		return false;
	}
}

static bool is_any_v4_connection(struct flowi4 *fl4)
{
	return ipv4_is_zeronet(fl4->saddr) && ipv4_is_zeronet(fl4->daddr);
}

#ifdef CONFIG_IPV6
static bool is_any_v6_connection(struct flowi6 *fl6)
{
	return (ipv6_addr_cmp(&fl6->saddr, &in6addr_any) == 0)
		&& (ipv6_addr_cmp(&fl6->daddr, &in6addr_any) == 0);
}
#endif

static bool is_any_connection(struct flowi *fl, unsigned short family)
{
	switch (family)
	{
	case AF_INET:
		return is_any_v4_connection(&fl->u.ip4);
		break;
#ifdef CONFIG_IPV6
	case AF_INET6:
		return is_any_v6_connection(&fl->u.ip6);
		break;
#endif
	default:
		return false;
	}
}

static struct mptcp_oracle_entry *lookup_entry_v4(struct net_device *dev, struct flowi4 *fl4)
{
	struct mptcp_oracle_entry *entry;
	list_for_each_entry(entry, &entry_list, list) {
		if (entry->ips.family == AF_INET) {
			if (entry->dev == dev && entry->ips.u.ip4.saddr == fl4->saddr
			    && entry->ips.u.ip4.daddr == fl4->daddr) {
				return entry;
			}
		}
	}
	return NULL;
}

#ifdef CONFIG_IPV6
static struct mptcp_oracle_entry *lookup_entry_v6(struct net_device *dev, struct flowi6 *fl6)
{
	struct mptcp_oracle_entry *entry;
	list_for_each_entry(entry, &entry_list, list) {
		if (entry->ips.family == AF_INET6) {
			if (entry->dev == dev
			    && ipv6_addr_cmp(&entry->ips.u.ip6.saddr, &fl6->saddr) == 0
			    && ipv6_addr_cmp(&entry->ips.u.ip6.daddr, &fl6->daddr) == 0) {
				return entry;
			}
		}
	}
	return NULL;
}
#endif

static struct mptcp_oracle_entry *lookup_entry(struct net_device *dev, struct flowi *fl,
					       unsigned short family)
{
	if (list_empty(&entry_list)) {
		return NULL;
	}
	switch (family)
	{
	case AF_INET:
		return lookup_entry_v4(dev, &fl->u.ip4);
		break;
#ifdef CONFIG_IPV6
	case AF_INET6:
		return lookup_entry_v6(dev, &fl->u.ip6);
		break;
#endif
	default:
		return NULL;
	}
}

static void __mptcp_oracle_del_entry(struct tcp_sock *tp, struct tcp_sk_entry *tp_entry)
{
	list_del(&tp_entry->list);
	tp->oracle_tp_entry = NULL;
	tp->oracle_entry = NULL;
	kfree(tp_entry);
}

void mptcp_oracle_add_entry_del_meta(struct sock *sk, struct sock *meta_sk)
{
	struct mptcp_oracle_entry *entry;
	struct inet_sock *inet = inet_sk(sk);
	struct flowi *fl = &inet->cork.fl;
	unsigned short family = sk->sk_family;
	struct dst_entry *dst;
	struct net_device *dev = NULL;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sk_entry *tp_entry;

	/* Avoid adding flows on loopback */
	if (is_loopback_connection(fl, family))
		return;

	/* Connections fully on any should not be tracked */
	if (is_any_connection(fl, family))
		return;

	if (meta_sk)
		/* Nothing may be sent on the sk yet; take meta info */
		dst = meta_sk->sk_dst_cache;
	else
		dst = sk->sk_dst_cache;

	if (dst)
		dev = dst->dev;

	if (meta_sk && tcp_sk(meta_sk)->oracle_entry) {
		struct tcp_sock *meta_tp = tcp_sk(meta_sk);
		struct tcp_sk_entry *meta_tp_entry = meta_tp->oracle_tp_entry;
		/* Put meta_sk info to sk and remove meta_sk from the list
		 * Note that the meta_sk and sk should actually share the same
		 * entry
		 */
		entry = meta_tp->oracle_entry;
		__mptcp_oracle_del_entry(meta_tp, meta_tp_entry);
	} else
		entry = lookup_entry(dev, fl, family);

	if (!entry) {
		pr_debug("Entry not found, create it\n");
		/* Better put everything to zero */
		entry = kzalloc(sizeof(struct mptcp_oracle_entry), GFP_ATOMIC);
		if (!entry) {
			pr_alert("Not enough memory to allocate entry!\n");
			return;
		}
		entry->dev = dev;
		entry->ips.family = family;
		if (family == AF_INET) {
			entry->ips.u.ip4.saddr = fl->u.ip4.saddr;
			entry->ips.u.ip4.daddr = fl->u.ip4.daddr;
		}
#ifdef CONFIG_IPV6
		else if (family == AF_INET6) {
			entry->ips.u.ip6.saddr = fl->u.ip6.saddr;
			entry->ips.u.ip6.daddr = fl->u.ip6.daddr;
		}
#endif
		INIT_LIST_HEAD(&entry->tcp_sk_list_head);
		list_add(&entry->list, &entry_list);
	}

	tp_entry = kzalloc(sizeof(struct tcp_sk_entry), GFP_ATOMIC);
	if (!tp_entry) {
		pr_alert("Not enough memory to allocate tp_entry!\n");
		kfree(entry);
		return;
	}
	tp_entry->tp = tp;
	pr_debug("Add tp %p with family %d to the list\n", tp, family);
	list_add(&tp_entry->list, &entry->tcp_sk_list_head);

	/* Make a link between the tp and the entry for quick access */
	tp->oracle_entry = entry;
	tp->oracle_tp_entry = tp_entry;
}

void mptcp_oracle_add_entry(struct sock *sk, struct sock *meta_sk, bool is_master_sk)
{
	return is_master_sk ?
		mptcp_oracle_add_entry_del_meta(sk, meta_sk)
		: mptcp_oracle_add_entry_del_meta(sk, NULL);
}

void mptcp_oracle_add_dev_to_entry(struct sock *sk, struct mptcp_oracle_entry *entry, struct tcp_sk_entry *tp_entry)
{
	struct dst_entry *dst;
	struct net_device *dev;

	if (!entry || !tp_entry)
		return;

	dst = sk->sk_dst_cache;
	if (!dst)
		return;

	dev = dst->dev;

	if (entry->dev == dev)
		return;

	/* Remove the previous entry with dummy dev and create a new one */
	mptcp_oracle_del_entry(sk);
	mptcp_oracle_add_entry_del_meta(sk, NULL);
}

void mptcp_oracle_del_entry(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_oracle_entry *entry = tp->oracle_entry;
	struct tcp_sk_entry *tp_entry = tp->oracle_tp_entry;

	if (!entry || !tp_entry)
		return;

	/* We need to ignore meta_sks, otherwise lists may be freed twice... */
	if (is_meta_sk(sk))
		return;

	__mptcp_oracle_del_entry(tp, tp_entry);

	if (list_empty(&entry->tcp_sk_list_head)) {
		pr_debug("Entry has no connection associated, should it be removed?\n");
	}
}

static void request_fast_join_all_tps(struct mptcp_oracle_entry *entry, bool declare_bad)
{
	struct tcp_sk_entry *tp_entry;
	struct tcp_sock *tp;
	list_for_each_entry(tp_entry, &entry->tcp_sk_list_head, list) {
		tp = tp_entry->tp;
		/* Consider the path as potentially failed, if not yet done,
		 * only if the entry was not considered bad before. Avoid
		 * starving connection by declaring backups as potentially
		 * failed
		 */
		if (!entry->declared_bad && declare_bad && (!mptcp(tp) || !mptcp_subflow_is_backup(tp))) {
			tp->pf = 1;
			tp->was_bad = 1;
		}
		/* Ignore non-MPTCP connections */
		if (!mptcp(tp))
			continue;
		/* Don't request fastjoin if not needed */
		if (!mptcp_should_request_fastjoin(tp))
			continue;
		if (tp->mpcb->pm_ops->push_info) {
			int have_bup;
			tp->mpcb->pm_ops->push_info(tp->meta_sk, MPTCP_HAVE_BUP, &have_bup);
			if (have_bup)
				mptcp_request_fast_join(tp->meta_sk, tp->mpcb);
		}
	}
	entry->declared_bad = 1;
}

static void sloss_threshold_exceeded(struct mptcp_oracle_entry *entry)
{
	pr_info_entry(entry, __func__);
	request_fast_join_all_tps(entry, true);
}

static void sretrans_threshold_exceeded(struct mptcp_oracle_entry *entry)
{
	pr_info_entry(entry, __func__);
	request_fast_join_all_tps(entry, true);
}

static void rto_threshold_exceeded(struct mptcp_oracle_entry *entry)
{
	pr_info_entry(entry, __func__);
	request_fast_join_all_tps(entry, false);
}

static void idle_periods_threshold_exceeded(struct mptcp_oracle_entry *entry)
{
	/* Select one subflow on which keepalive will be enabled */
	struct tcp_sk_entry *tp_entry;
	struct tcp_sock *tp, *meta_tp;
	struct sock *meta_sk;
	pr_debug("Idle detected\n");
	if (idle_periods_threshold < 1)
		return;

	list_for_each_entry(tp_entry, &entry->tcp_sk_list_head, list) {
		tp = tp_entry->tp;
		/* Ignore non-MPTCP connections */
		if (!mptcp(tp) || !tp->mptcp)
			continue;
		/* Only do this on non-backup subflows that are alone on their
		 * connection, otherwise MPTCP might send keepalive on the wrong
		 * subflow
		 */
		if (mptcp_subflow_is_active(tp) && tp->mpcb->cnt_established == 1) {
			meta_sk = tp->meta_sk;
			meta_tp = tcp_sk(meta_sk);
			sock_set_flag(meta_sk, SOCK_KEEPOPEN);
			/* XXX maybe a better way to do this ? */
			meta_tp->keepalive_intvl = keepalive_intvl_when(meta_tp);
			meta_tp->keepalive_time = keepalive_intvl_when(meta_tp);
			inet_csk_reset_keepalive_timer(meta_sk, meta_tp->keepalive_intvl);
			return;
		}
	}
}

void mptcp_icsk_probes_threshold_exceeded(struct mptcp_oracle_entry *entry)
{
	if (!entry)
		return;

	pr_info_entry(entry, __func__);
	request_fast_join_all_tps(entry, true);
}

void mptcp_receive_timer_expired(struct mptcp_oracle_entry *entry, struct sock *meta_sk)
{
	if (!entry) {
		/* Don't be stuck! */
		struct sock *tmp_sk;
		struct tcp_sock *tmp_tp;
		struct tcp_sock *meta_tp = tcp_sk(meta_sk);
		struct mptcp_cb *mpcb = meta_tp->mpcb;
		if (mpcb->mp_idle) {
			pr_alert("Receive timer shouldn't have been fired...\n");
			return;
		}
		mptcp_for_each_sk(mpcb, tmp_sk) {
			tmp_tp = tcp_sk(tmp_sk);
			tmp_tp->pf = 1;
			tmp_tp->was_bad = 1;
		}
		if (mpcb->pm_ops->push_info) {
			int have_bup;
			mpcb->pm_ops->push_info(meta_sk, MPTCP_HAVE_BUP, &have_bup);
			if (have_bup)
				mptcp_request_fast_join(meta_sk, mpcb);
		}
		return;
	}

	pr_info_entry(entry, __func__);
	request_fast_join_all_tps(entry, true);
}

/* Volume-weighted Exponential Moving Average (V-EMA) */
static int ema_update(struct ema_entry *ema, unsigned int new_value, unsigned int new_volume)
{
	u64 new_product;
	u64 old_value = ema->value;

	if (new_volume == 0)
		return 0;

	new_product = new_value * MULTIPLIER_VAL;
	/* On 32-bit systems, the division should be explicitly split into two
	 * statements
	 */
	ema->product = alpha * new_product + (ALPHA_DIV - alpha) * ema->product;
	do_div(ema->product, ALPHA_DIV);
	ema->volume  = alpha * new_volume * MULTIPLIER_VOL + (ALPHA_DIV - alpha) * ema->volume;
	do_div(ema->volume, ALPHA_DIV);
	ema->value = ema->product;
	do_div(ema->value, ema->volume);

	if (ema->value > old_value)
		return 1;

	/* Value decreased */
	return -1;
}

static enum hrtimer_restart oracle_timer_function(struct hrtimer *timer)
{
	struct mptcp_oracle_entry *entry;
	struct tcp_sk_entry *tp_entry;
	u32 cnt_packets_out, cnt_lost_out, cnt_snd_packets, cnt_total_retrans;
	u32 rto, rto_ms;
	struct tcp_sock *tp;
	int timer_period_s = timer_period_ms / 1000;
	int timer_period_ns = (timer_period_ms % 1000) * 1000000;
	bool rcv_packet, rto_exceeded;
	int sloss_update, sretrans_update;

	kt_period = ktime_set(timer_period_s, timer_period_ns);

	list_for_each_entry(entry, &entry_list, list) {
		/* Collect dev stats, if available */
		//if (entry->dev && entry->dev->name != '\0' && entry->dev->netdev_ops->ndo_get_stats) {
		//	struct net_device_stats *ns = entry->dev->netdev_ops->ndo_get_stats(entry->dev);
		//	pr_alert("For %s: rx %lu tx %lu rx_err %lu tx_err %lu rx_dropped %lu tx_dropped %lu\n", entry->dev->name, ns->rx_packets, ns->tx_packets, ns->rx_errors, ns->tx_errors, ns->rx_dropped, ns->tx_dropped);
		//}
		cnt_packets_out = cnt_lost_out = cnt_snd_packets = cnt_total_retrans = 0;
		sloss_update = 0;
		sretrans_update = 0;
		rcv_packet = false;
		rto_exceeded = false;
		if (list_empty(&entry->tcp_sk_list_head))
			continue;

		list_for_each_entry(tp_entry, &entry->tcp_sk_list_head, list) {
			// TODO ensure no concurrency problem will occur
			tp = tp_entry->tp;
			cnt_packets_out += tp->packets_out;
			cnt_lost_out += tp->lost_out;
			/* If the last packet loss finally goes through, count
			 * it as one out packet for volume */
			if (tp->lost_out < tp_entry->last_lost_out)
				cnt_packets_out += tp_entry->last_lost_out - tp->lost_out;

			tp_entry->last_lost_out = tp->lost_out;
			cnt_snd_packets += tp->snd_packets - tp_entry->last_snd_packets;
			tp_entry->last_snd_packets = tp->snd_packets;
			cnt_total_retrans += tp->total_retrans - tp_entry->last_total_retrans;
			tp_entry->last_total_retrans = tp->total_retrans;
			if (after(tp->rcv_tstamp, entry->tcp_stats.last_rcv_tstamp)) {
				entry->tcp_stats.last_rcv_tstamp = tp->rcv_tstamp;
				rcv_packet = true;
			}
			rto = inet_csk((struct sock *)tp)->icsk_rto;
			rto_ms = jiffies_to_msecs(rto);
			/* Be cautious to open only once, especially if
			 * connection is very long
			 */
			if (rto_ms_threshold > 0 && rto_ms >= rto_ms_threshold) {
				rto_exceeded = true;
				tp_entry->rto_exceed_seen = 1;
				tp->high_rto = 1;
			}
		}
		sloss_update = ema_update(&entry->tcp_stats.sloss, cnt_lost_out, cnt_packets_out);
		sretrans_update = ema_update(&entry->tcp_stats.sretrans, cnt_total_retrans, cnt_snd_packets);

		if (sloss_threshold > 0 &&
		    sloss_update > 0 && entry->tcp_stats.sloss.value >= sloss_threshold)
			sloss_threshold_exceeded(entry);

		else if (sretrans_threshold > 0 &&
		    sretrans_update > 0 && entry->tcp_stats.sretrans.value >= sretrans_threshold)
			sretrans_threshold_exceeded(entry);

		else if (rto_ms_threshold > 0 && rto_exceeded)
			rto_threshold_exceeded(entry);

		else
			entry->declared_bad = 0;
		/* Is the path idle? */
		if (idle_periods_threshold > 0 && !sloss_update && !sretrans_update && !rcv_packet) {
			entry->tcp_stats.idle_periods++;
			/* Should we trigger probes ? */
			if (idle_periods_threshold > 0 &&
			    entry->tcp_stats.idle_periods >= idle_periods_threshold)
				idle_periods_threshold_exceeded(entry);
		} else
			entry->tcp_stats.idle_periods = 0;
	}
	/* Restart the timer */
	hrtimer_forward_now(timer, kt_period);

	return HRTIMER_RESTART;
}

static int __init mptcp_oracle_register(void)
{
	int timer_period_s = timer_period_ms / 1000;
	int timer_period_ns = (timer_period_ms % 1000) * 1000000;
	kt_period = ktime_set(timer_period_s, timer_period_ns);
	hrtimer_init (&htimer, CLOCK_REALTIME, HRTIMER_MODE_REL);
	htimer.function = oracle_timer_function;
	hrtimer_start(&htimer, kt_period, HRTIMER_MODE_REL);
	pr_info("Oracle is initialized\n");
	return 0;
}

static void __exit mptcp_oracle_unregister(void)
{
	hrtimer_cancel(&htimer);
}

module_init(mptcp_oracle_register);
module_exit(mptcp_oracle_unregister);

MODULE_AUTHOR("Quentin De Coninck");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPTCP Oracle");
MODULE_VERSION("0.1");

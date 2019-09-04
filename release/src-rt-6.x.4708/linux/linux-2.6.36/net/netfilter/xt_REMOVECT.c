#include <linux/module.h>
#include <linux/skbuff.h>

#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_queue.h>

MODULE_DESCRIPTION("Xtables: Removing connection tracking for packets");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_REMOVECT");

static int resetct_queue(struct nf_queue_entry *entry, unsigned queue_num)
{
	struct sk_buff *skb = entry->skb;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	ct = nf_ct_get(skb, &ctinfo);
	// in 2.6.32 pass skb to nf_ct_is_untracked
	if (nf_ct_is_untracked(ct)) {
		goto reinject;
	}
	else if (ct == NULL) {
		goto reinject;
	}
	else {
//		struct list_head *elem = &nf_hooks[entry->pf][entry->hook];
		struct list_head *elem = entry->elem->list.prev;
		while (list_entry(elem, struct nf_hook_ops, list)->priority >= NF_IP_PRI_CONNTRACK)
			elem = elem->prev;
		nf_reset(skb);
		nf_ct_kill(ct);
		entry->elem = list_entry(elem, struct nf_hook_ops, list);
//		printk(KERN_INFO "new priority %d\n", entry->elem->priority);
	}
reinject:
	nf_reinject(entry, NF_ACCEPT);
	return 0;
}

static struct nf_queue_handler removect_qh = {
	.outfn = resetct_queue,
};

static unsigned int removect_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	ct = nf_ct_get(skb, &ctinfo);
	if (ct == NULL || ct == &nf_conntrack_untracked) {
		return XT_CONTINUE;
	}
	return NF_QUEUE;
}

static struct xt_target removect_tg_reg __read_mostly = {
	.name     = "REMOVECT",
	.revision = 0,
	.family   = NFPROTO_IPV4,
	.target   = removect_tg,
	.table    = "mangle",
	.me       = THIS_MODULE,
};

static int __init removect_tg_init(void)
{
	nf_register_queue_handler(NFPROTO_IPV4, &removect_qh);
	return xt_register_target(&removect_tg_reg);
}

static void __exit removect_tg_exit(void)
{
	nf_unregister_queue_handlers(&removect_qh);
	xt_unregister_target(&removect_tg_reg);
}

module_init(removect_tg_init);
module_exit(removect_tg_exit);

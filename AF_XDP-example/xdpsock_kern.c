/**
 * Based on linux/samples/bpf/xdpsock_user.c from kernel 5.19-rc4
 * Hacking our way to a better kernel
 */

// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "xdpsock.h"
#include <linux/if_xdp.h>


#include <netinet/if_ether.h>
#define MULTI_FCQ
#define USE_DEBUGMODE
#ifdef MULTI_FCQ
#define QTYPE "MULTI"
#else
#define QTYPE "SINGLE"
#endif

#ifdef USE_DEBUGMODE
#define odbpf_vdebug(fmt, args...)                                                       \
	({                                                                                   \
		char ____fmt[] = fmt;                                                            \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##args);                              \
	})
#define odbpf_debug(fmt, args...) odbpf_vdebug(fmt, ##args)
#else
#define odbpf_debug(fmt, args...)
#endif /* USE_DEBUGMODE */

/* This XDP program is only needed for the XDP_SHARED_UMEM mode.
 * If you do not use this mode, libbpf can supply an XDP program for you.
 */

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

// struct bpf_map_def {
// 	unsigned int type;
// 	unsigned int key_size;
// 	unsigned int value_size;
// 	unsigned int max_entries;
// };

// struct bpf_map_def xsks_map = {
//     .type        = BPF_MAP_TYPE_XSKMAP,
//     .key_size    = sizeof(u32),
//     .value_size  = sizeof(int),
//     .max_entries = 64
// };


static unsigned int rr;

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
	struct ethhdr *eth = (struct ethhdr *)(unsigned long)(ctx->data);
	void *data_end = (void *)(unsigned long)(ctx->data_end);

	if ((void *)eth + sizeof(struct ethhdr) > data_end)
		return XDP_ABORTED;

	/* Pass ARP so tests don't start failing due to switch issues. Note htons(arp) == 1544. */
	if (eth->h_proto == 1544)
		return XDP_PASS;
	
#ifdef MULTI_FCQ
	/* In a multi-FCQ setup we lookup the rx channel ID in our xsk map */
	//rr = ctx->rx_queue_index;
	//bpf_printk("rr = %d", rr);
	//rr = 0;
	//rr = (rr + 1) & (MAX_SOCKS - 1);
	rr = (rr + 1) & (1 - 1);
#else
	/* In a single-FCQ setup we roundrobin between sockets. */
	rr = (rr + 1) & (MAX_SOCKS - 1);
#endif
	int *x = bpf_map_lookup_elem(&xsks_map, &rr);
	odbpf_debug("&xsks_map == %p\n",&xsks_map);
	odbpf_debug("x == %llx\n",x);
	odbpf_debug("rr == %llx\n", rr);
	//odbpf_debug("fd == %llx\n", bpf_map__fd(&xsks_map));
	if (x)
	{
		odbpf_vdebug("[%s][%u] Redirecting to *x=%u\n", QTYPE, ctx->rx_queue_index, *x);
		odbpf_debug("[%s][%u] Redirecting to rr=%u\n", QTYPE, ctx->rx_queue_index, rr);
		odbpf_debug("xsks_map == %llx\n",&xsks_map);
		return bpf_redirect_map(&xsks_map, rr, 0);
		//return xdp_redirect(ctx, x);
	}
	//odbpf_debug("[%s][%u] Lookup failed on rr=%u", QTYPE, ctx->rx_queue_index, rr);
	return XDP_DROP;
}

char _license[] SEC("license") = "Dual BSD/GPL";
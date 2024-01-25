// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "xdpsock.h"

/* This XDP program is only needed for multi-buffer and XDP_SHARED_UMEM modes.
 * If you do not use these modes, libbpf can supply an XDP program for you.
 */

#define odbpf_vdebug(fmt, args...)                                                       \
	({                                                                                   \
		char ____fmt[] = fmt;                                                            \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##args);                              \
	})

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_SOCKS + 1);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

// int num_socks = 1;
// static unsigned int rr = 0;
static u32 index = 0;
SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
    index = ctx->rx_queue_index;
	odbpf_vdebug("index = %d\n", index);
    // __u32 *pkt_count;

    // pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
    // if (pkt_count) {

    //     /* We pass every other packet */
    //     if ((*pkt_count)++ & 1)
    //         return XDP_PASS;
    // }

    /* A set entry here means that the correspnding queue_id
     * has an active AF_XDP socket bound to it. */
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";

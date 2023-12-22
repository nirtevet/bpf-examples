// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2022 Intel Corporation. */

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
//#include <linux/err.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <locale.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>

#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdpsock.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL     69
#endif

#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET     70
#endif

#define NUM_FRAMES (4 * 1024)
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 9728 /* Max frame size supported by many NICs */
#define IS_EOP_DESC(options) (!((options) & XDP_PKT_CONTD))

#define DEBUG_HEXDUMP 1

#define VLAN_PRIO_MASK		0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT		13
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
#define VLAN_VID__DEFAULT	1
#define VLAN_PRI__DEFAULT	0

#define NSEC_PER_SEC		1000000000UL
#define NSEC_PER_USEC		1000

#define SCHED_PRI__DEFAULT	0
#define STRERR_BUFSIZE          1024
#define MASK_FOR_UMEM_ADDRESS 0x1FFFFF
#define CONVERT_TO_RELATIVE_ADDRESS(addr) (addr & MASK_FOR_UMEM_ADDRESS)

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

static unsigned long prev_time;
static long tx_cycle_diff_min;
static long tx_cycle_diff_max;
static double tx_cycle_diff_ave;
static long tx_cycle_cnt;

enum benchmark_type {
	BENCH_RXDROP = 0,
	BENCH_TXONLY = 1,
	BENCH_L2FWD = 2,
};

static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static u32 prog_id;

static enum benchmark_type opt_bench = BENCH_RXDROP;
static enum xdp_attach_mode opt_attach_mode = XDP_MODE_NATIVE;
static const char *opt_if = "";
static int opt_ifindex;
static int opt_queue;
static unsigned long opt_duration;
static unsigned long start_time;
static bool benchmark_done;
static u32 opt_batch_size = 64;
static int opt_pkt_count;
static u16 opt_pkt_size = MIN_PKT_SIZE;
static u32 opt_pkt_fill_pattern = 0x12345678;
static bool opt_vlan_tag;
static u16 opt_pkt_vlan_id = VLAN_VID__DEFAULT;
static u16 opt_pkt_vlan_pri = VLAN_PRI__DEFAULT;
static struct ether_addr opt_txdmac = {{ 0x3c, 0xfd, 0xfe,
					 0x9e, 0x7f, 0x71 }};
static struct ether_addr opt_txsmac = {{ 0xec, 0xb1, 0xd7,
					 0x98, 0x3a, 0xc0 }};
static bool opt_extra_stats;
static bool opt_quiet;
static bool opt_app_stats;
static const char *opt_irq_str = "";
static u32 irq_no;
static int irqs_at_init = -1;
static u32 sequence;
static int opt_poll;
static int opt_interval = 1;
static int opt_retries = 3;
static u32 opt_xdp_bind_flags = XDP_USE_NEED_WAKEUP;
static u32 opt_umem_flags;
static int opt_unaligned_chunks;
static int opt_mmap_flags;
static int opt_xsk_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
static int frames_per_pkt;
static int opt_timeout = 1000;
static bool opt_need_wakeup = true;
static u32 opt_num_xsks = 1;
static bool opt_busy_poll;
static bool opt_reduced_cap = false;
static clockid_t opt_clock = CLOCK_MONOTONIC;
static unsigned long opt_tx_cycle_ns;
static int opt_schpolicy = SCHED_OTHER;
static int opt_schprio = SCHED_PRI__DEFAULT;
static bool opt_tstamp;
static struct xdp_program *xdp_prog;
static bool opt_frags;
static bool load_xdp_prog=true;
static pthread_t pt;
static void *bufs;
static struct xsk_umem_info *umem;

struct packet_desc
 {
	//char *packet  need to deside between char* pkt to addres, depend where we will do the IS_EOP()
	u64 addr;
	u32 len;
	u32 option;
};

void print_packet_desc(struct packet_desc desc){
	printf("\naddr = %llx\n", desc.addr);
	printf("\nlen = %d\n", desc.len);
	printf("\noption = %d\n", desc.option);

}

struct vlan_ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__be16 h_vlan_proto;
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

#define PKTGEN_MAGIC 0xbe9be955
struct pktgen_hdr {
	__be32 pgh_magic;
	__be32 seq_num;
	__be32 tv_sec;
	__be32 tv_usec;
};

struct xsk_ring_stats {
	unsigned long rx_frags;
	unsigned long rx_npkts;
	unsigned long tx_frags;
	unsigned long tx_npkts;
	unsigned long rx_dropped_npkts;
	unsigned long rx_invalid_npkts;
	unsigned long tx_invalid_npkts;
	unsigned long rx_full_npkts;
	unsigned long rx_fill_empty_npkts;
	unsigned long tx_empty_npkts;
	unsigned long prev_rx_frags;
	unsigned long prev_rx_npkts;
	unsigned long prev_tx_frags;
	unsigned long prev_tx_npkts;
	unsigned long prev_rx_dropped_npkts;
	unsigned long prev_rx_invalid_npkts;
	unsigned long prev_tx_invalid_npkts;
	unsigned long prev_rx_full_npkts;
	unsigned long prev_rx_fill_empty_npkts;
	unsigned long prev_tx_empty_npkts;
};

struct xsk_driver_stats {
	unsigned long intrs;
	unsigned long prev_intrs;
};

struct xsk_app_stats {
	unsigned long rx_empty_polls;
	unsigned long fill_fail_polls;
	unsigned long copy_tx_sendtos;
	unsigned long tx_wakeup_sendtos;
	unsigned long opt_polls;
	unsigned long prev_rx_empty_polls;
	unsigned long prev_fill_fail_polls;
	unsigned long prev_copy_tx_sendtos;
	unsigned long prev_tx_wakeup_sendtos;
	unsigned long prev_opt_polls;
};

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	struct xsk_ring_stats ring_stats;
	struct xsk_app_stats app_stats;
	struct xsk_driver_stats drv_stats;
	u32 outstanding_tx;
	u32 channel_id; /**< Channel ID of this xsk */
	u32 xsk_index; /**< Index of this xsk within xsks */
	struct xsk_ring_prod fq; /**< Dedicated fill queue */
	struct xsk_ring_cons cq; /**< Dedicated comp queue */
	u64 umem_offset; /**< Umem offset of descriptors for this XSK */
	u32 key;
	u32 fd;
};

static const struct clockid_map {
	const char *name;
	clockid_t clockid;
} clockids_map[] = {
	{ "REALTIME", CLOCK_REALTIME },
	{ "TAI", CLOCK_TAI },
	{ "BOOTTIME", CLOCK_BOOTTIME },
	{ "MONOTONIC", CLOCK_MONOTONIC },
	{ NULL }
};

static const struct sched_map {
	const char *name;
	int policy;
} schmap[] = {
	{ "OTHER", SCHED_OTHER },
	{ "FIFO", SCHED_FIFO },
	{ NULL }
};

static int num_socks = 0;
struct xsk_socket_info *xsks[MAX_SOCKS];
int sock;


static int get_clockid(clockid_t *id, const char *name)
{
	const struct clockid_map *clk;

	for (clk = clockids_map; clk->name; clk++) {
		if (strcasecmp(clk->name, name) == 0) {
			*id = clk->clockid;
			return 0;
		}
	}

	return -1;
}

static int get_schpolicy(int *policy, const char *name)
{
	const struct sched_map *sch;

	for (sch = schmap; sch->name; sch++) {
		if (strcasecmp(sch->name, name) == 0) {
			*policy = sch->policy;
			return 0;
		}
	}

	return -1;
}

static unsigned long get_nsecs(void)
{
	struct timespec ts;

	clock_gettime(opt_clock, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}


static void print_benchmark(bool running)
{
	const char *bench_str = "INVALID";

	if (opt_bench == BENCH_RXDROP)
		bench_str = "rxdrop";
	else if (opt_bench == BENCH_TXONLY)
		bench_str = "txonly";
	else if (opt_bench == BENCH_L2FWD)
		bench_str = "l2fwd";

	printf("%s:%d %s ", opt_if, opt_queue, bench_str);
	if (opt_attach_mode == XDP_MODE_SKB)
		printf("xdp-skb ");
	else if (opt_attach_mode == XDP_MODE_NATIVE)
		printf("xdp-drv ");
	else
		printf("	");

	if (opt_poll)
		printf("poll() ");

	if (running) {
		printf("running...");
		fflush(stdout);
	}
}

static int xsk_get_xdp_stats(int fd, struct xsk_socket_info *xsk)
{
	struct xdp_statistics stats;
	socklen_t optlen;
	int err;

	optlen = sizeof(stats);
	err = getsockopt(fd, SOL_XDP, XDP_STATISTICS, &stats, &optlen);
	if (err)
		return err;

	if (optlen == sizeof(struct xdp_statistics)) {
		xsk->ring_stats.rx_dropped_npkts = stats.rx_dropped;
		xsk->ring_stats.rx_invalid_npkts = stats.rx_invalid_descs;
		xsk->ring_stats.tx_invalid_npkts = stats.tx_invalid_descs;
		xsk->ring_stats.rx_full_npkts = stats.rx_ring_full;
		xsk->ring_stats.rx_fill_empty_npkts = stats.rx_fill_ring_empty_descs;
		xsk->ring_stats.tx_empty_npkts = stats.tx_ring_empty_descs;
		return 0;
	}

	return -EINVAL;
}


static void dump_app_stats(long dt)
{
	int i;

	for (i = 0; i < num_socks && xsks[i]; i++) {
		char *fmt = "%-18s %'-14.0f %'-14lu\n";
		double rx_empty_polls_ps, fill_fail_polls_ps, copy_tx_sendtos_ps,
				tx_wakeup_sendtos_ps, opt_polls_ps;

		rx_empty_polls_ps = (xsks[i]->app_stats.rx_empty_polls -
					xsks[i]->app_stats.prev_rx_empty_polls) * 1000000000. / dt;
		fill_fail_polls_ps = (xsks[i]->app_stats.fill_fail_polls -
					xsks[i]->app_stats.prev_fill_fail_polls) * 1000000000. / dt;
		copy_tx_sendtos_ps = (xsks[i]->app_stats.copy_tx_sendtos -
					xsks[i]->app_stats.prev_copy_tx_sendtos) * 1000000000. / dt;
		tx_wakeup_sendtos_ps = (xsks[i]->app_stats.tx_wakeup_sendtos -
					xsks[i]->app_stats.prev_tx_wakeup_sendtos)
										* 1000000000. / dt;
		opt_polls_ps = (xsks[i]->app_stats.opt_polls -
					xsks[i]->app_stats.prev_opt_polls) * 1000000000. / dt;

		printf("\n%-18s %-14s %-14s\n", "", "calls/s", "count");
		printf(fmt, "rx empty polls", rx_empty_polls_ps, xsks[i]->app_stats.rx_empty_polls);
		printf(fmt, "fill fail polls", fill_fail_polls_ps,
							xsks[i]->app_stats.fill_fail_polls);
		printf(fmt, "copy tx sendtos", copy_tx_sendtos_ps,
							xsks[i]->app_stats.copy_tx_sendtos);
		printf(fmt, "tx wakeup sendtos", tx_wakeup_sendtos_ps,
							xsks[i]->app_stats.tx_wakeup_sendtos);
		printf(fmt, "opt polls", opt_polls_ps, xsks[i]->app_stats.opt_polls);

		xsks[i]->app_stats.prev_rx_empty_polls = xsks[i]->app_stats.rx_empty_polls;
		xsks[i]->app_stats.prev_fill_fail_polls = xsks[i]->app_stats.fill_fail_polls;
		xsks[i]->app_stats.prev_copy_tx_sendtos = xsks[i]->app_stats.copy_tx_sendtos;
		xsks[i]->app_stats.prev_tx_wakeup_sendtos = xsks[i]->app_stats.tx_wakeup_sendtos;
		xsks[i]->app_stats.prev_opt_polls = xsks[i]->app_stats.opt_polls;
	}

	if (opt_tx_cycle_ns) {
		printf("\n%-18s %-10s %-10s %-10s %-10s %-10s\n",
		       "", "period", "min", "ave", "max", "cycle");
		printf("%-18s %-10lu %-10lu %-10lu %-10lu %-10lu\n",
		       "Cyclic TX", opt_tx_cycle_ns, tx_cycle_diff_min,
		       (long)(tx_cycle_diff_ave / tx_cycle_cnt),
		       tx_cycle_diff_max, tx_cycle_cnt);
	}
}

static inline int get_batch_size(int pkt_cnt)
{
	if (!opt_pkt_count)
		return opt_batch_size * frames_per_pkt;

	if (pkt_cnt + opt_batch_size <= opt_pkt_count)
		return opt_batch_size * frames_per_pkt;

	return (opt_pkt_count - pkt_cnt) * frames_per_pkt;
}

static bool get_interrupt_number(void)
{
	FILE *f_int_proc;
	char line[4096];
	bool found = false;

	f_int_proc = fopen("/proc/interrupts", "r");
	if (f_int_proc == NULL) {
		printf("Failed to open /proc/interrupts.\n");
		return found;
	}

	while (!feof(f_int_proc) && !found) {
		/* Make sure to read a full line at a time */
		if (fgets(line, sizeof(line), f_int_proc) == NULL ||
				line[strlen(line) - 1] != '\n') {
			printf("Error reading from interrupts file\n");
			break;
		}

		/* Extract interrupt number from line */
		if (strstr(line, opt_irq_str) != NULL) {
			irq_no = atoi(line);
			found = true;
			break;
		}
	}

	fclose(f_int_proc);

	return found;
}

static int get_irqs(void)
{
	char count_path[PATH_MAX];
	int total_intrs = -1;
	FILE *f_count_proc;
	char line[4096];

	snprintf(count_path, sizeof(count_path),
		"/sys/kernel/irq/%i/per_cpu_count", irq_no);
	f_count_proc = fopen(count_path, "r");
	if (f_count_proc == NULL) {
		printf("Failed to open %s\n", count_path);
		return total_intrs;
	}

	if (fgets(line, sizeof(line), f_count_proc) == NULL ||
			line[strlen(line) - 1] != '\n') {
		printf("Error reading from %s\n", count_path);
	} else {
		static const char com[2] = ",";
		char *token;

		total_intrs = 0;
		token = strtok(line, com);
		while (token != NULL) {
			/* sum up interrupts across all cores */
			total_intrs += atoi(token);
			token = strtok(NULL, com);
		}
	}

	fclose(f_count_proc);

	return total_intrs;
}

static void dump_driver_stats(long dt)
{
	int i;

	for (i = 0; i < num_socks && xsks[i]; i++) {
		char *fmt = "%-18s %'-14.0f %'-14lu\n";
		double intrs_ps;
		int n_ints = get_irqs();

		if (n_ints < 0) {
			printf("error getting intr info for intr %i\n", irq_no);
			return;
		}
		xsks[i]->drv_stats.intrs = n_ints - irqs_at_init;

		intrs_ps = (xsks[i]->drv_stats.intrs - xsks[i]->drv_stats.prev_intrs) *
			 1000000000. / dt;

		printf("\n%-18s %-14s %-14s\n", "", "intrs/s", "count");
		printf(fmt, "irqs", intrs_ps, xsks[i]->drv_stats.intrs);

		xsks[i]->drv_stats.prev_intrs = xsks[i]->drv_stats.intrs;
	}
}

static void dump_stats(void)
{
	unsigned long now = get_nsecs();
	long dt = now - prev_time;
	int i;

	prev_time = now;

	for (i = 0; i < num_socks && xsks[i]; i++) {
		char *fmt = "%-18s %'-14.0f %'-14lu\n";
		double rx_pps, tx_pps, dropped_pps, rx_invalid_pps, full_pps, fill_empty_pps,
			tx_invalid_pps, tx_empty_pps;

		rx_pps = (xsks[i]->ring_stats.rx_npkts - xsks[i]->ring_stats.prev_rx_npkts) *
			 1000000000. / dt;
		tx_pps = (xsks[i]->ring_stats.tx_npkts - xsks[i]->ring_stats.prev_tx_npkts) *
			 1000000000. / dt;

		printf("\n sock%d@", i);
		print_benchmark(false);
		printf("\n");

		if (opt_frags) {
			u64 rx_frags = xsks[i]->ring_stats.rx_frags;
			u64 tx_frags = xsks[i]->ring_stats.tx_frags;
			double rx_fps = (rx_frags - xsks[i]->ring_stats.prev_rx_frags) *
				1000000000. / dt;
			double tx_fps = (tx_frags - xsks[i]->ring_stats.prev_tx_frags) *
				1000000000. / dt;
			char *ffmt = "%-18s %'-14.0f %'-14lu %'-14.0f %'-14lu\n";

			printf("%-18s %-14s %-14s %-14s %-14s %-14.2f\n", "", "pps", "pkts",
					"fps", "frags", dt / 1000000000.);
			printf(ffmt, "rx", rx_pps, xsks[i]->ring_stats.rx_npkts, rx_fps, rx_frags);
			printf(ffmt, "tx", tx_pps, xsks[i]->ring_stats.tx_npkts, tx_fps, tx_frags);
			xsks[i]->ring_stats.prev_rx_frags = rx_frags;
			xsks[i]->ring_stats.prev_tx_frags = tx_frags;
		} else {

			printf("%-18s %-14s %-14s %-14.2f\n", "", "pps", "pkts",
					dt / 1000000000.);
			printf(fmt, "rx", rx_pps, xsks[i]->ring_stats.rx_npkts);
			printf(fmt, "tx", tx_pps, xsks[i]->ring_stats.tx_npkts);
		}

		xsks[i]->ring_stats.prev_rx_npkts = xsks[i]->ring_stats.rx_npkts;
		xsks[i]->ring_stats.prev_tx_npkts = xsks[i]->ring_stats.tx_npkts;

		if (opt_extra_stats) {
			if (!xsk_get_xdp_stats(xsk_socket__fd(xsks[i]->xsk), xsks[i])) {
				dropped_pps = (xsks[i]->ring_stats.rx_dropped_npkts -
						xsks[i]->ring_stats.prev_rx_dropped_npkts) *
							1000000000. / dt;
				rx_invalid_pps = (xsks[i]->ring_stats.rx_invalid_npkts -
						xsks[i]->ring_stats.prev_rx_invalid_npkts) *
							1000000000. / dt;
				tx_invalid_pps = (xsks[i]->ring_stats.tx_invalid_npkts -
						xsks[i]->ring_stats.prev_tx_invalid_npkts) *
							1000000000. / dt;
				full_pps = (xsks[i]->ring_stats.rx_full_npkts -
						xsks[i]->ring_stats.prev_rx_full_npkts) *
							1000000000. / dt;
				fill_empty_pps = (xsks[i]->ring_stats.rx_fill_empty_npkts -
						xsks[i]->ring_stats.prev_rx_fill_empty_npkts) *
							1000000000. / dt;
				tx_empty_pps = (xsks[i]->ring_stats.tx_empty_npkts -
						xsks[i]->ring_stats.prev_tx_empty_npkts) *
							1000000000. / dt;

				printf(fmt, "rx dropped", dropped_pps,
				       xsks[i]->ring_stats.rx_dropped_npkts);
				printf(fmt, "rx invalid", rx_invalid_pps,
				       xsks[i]->ring_stats.rx_invalid_npkts);
				printf(fmt, "tx invalid", tx_invalid_pps,
				       xsks[i]->ring_stats.tx_invalid_npkts);
				printf(fmt, "rx queue full", full_pps,
				       xsks[i]->ring_stats.rx_full_npkts);
				printf(fmt, "fill ring empty", fill_empty_pps,
				       xsks[i]->ring_stats.rx_fill_empty_npkts);
				printf(fmt, "tx ring empty", tx_empty_pps,
				       xsks[i]->ring_stats.tx_empty_npkts);

				xsks[i]->ring_stats.prev_rx_dropped_npkts =
					xsks[i]->ring_stats.rx_dropped_npkts;
				xsks[i]->ring_stats.prev_rx_invalid_npkts =
					xsks[i]->ring_stats.rx_invalid_npkts;
				xsks[i]->ring_stats.prev_tx_invalid_npkts =
					xsks[i]->ring_stats.tx_invalid_npkts;
				xsks[i]->ring_stats.prev_rx_full_npkts =
					xsks[i]->ring_stats.rx_full_npkts;
				xsks[i]->ring_stats.prev_rx_fill_empty_npkts =
					xsks[i]->ring_stats.rx_fill_empty_npkts;
				xsks[i]->ring_stats.prev_tx_empty_npkts =
					xsks[i]->ring_stats.tx_empty_npkts;
			} else {
				printf("%-15s\n", "Error retrieving extra stats");
			}
		}
	}

	if (opt_app_stats)
		dump_app_stats(dt);
	if (irq_no)
		dump_driver_stats(dt);
}

static bool is_benchmark_done(void)
{
	if (opt_duration > 0) {
		unsigned long dt = (get_nsecs() - start_time);

		if (dt >= opt_duration)
			benchmark_done = true;
	}
	return benchmark_done;
}

static void *poller(void *arg)
{
	(void)arg;
	while (!is_benchmark_done()) {
		sleep(opt_interval);
		dump_stats();
	}

	return NULL;
}

static void remove_xdp_program(void)
{
	int err;

	err = xdp_program__detach(xdp_prog, opt_ifindex, opt_attach_mode, 0);
	if (err)
		fprintf(stderr, "Could not detach XDP program. Error: %s\n", strerror(-err));
}

static void int_exit(int sig)
{
	benchmark_done = true;
	if (load_xdp_prog)
		remove_xdp_program();
	exit(EXIT_FAILURE);
}

static void __exit_with_error(int error, const char *file, const char *func,
			      int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func,
		line, error, strerror(error));

	if (load_xdp_prog)
		remove_xdp_program();
	exit(EXIT_FAILURE);
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, __LINE__)

static void xdpsock_cleanup(void)
{
	struct xsk_umem *umem = xsks[0]->umem->umem;
	int i, cmd = CLOSE_CONN;

	dump_stats();
	for (i = 0; i < num_socks; i++)
		xsk_socket__delete(xsks[i]->xsk);
	(void)xsk_umem__delete(umem);

	if (opt_reduced_cap) {
		if (write(sock, &cmd, sizeof(int)) < 0)
			exit_with_error(errno);
	}

	if (load_xdp_prog)
		remove_xdp_program();
}

static void hex_dump(void *pkt, size_t length, u64 addr)
{
	const unsigned char *address = (unsigned char *)pkt;
	const unsigned char *line = address;
	size_t line_size = 32;
	unsigned char c;
	char buf[32];
	int i = 0;

	if (!DEBUG_HEXDUMP)
		return;

	//sprintf(buf, "addr=%llu", addr);
	printf("length = %zu\n", length);
	//printf("%s | ", buf);
	while (length-- > 0) {
		printf("%02X ", *address++);
		if (!(++i % line_size) || (length == 0 && i % line_size)) {
			if (length == 0) {
				while (i++ % line_size)
					printf("__ ");
			}
			printf(" | ");	/* right close */
			while (line < address) {
				c = *line++;
				printf("%c", (c < 33 || c == 255) ? 0x2E : c);
			}
			printf("\n");
			//if (length > 0)
				//printf("%s | ", buf);
		}
	}
	printf("\n");
}

static void *memset32_htonl(void *dest, u32 val, u32 size)
{
	u32 *ptr = (u32 *)dest;
	int i;

	val = htonl(val);

	for (i = 0; i < (size & (~0x3)); i += 4)
		ptr[i >> 2] = val;

	for (; i < size; i++)
		((char *)dest)[i] = ((char *)&val)[i & 3];

	return dest;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static unsigned int do_csum(const unsigned char *buff, int len)
{
	unsigned int result = 0;
	int odd;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long)buff;
	if (odd) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long)buff) {
			result += *(unsigned short *)buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff +
						   ((unsigned int)len & ~3);
			unsigned int carry = 0;

			do {
				unsigned int w = *(unsigned int *)buff;

				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *)buff;
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *	This function code has been taken from
 *	Linux kernel lib/checksum.c
 */
static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	return (__sum16)~do_csum(iph, ihl * 4);
}

/*
 * Fold a partial checksum
 * This function code has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16 csum_fold(__wsum csum)
{
	u32 sum = (u32)csum;

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__sum16)~sum;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline u32 from64to32(u64 x)
{
	/* add up 32-bit and 32-bit for 32+c bit */
	x = (x & 0xffffffff) + (x >> 32);
	/* add up carry.. */
	x = (x & 0xffffffff) + (x >> 32);
	return (u32)x;
}

__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			  __u32 len, __u8 proto, __wsum sum);

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			  __u32 len, __u8 proto, __wsum sum)
{
	unsigned long long s = (u32)sum;

	s += (u32)saddr;
	s += (u32)daddr;
#ifdef __BIG_ENDIAN__
	s += proto + len;
#else
	s += (proto + len) << 8;
#endif
	return (__wsum)from64to32(s);
}

/*
 * This function has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16
csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len,
		  __u8 proto, __wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static inline u16 udp_csum(u32 saddr, u32 daddr, u32 len,
			   u8 proto, u16 *udp_pkt)
{
	u32 csum = 0;
	u32 cnt = 0;

	/* udp hdr and data */
	for (; cnt < len; cnt += 2)
		csum += udp_pkt[cnt >> 1];

	return csum_tcpudp_magic(saddr, daddr, len, proto, csum);
}

#define ETH_FCS_SIZE 4

#define ETH_HDR_SIZE (opt_vlan_tag ? sizeof(struct vlan_ethhdr) : \
		      sizeof(struct ethhdr))
#define PKTGEN_HDR_SIZE (opt_tstamp ? sizeof(struct pktgen_hdr) : 0)
#define PKT_HDR_SIZE (ETH_HDR_SIZE + sizeof(struct iphdr) + \
		      sizeof(struct udphdr) + PKTGEN_HDR_SIZE)
#define PKTGEN_HDR_OFFSET (ETH_HDR_SIZE + sizeof(struct iphdr) + \
			   sizeof(struct udphdr))
#define PKTGEN_SIZE_MIN (PKTGEN_HDR_OFFSET + sizeof(struct pktgen_hdr) + \
			 ETH_FCS_SIZE)

#define PKT_SIZE		(opt_pkt_size - ETH_FCS_SIZE)
#define IP_PKT_SIZE		(PKT_SIZE - ETH_HDR_SIZE)
#define UDP_PKT_SIZE		(IP_PKT_SIZE - sizeof(struct iphdr))
#define UDP_PKT_DATA_SIZE	(UDP_PKT_SIZE - \
				 (sizeof(struct udphdr) + PKTGEN_HDR_SIZE))

static u8 pkt_data[MAX_PKT_SIZE];

static void gen_eth_hdr_data(void)
{
	struct pktgen_hdr *pktgen_hdr;
	struct udphdr *udp_hdr;
	struct iphdr *ip_hdr;

	if (opt_vlan_tag) {
		struct vlan_ethhdr *veth_hdr = (struct vlan_ethhdr *)pkt_data;
		u16 vlan_tci = 0;

		udp_hdr = (struct udphdr *)(pkt_data +
					    sizeof(struct vlan_ethhdr) +
					    sizeof(struct iphdr));
		ip_hdr = (struct iphdr *)(pkt_data +
					  sizeof(struct vlan_ethhdr));
		pktgen_hdr = (struct pktgen_hdr *)(pkt_data +
						   sizeof(struct vlan_ethhdr) +
						   sizeof(struct iphdr) +
						   sizeof(struct udphdr));
		/* ethernet & VLAN header */
		memcpy(veth_hdr->h_dest, &opt_txdmac, ETH_ALEN);
		memcpy(veth_hdr->h_source, &opt_txsmac, ETH_ALEN);
		veth_hdr->h_vlan_proto = htons(ETH_P_8021Q);
		vlan_tci = opt_pkt_vlan_id & VLAN_VID_MASK;
		vlan_tci |= (opt_pkt_vlan_pri << VLAN_PRIO_SHIFT) & VLAN_PRIO_MASK;
		veth_hdr->h_vlan_TCI = htons(vlan_tci);
		veth_hdr->h_vlan_encapsulated_proto = htons(ETH_P_IP);
	} else {
		struct ethhdr *eth_hdr = (struct ethhdr *)pkt_data;

		udp_hdr = (struct udphdr *)(pkt_data +
					    sizeof(struct ethhdr) +
					    sizeof(struct iphdr));
		ip_hdr = (struct iphdr *)(pkt_data +
					  sizeof(struct ethhdr));
		pktgen_hdr = (struct pktgen_hdr *)(pkt_data +
						   sizeof(struct ethhdr) +
						   sizeof(struct iphdr) +
						   sizeof(struct udphdr));
		/* ethernet header */
		memcpy(eth_hdr->h_dest, &opt_txdmac, ETH_ALEN);
		memcpy(eth_hdr->h_source, &opt_txsmac, ETH_ALEN);
		eth_hdr->h_proto = htons(ETH_P_IP);
	}


	/* IP header */
	ip_hdr->version = IPVERSION;
	ip_hdr->ihl = 0x5; /* 20 byte header */
	ip_hdr->tos = 0x0;
	ip_hdr->tot_len = htons(IP_PKT_SIZE);
	ip_hdr->id = 0;
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = IPDEFTTL;
	ip_hdr->protocol = IPPROTO_UDP;
	ip_hdr->saddr = htonl(0x0a0a0a10);
	ip_hdr->daddr = htonl(0x0a0a0a20);

	/* IP header checksum */
	ip_hdr->check = 0;
	ip_hdr->check = ip_fast_csum((const void *)ip_hdr, ip_hdr->ihl);

	/* UDP header */
	udp_hdr->source = htons(0x1000);
	udp_hdr->dest = htons(0x1000);
	udp_hdr->len = htons(UDP_PKT_SIZE);

	if (opt_tstamp)
		pktgen_hdr->pgh_magic = htonl(PKTGEN_MAGIC);

	/* UDP data */
	memset32_htonl(pkt_data + PKT_HDR_SIZE, opt_pkt_fill_pattern,
		       UDP_PKT_DATA_SIZE);

	/* UDP header checksum */
	udp_hdr->check = 0;
	udp_hdr->check = udp_csum(ip_hdr->saddr, ip_hdr->daddr, UDP_PKT_SIZE,
				  IPPROTO_UDP, (u16 *)udp_hdr);
}

static void gen_eth_frame(struct xsk_umem_info *umem, u64 addr)
{
	static u32 len;
	u32 copy_len = opt_xsk_frame_size;

	if (!len)
		len = PKT_SIZE;

	if (len < opt_xsk_frame_size)
		copy_len = len;
	memcpy(xsk_umem__get_data(umem->buffer, addr),
			pkt_data + PKT_SIZE - len, copy_len);
	len -= copy_len;
}

static struct xsk_umem_info *xsk_configure_umem(void *buffer, u64 size)
{
	struct xsk_umem_info *umem;
	struct xsk_umem_config cfg = {
		/* We recommend that you set the fill ring size >= HW RX ring size +
		 * AF_XDP RX ring size. Make sure you fill up the fill ring
		 * with buffers at regular intervals, and you will with this setting
		 * avoid allocation failures in the driver. These are usually quite
		 * expensive since drivers have not been written to assume that
		 * allocation failures are common. For regular sockets, kernel
		 * allocated memory is used that only runs out in OOM situations
		 * that should be rare.
		 */
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = opt_xsk_frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = opt_umem_flags | XDP_SHARED_UMEM 
	};
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		exit_with_error(errno);

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       &cfg);
	if (ret)
		exit_with_error(-ret);

	umem->buffer = buffer;
	return umem;
}

static void xsk_populate_fill_ring(struct xsk_umem_info *umem)
{
	int ret, i;
	u32 idx;

	ret = xsk_ring_prod__reserve(&umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS * 2, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
		exit_with_error(-ret);
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS * 2; i++)
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) =
			i * opt_xsk_frame_size;
	xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2);
}

static void xsk_populate_fill_ring_multicore(struct xsk_umem_info *umem, struct xsk_socket_info *xsk)
{
	int ret, i;
	u32 idx;

	if (umem == NULL || xsk == NULL)
		exit_with_error(-EINVAL);

	fprintf(stdout, "Filling multi-FCQ XSK[%u] from umem_offset:%llu\n",
		xsk->xsk_index, xsk->umem_offset);

	/* Multi FCQ mode, we fill the xsk->fq. */
	struct xsk_ring_prod *fq_ptr = &xsk->fq;

	/* In a multi-FCQ setup, umem size is multiplied by the number of XSK sockets we have. That
	 * means our umem offset for each descriptor is not uniform - and is different on a per-FQ/CQ
	 * basis. */
	int offset = xsk->umem_offset;

	ret = xsk_ring_prod__reserve(fq_ptr,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS * 2, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
		exit_with_error(-ret);
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS * 2; i++)
		*xsk_ring_prod__fill_addr(fq_ptr, idx++) =
			offset + (i * opt_xsk_frame_size);
	xsk_ring_prod__submit(fq_ptr, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2);
}

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem,
						    bool rx, bool tx)
{
	struct xsk_socket_config cfg;
	struct xsk_socket_info *xsk;
	struct xsk_ring_cons *rxr;
	struct xsk_ring_prod *txr;
	int ret;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		exit_with_error(errno);

	xsk->umem = umem;
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	if (load_xdp_prog || opt_reduced_cap)
		cfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
	else
		cfg.libxdp_flags = 0;
	if (opt_attach_mode == XDP_MODE_SKB)
		cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
	else
		cfg.xdp_flags = XDP_FLAGS_DRV_MODE;
	cfg.bind_flags = opt_xdp_bind_flags;

	rxr = rx ? &xsk->rx : NULL;
	txr = tx ? &xsk->tx : NULL;
	ret = xsk_socket__create(&xsk->xsk, opt_if, opt_queue, umem->umem,
				 rxr, txr, &cfg);
	if (ret)
		exit_with_error(-ret);

	xsk->app_stats.rx_empty_polls = 0;
	xsk->app_stats.fill_fail_polls = 0;
	xsk->app_stats.copy_tx_sendtos = 0;
	xsk->app_stats.tx_wakeup_sendtos = 0;
	xsk->app_stats.opt_polls = 0;
	xsk->app_stats.prev_rx_empty_polls = 0;
	xsk->app_stats.prev_fill_fail_polls = 0;
	xsk->app_stats.prev_copy_tx_sendtos = 0;
	xsk->app_stats.prev_tx_wakeup_sendtos = 0;
	xsk->app_stats.prev_opt_polls = 0;

	return xsk;
}

static void kick_tx(struct xsk_socket_info *xsk) {
    int ret;

    // Perform a non-blocking sendto to wake up the transmission queue
    ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    // Check for successful transmission or expected non-blocking errors
    if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN ||
        errno == EBUSY || errno == ENETDOWN)
        return;

    // If an unexpected error occurs, exit the program with an error message
    exit_with_error(errno);
}

static inline void complete_tx_only(struct xsk_socket_info *xsk,
				    int batch_size)
{
	unsigned int rcvd;
	u32 idx_fq = 0;
	u32 idx_cq = 0;

	if (!xsk->outstanding_tx)
		return;

	if (!opt_need_wakeup || xsk_ring_prod__needs_wakeup(&xsk->tx)) {
		xsk->app_stats.tx_wakeup_sendtos++;
		kick_tx(xsk);
	}

	rcvd = xsk_ring_cons__peek(&xsk->cq, batch_size, &idx_cq);

	if (rcvd > 0) {
		unsigned int i;
		int ret;

		ret = xsk_ring_prod__reserve(&xsk->fq, rcvd, &idx_fq);
		while (ret != rcvd) {
			if (ret < 0)
				exit_with_error(-ret);
			if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->fq)) {
				xsk->app_stats.fill_fail_polls++;
				recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL,
					 NULL);
			}
			ret = xsk_ring_prod__reserve(&xsk->fq, rcvd, &idx_fq);
		}

		for (i = 0; i < rcvd; i++)
			*xsk_ring_prod__fill_addr(&xsk->fq, idx_fq++) =
				*xsk_ring_cons__comp_addr(&xsk->cq, idx_cq++);

		xsk_ring_prod__submit(&xsk->fq, rcvd);
		xsk_ring_cons__release(&xsk->cq, rcvd);
		xsk_ring_cons__release(&xsk->rx, rcvd);
		xsk->outstanding_tx -= rcvd;
	}
}

static u16 ophir_rx_only(u16 xsk_id, 
						 struct packet_desc *rx_array,
						 u16 array_size) {

    unsigned int rcvd, i, eop_cnt = 0;
    u32 idx_rx = 0, idx_fq = 0, wanted_num_of_packets = 0;
    int ret;
	struct xsk_socket_info *xsk = xsks[xsk_id];
	// printf("rx: socket_id = %d\n", xsk_id);
    // Peek into the receive ring buffer to check the number of received packets
    rcvd = xsk_ring_cons__peek(&xsk->rx, opt_batch_size, &idx_rx);
	
    // If no packets are received, perform optional polling or wait for a wakeup signal
    if (!rcvd) {
		//print("111\n");
        if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->fq)) {
            xsk->app_stats.rx_empty_polls++;
            recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL); // Read 0 bits from fd to null
        }
        return 0;
    }
	//printf("222\n");
    // Determine the number of packets to process, capped by the array size or the received count
    wanted_num_of_packets = array_size < rcvd ? array_size : rcvd;

    // Process each packet and populate the provided array
    for (i = 0; i < wanted_num_of_packets; i++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
        u64 addr = desc->addr;
		// printf("\naddr = 0x%llx", addr);
        u32 len = desc->len;
		// printf("\nlen = 0x%llx", len);
        u64 orig = xsk_umem__extract_addr(addr);
		// printf("\naddr = 0x%llx", orig);
        eop_cnt += IS_EOP_DESC(desc->options);

        addr = xsk_umem__add_offset_to_addr(addr);
		// printf("\naddr after add offset= 0x%llx", addr);
        char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
		// printf("\naddr after get data= 0x%llx", pkt);
        rx_array[i].addr = pkt;
        rx_array[i].len = len;
        rx_array[i].option = desc->options;
	}

    ///printf("333\n");
    // Update statistics
    xsk->ring_stats.rx_npkts += eop_cnt;
    xsk->ring_stats.rx_frags += rcvd;
	return wanted_num_of_packets;
}


static void ophir_rx_release(u16 xsk_id, u32 done_packets,
							 struct packet_desc* pkt_array) 
    // we need to Check if the number of done_packets is less than rx_size and pkt_array_id is within bounds
    // Also, ensure that xsks[pkt_array_id] is not NULL
    // If any of these conditions are not met, exit with an error code
{
	unsigned int rcvd, i, eop_cnt = 0;
	u32 idx_rx = 0, idx_fq = 0;
	int ret;
	struct xsk_socket_info *xsk = xsks[xsk_id];

	ret = xsk_ring_prod__reserve(&xsk->fq, rcvd, &idx_fq);
	while (ret != rcvd) {
		if (ret < 0)
			exit_with_error(-ret);
		if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->fq)) {
			xsk->app_stats.fill_fail_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		ret = xsk_ring_prod__reserve(&xsk->fq, rcvd, &idx_fq);
	}

	for (i = 0; i < rcvd; i++) {
		u64 addr = CONVERT_TO_RELATIVE_ADDRESS(pkt_array[i].addr);
		*xsk_ring_prod__fill_addr(&xsk->fq, idx_fq++) = addr;
	}

	xsk_ring_prod__submit(&xsk->fq, rcvd);
	xsk_ring_cons__release(&xsk->rx, rcvd);
}

static inline void ophir_tx_release_complete_tx_only(struct xsk_socket_info *xsk,
													 int nb_frames) {
    unsigned int rcvd;
    u32 idx;
//need to understand where to call it, maybe from our ophir_tx_only
    // If there are no outstanding transmissions, nothing to complete
	printf("111 \n");
    if (!xsk->outstanding_tx)
        return;
	printf("222 \n");
    // If wakeup is needed or explicitly requested, perform wakeup and update statistics
    if (!opt_need_wakeup || xsk_ring_prod__needs_wakeup(&xsk->tx)) {
        xsk->app_stats.tx_wakeup_sendtos++;
        kick_tx(xsk);
    }
	printf("333 \n");
    // Peek into the completion ring buffer to check the number of completed transmissions
    rcvd = xsk_ring_cons__peek(&xsk->cq, nb_frames, &idx);

    // If there are completed transmissions, release them and update outstanding_tx count
    if (rcvd > 0) {
        xsk_ring_cons__release(&xsk->cq, rcvd);
        xsk->outstanding_tx -= rcvd;
    }
}


static int ophir_tx_only(u32 xsk_idx, struct packet_desc* tx_array, int batch_size, u32 pkt_cnt)
{
	
	u32 idx;
	u32 frame_nb = 0;
	unsigned int i;
	u32 packets_done = 0;
	struct xsk_socket_info *xsk = xsks[xsk_idx];
	if(!pkt_cnt){
		return 0;
	}

	while(packets_done < pkt_cnt){

		if(pkt_cnt - packets_done < batch_size){
			batch_size = pkt_cnt - packets_done;
		}

		while (xsk_ring_prod__reserve(&xsk->tx, batch_size, &idx) < batch_size) {
			complete_tx_only(xsk, batch_size);
		}

		for (i = 0; i < batch_size; ) {
			u32 len = tx_array[i].len;

			do {
				struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx + i);
				tx_desc->addr = CONVERT_TO_RELATIVE_ADDRESS(tx_array[packets_done].addr);
				if (len > opt_xsk_frame_size) {
					tx_desc->len = opt_xsk_frame_size;
					tx_desc->options = XDP_PKT_CONTD;
				} else {
					tx_desc->len = len;
					tx_desc->options = 0;
					xsk->ring_stats.tx_npkts++;
					packets_done++;
				}
				len -= tx_desc->len;
				frame_nb = (frame_nb + 1) % NUM_FRAMES;
				i++;
			} while (len);
		}
		xsk_ring_prod__submit(&xsk->tx, batch_size);
		xsk->outstanding_tx += batch_size;
		xsk->ring_stats.tx_frags += batch_size;
		complete_tx_only(xsk, batch_size);
	}
	return batch_size / frames_per_pkt;
}

static int tx_only(struct xsk_socket_info *xsk,
				   u32 *frame_nb,
				   int batch_size,
				   unsigned long tx_ns) {
    u32 idx, tv_sec, tv_usec;
    unsigned int i;

    // Reserve space in the transmit ring buffer for the specified batch size
    while (xsk_ring_prod__reserve(&xsk->tx, batch_size, &idx) < batch_size) {
        // If unable to reserve enough space, complete any outstanding transmissions
        complete_tx_only(xsk, batch_size);

        // Check if the benchmark is done, and if so, return
        if (benchmark_done)
            return 0;
    }

    // If timestamping is enabled, calculate seconds and microseconds
    if (opt_tstamp) {
        tv_sec = (u32)(tx_ns / NSEC_PER_SEC);
        tv_usec = (u32)((tx_ns % NSEC_PER_SEC) / 1000);
    }

    // Loop through each packet in the batch
    for (i = 0; i < batch_size; ) {
        u32 len = PKT_SIZE;

        // Loop to create a multi-frame packet if necessary
        do {
            struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx + i);

            // Set the address for the current frame
            tx_desc->addr = *frame_nb * opt_xsk_frame_size;

            // Determine length and options for the current frame
            if (len > opt_xsk_frame_size) {
                tx_desc->len = opt_xsk_frame_size;
                tx_desc->options = XDP_PKT_CONTD;
            } else {
                tx_desc->len = len;
                tx_desc->options = 0;
                xsk->ring_stats.tx_npkts++;
            }

            // Update variables for the next iteration
            len -= tx_desc->len;
            *frame_nb = (*frame_nb + 1) % NUM_FRAMES;
            i++;

            // If timestamping is enabled, set timestamp information in the packet header
            if (opt_tstamp) {
                struct pktgen_hdr *pktgen_hdr;
                u64 addr = tx_desc->addr;
                char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
                pktgen_hdr = (struct pktgen_hdr *)(pkt + PKTGEN_HDR_OFFSET);

                pktgen_hdr->seq_num = htonl(sequence++);
                pktgen_hdr->tv_sec = htonl(tv_sec);
                pktgen_hdr->tv_usec = htonl(tv_usec);


            }
        } while (len);
    }

    // The function does not submit the packets or update statistics here.
    // This part of the functionality is expected to be handled elsewhere in your code.

	xsk_ring_prod__submit(&xsk->tx, batch_size);
	xsk->outstanding_tx += batch_size;
	xsk->ring_stats.tx_frags += batch_size;
	complete_tx_only(xsk, batch_size);

	return batch_size / frames_per_pkt;
}



static int ophir_complete_tx_only_all(void) {
    bool pending;
    int i;
	u32 num_of_realsed_desc = 0;

	// we need to decide if that matter to us from which xsk we will realse.
	//	if we will distribute the tx pakcet equal (replase the for to an hash)
	// should not cause an issue. 

    // Continue processing until all outstanding transmissions are completed or retries are exhausted
    do {
        pending = false;

        // Iterate through each socket and complete outstanding transmissions
        for (i = 0; i < num_socks; i++) {
            // Check if the socket has outstanding transmissions
            if (xsks[i]->outstanding_tx) {
                // Complete outstanding transmissions for the current socket
                num_of_realsed_desc += ophir_complete_tx_only(xsks[i], opt_batch_size);
                // Check if there are still outstanding transmissions after completion
                pending = !!xsks[i]->outstanding_tx;
            }
        }

        // If there are still pending transmissions, sleep for 1 second and decrement retries
        if (pending && opt_retries-- > 0) {
            sleep(1);
        }
    } while (pending && opt_retries > 0);
	return num_of_realsed_desc;
}

static void complete_tx_only_all(void) {
    bool pending;
    int i;

    // Continue processing until all outstanding transmissions are completed or retries are exhausted
    do {
        pending = false;

        // Iterate through each socket and complete outstanding transmissions
        for (i = 0; i < num_socks; i++) {
            // Check if the socket has outstanding transmissions
            if (xsks[i]->outstanding_tx) {
                // Complete outstanding transmissions for the current socket
                complete_tx_only(xsks[i], opt_batch_size);
                
                // Check if there are still outstanding transmissions after completion
                pending = !!xsks[i]->outstanding_tx;
            }
        }

        // If there are still pending transmissions, sleep for 1 second and decrement retries
        if (pending && opt_retries-- > 0) {
            sleep(1);
        }
    } while (pending && opt_retries > 0);
}

static void load_xdp_program(void)
{
	char errmsg[STRERR_BUFSIZE];
	int err;

	xdp_prog = xdp_program__open_file("xdpsock_kern.o", NULL, NULL);
	err = libxdp_get_error(xdp_prog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERROR: program loading failed: %s\n", errmsg);
		exit(EXIT_FAILURE);
	}

	err = xdp_program__set_xdp_frags_support(xdp_prog, opt_frags);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERROR: Enable frags support failed: %s\n", errmsg);
		exit(EXIT_FAILURE);
	}

	err = xdp_program__attach(xdp_prog, opt_ifindex, opt_attach_mode, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERROR: attaching program failed: %s\n", errmsg);
		exit(EXIT_FAILURE);
	}
}

static int lookup_bpf_map(int prog_fd)
{
	__u32 i, *map_ids, num_maps, prog_len = sizeof(struct bpf_prog_info);
	__u32 map_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info prog_info = {};
	int fd, err, xsks_map_fd = -ENOENT;
	struct bpf_map_info map_info;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err)
		return err;

	num_maps = prog_info.nr_map_ids;

	map_ids = calloc(prog_info.nr_map_ids, sizeof(*map_ids));
	if (!map_ids)
		return -ENOMEM;

	memset(&prog_info, 0, prog_len);
	prog_info.nr_map_ids = num_maps;
	prog_info.map_ids = (__u64)(unsigned long)map_ids;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err) {
		free(map_ids);
		return err;
	}

	for (i = 0; i < prog_info.nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			continue;

		memset(&map_info, 0, map_len);
		err = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (err) {
			close(fd);
			continue;
		}

		if (!strncmp(map_info.name, "xsks_map", sizeof(map_info.name)) &&
		    map_info.key_size == 4 && map_info.value_size == 4) {
			xsks_map_fd = fd;
			break;
		}

		close(fd);
	}

	free(map_ids);
	return xsks_map_fd;
}



// static void enter_xsks_into_map(void)
// {
// 	struct bpf_map *map;
// 	int i, xsks_map;

// 	map = bpf_object__find_map_by_name(xdp_program__bpf_obj(xdp_prog), "xsks_map");
// 	xsks_map = bpf_map__fd(map);
// 	if (xsks_map < 0) {
// 		fprintf(stderr, "ERROR: no xsks map found: %s\n",
// 			strerror(xsks_map));
// 			exit(EXIT_FAILURE);
// 	}

// 	for (i = 0; i < num_socks; i++) {

// 		if (i != xsks[i]->xsk_index)
// 		{
// 			fprintf(stderr, "ERROR: xsk with invalid xsk_index at index (xsk_index:%u, i:%d)\n",
// 				xsks[i]->xsk_index, i);
// 			exit(EXIT_FAILURE);
// 		}

// 		int fd = xsk_socket__fd(xsks[i]->xsk);
// 		int key, ret;
// 		/* In a multi-FCQ setup, we need to insert with key=channel */
// 		key = xsks[i]->channel_id;
// 		printf("chanel_id = %d\n", xsks[i]->channel_id);
// 		ret = bpf_map_update_elem(xsks_map, &key, &fd, 0);
// 		if (ret) {
// 			fprintf(stderr, "ERROR: bpf_map_update_elem %d\n", i);
// 			exit(EXIT_FAILURE);
// 		}

// 		fprintf(stdout, "Inserted XSK[%u] fd:%d into xsks_map[key=%u]\n", xsks[i]->xsk_index, fd, key);
// 	}
// }

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	/* Lesson#3: bpf_object to bpf_map */
	map = bpf_object__find_map_by_name(bpf_obj, mapname);
        if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
 out:
	return map_fd;
}

static void enter_xsks_into_map(void)
{
	//struct bpf_map *data_map;
	int i, xsks_map;
	int key = 0;

	//data_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(xdp_prog), ".bss");

	xsks_map = find_map_fd(xdp_program__bpf_obj(xdp_prog), "xsks_map");
	printf("xsks_map = %d\n", xsks_map);
	// if (!data_map || !bpf_map__is_internal(data_map)) {
	// 	fprintf(stderr, "ERROR: bss map found!\n");
	// 	exit(EXIT_FAILURE);
	// }
	// if (bpf_map_update_elem(bpf_map__fd(data_map), &key, &num_socks, BPF_ANY)) {
	// 	fprintf(stderr, "ERROR: bpf_map_update_elem num_socks %d!\n", num_socks);
	// 	exit(EXIT_FAILURE);
	// }
	//xsks_map = lookup_bpf_map(xdp_program__fd(xdp_prog));
	// printf("xsks_map = %p\n", xsks_map);
	if (xsks_map < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(xsks_map));
			exit(EXIT_FAILURE);
	}

	for (i = 0; i < num_socks; i++) {
		xsks[i]->fd = xsk_socket__fd(xsks[i]->xsk);
		printf("fd = %d\n", xsks[i]->fd);
		int ret;

		//key = xsks[i]->channel_id;
		xsks[i]->key = 5;
		printf("key: %llx\n", &key);
		printf("channel id: %d\n", xsks[i]->channel_id);

		ret = bpf_map_update_elem(xsks_map, &xsks[i]->key, &xsks[i]->fd, 0);

		//printf("*x: %d\n", *x);
		if (ret) {
			fprintf(stderr, "ERROR: bpf_map_update_elem %d\n", i);
			exit(EXIT_FAILURE);
		}
	}
}


static void apply_setsockopt(struct xsk_socket_info *xsk)
{
	int sock_opt;

	if (!opt_busy_poll)
		return;

	sock_opt = 1;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = 20;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = opt_batch_size;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);
}

static int recv_xsks_map_fd_from_ctrl_node(int sock, int *_fd)
{
	char cms[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	int value;
	int len;

	iov.iov_base = &value;
	iov.iov_len = sizeof(int);

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = (caddr_t)cms;
	msg.msg_controllen = sizeof(cms);

	len = recvmsg(sock, &msg, 0);

	if (len < 0) {
		fprintf(stderr, "Recvmsg failed length incorrect.\n");
		return -EINVAL;
	}

	if (len == 0) {
		fprintf(stderr, "Recvmsg failed no data\n");
		return -EINVAL;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	*_fd = *(int *)CMSG_DATA(cmsg);

	return 0;
}

static int recv_xsks_map_fd(int *xsks_map_fd)
{
	struct sockaddr_un server;
	int err;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "Error opening socket stream: %s", strerror(errno));
		return errno;
	}

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, SOCKET_NAME);

	if (connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
		close(sock);
		fprintf(stderr, "Error connecting stream socket: %s", strerror(errno));
		return errno;
	}

	err = recv_xsks_map_fd_from_ctrl_node(sock, xsks_map_fd);
	if (err) {
		fprintf(stderr, "Error %d receiving fd\n", err);
		return err;
	}
	return 0;
}

static struct xsk_socket_info *xsk_configure_socket_multicore(struct xsk_umem_info *umem,
						    bool rx, bool tx, int xsk_index)
{
	struct xsk_socket_config cfg;
	struct xsk_socket_info *xsk;
	struct xsk_ring_cons *rxr;
	struct xsk_ring_prod *txr;
	int ret;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		exit_with_error(errno);

	xsk->umem = umem;
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;


	/* We don't want to use dispatcher - we always want to load our kernel. */
	cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;

	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = opt_xdp_bind_flags;

	rxr = rx ? &xsk->rx : NULL;
	txr = tx ? &xsk->tx : NULL;

	/* Save our position in xsks array and map. */
	xsk->xsk_index = xsk_index;

	/* In a multi-FCQ setup we need to store a umem offset, telling us where the umem descriptors
	 * for this XSK are. This is so each channel does not hit the same memory space.
	 *
	 * Logic here is xsk[0] gets the first batch of descriptors, xsk[1] gets the next batch,
	 * and so on. */

	xsk->umem_offset = xsk_index * (NUM_FRAMES * opt_xsk_frame_size);

	/* In a multi-FCQ setup, we bind to multiple channel IDs, so we calculate this via the
	 * queue number + the xsk index. Mellanox cards will need to have --queue=n for zero copy. */

	xsk->channel_id = opt_queue + xsk_index;
	printf("opt_queue: %d\n", opt_queue);
	printf("xsk_index: %d\n", xsk_index);
	//xsk->channel_id = 6;

	/* In a multi-FCQ setup we use the xsk_socket__create_shared() API which lets us pass
	 * in pointers to dedicated Fill/Completion queue per XSK. */

	fprintf(stdout, "Opening multi-FCQ XSK[%u] to %s channel %u...\n",
		xsk->xsk_index, opt_if, xsk->channel_id);
	ret = xsk_socket__create_shared(&xsk->xsk, opt_if, xsk->channel_id, umem->umem,
	 			rxr, txr, &xsk->fq, &xsk->cq, &cfg);

	// printf("xsk: %llx\n", &xsk->xsk);
	// printf("opt_if: %s\n", opt_if);
	// printf("xsk->channel_id: %d\n", xsk->channel_id);
	// printf("umem->umem: %llx\n", umem->umem);
	// printf("rxr: %llx\n", rxr);
	// printf("txr: %llx\n", txr);
	// printf("&xsk->fq: %llx\n", &xsk->fq);
	// printf("&xsk->cq: %llx\n", &xsk->cq);
	// printf("&cfg: %llx\n", &cfg);
	// printf("ret: %d\n", ret);


	if (ret)
		exit_with_error(-ret);

	ret = bpf_xdp_query_id(opt_ifindex, opt_xdp_flags, &prog_id);
	if (ret)
		exit_with_error(-ret);

	xsk->app_stats.rx_empty_polls = 0;
	xsk->app_stats.fill_fail_polls = 0;
	xsk->app_stats.copy_tx_sendtos = 0;
	xsk->app_stats.tx_wakeup_sendtos = 0;
	xsk->app_stats.opt_polls = 0;
	xsk->app_stats.prev_rx_empty_polls = 0;
	xsk->app_stats.prev_fill_fail_polls = 0;
	xsk->app_stats.prev_copy_tx_sendtos = 0;
	xsk->app_stats.prev_tx_wakeup_sendtos = 0;
	xsk->app_stats.prev_opt_polls = 0;

	return xsk;
}


int xdp_init(int num_of_xsks, char* interface_name)
{
	struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct data[2] = { { 0 } };
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct sched_param schparam;

	int xsks_map_fd = 0;
	int i, ret;
	bool rx = true;
	bool tx = true;

	opt_if = interface_name;
	opt_num_xsks = num_of_xsks;
	opt_ifindex = if_nametoindex(opt_if);
	//printf("if_nametoindex: %d\n", if_nametoindex(opt_if));
	if (opt_reduced_cap) {
		if (capget(&hdr, data)  < 0)
			fprintf(stderr, "Error getting capabilities\n");

		data->effective &= CAP_TO_MASK(CAP_NET_RAW);
		data->permitted &= CAP_TO_MASK(CAP_NET_RAW);

		if (capset(&hdr, data) < 0)
			fprintf(stderr, "Setting capabilities failed\n");

		if (capget(&hdr, data)  < 0) {
			fprintf(stderr, "Error getting capabilities\n");
		} else {
			fprintf(stderr, "Capabilities EFF %x Caps INH %x Caps Per %x\n",
				data[0].effective, data[0].inheritable, data[0].permitted);
			fprintf(stderr, "Capabilities EFF %x Caps INH %x Caps Per %x\n",
				data[1].effective, data[1].inheritable, data[1].permitted);
		}
	} else {
		if (setrlimit(RLIMIT_MEMLOCK, &r)) {
			fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
				strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (load_xdp_prog)
			load_xdp_program();
	}

	/* Reserve memory for the umem. Use hugepages if unaligned chunk mode */
	bufs = mmap(NULL, (NUM_FRAMES * opt_xsk_frame_size) * opt_num_xsks,
		    PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | opt_mmap_flags, -1, 0);
	if (bufs == MAP_FAILED) {
		printf("ERROR: mmap failed\n");
		exit(EXIT_FAILURE);
	}

	/* Create sockets... */
	umem = xsk_configure_umem(bufs, (NUM_FRAMES * opt_xsk_frame_size) * opt_num_xsks);
	//xsk_populate_fill_ring(umem);
	
	for (i = 0; i < opt_num_xsks; i++){
		//xsks[num_socks++] = xsk_configure_socket(umem, rx, tx);
		xsks[num_socks++] = xsk_configure_socket_multicore(umem, rx, tx, i);
		printf("\n\n xsks = 0x%llx", xsks[i]);
	}
	/* In a multi-fcq setup we fill via each XSK FQ. */
	for (i = 0; i < num_socks; i++)
		xsk_populate_fill_ring_multicore(umem, xsks[i]);
	for (i = 0; i < num_socks; i++)
		apply_setsockopt(xsks[i]);

	
	frames_per_pkt = (opt_pkt_size - 1) / XSK_UMEM__DEFAULT_FRAME_SIZE + 1;

	if (load_xdp_prog)
		enter_xsks_into_map();

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

	setlocale(LC_ALL, "");

	prev_time = get_nsecs();
	start_time = prev_time;

	if (!opt_quiet) {
		ret = pthread_create(&pt, NULL, poller, NULL);
		if (ret)
			exit_with_error(ret);
	}

	/* Configure sched priority for better wake-up accuracy */
	memset(&schparam, 0, sizeof(schparam));
	schparam.sched_priority = opt_schprio;
	ret = sched_setscheduler(0, opt_schpolicy, &schparam);
	if (ret) {
		fprintf(stderr, "Error(%d) in setting priority(%d): %s\n",
			errno, opt_schprio, strerror(errno));
		xdp_exit();
	}
}

int xdp_exit(){
	//printf("\nexit\n");
	benchmark_done = true;

	if (!opt_quiet)
		pthread_join(pt, NULL);

	xdpsock_cleanup();
	munmap(bufs, (NUM_FRAMES * opt_xsk_frame_size) * opt_num_xsks);
	return 0;
}


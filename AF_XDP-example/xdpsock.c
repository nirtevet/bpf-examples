// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2022 Intel Corporation. */

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/err.h>
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
#include <stdatomic.h>
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

#define DEBUG_HEXDUMP 0

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

static enum xdp_attach_mode opt_attach_mode = XDP_MODE_NATIVE;
static const char *opt_if = "";
static int opt_ifindex;

static unsigned long opt_duration;
static unsigned long start_time;
bool benchmark_done = false;
static u32 opt_batch_size = 1024;

static u16 opt_pkt_size = MIN_PKT_SIZE;


static bool opt_extra_stats;
static bool opt_quiet = false; //print stats to terminal
static bool opt_app_stats;

static u32 irq_no;
static int irqs_at_init = -1;

static int opt_poll;
static int opt_interval = 1;

static u32 opt_xdp_bind_flags = XDP_USE_NEED_WAKEUP;
static u32 opt_umem_flags;

static int opt_mmap_flags;
static int opt_xsk_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
static int frames_per_pkt;

static bool opt_need_wakeup = true;
static u32 opt_num_xsks = 1;

static clockid_t opt_clock = CLOCK_MONOTONIC;
static unsigned long opt_tx_cycle_ns;
static int opt_schpolicy = SCHED_OTHER;
static int opt_schprio = SCHED_PRI__DEFAULT;

static struct xdp_program *xdp_prog;
static bool opt_frags;
static bool load_xdp_prog = true;

static bool finish_flag = false;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t* threads;

static struct xsk_umem_info *umems[MAX_SOCKS];
static void** bufs_array[MAX_SOCKS];
static bool opt_vlan_tag;

struct vlan_ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__be16 h_vlan_proto;
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
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

struct packet_desc
 {
	u64 addr;
	u32 len;
	u32 option;
};

static int num_socks;
struct xsk_socket_info *xsks[MAX_SOCKS];
int sock;
pthread_t pt;
void *bufs;

static unsigned long get_nsecs(void)
{
	struct timespec ts;

	clock_gettime(opt_clock, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static void print_benchmark(bool running)
{
	printf("%s:", opt_if);
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


void handle_signals() {
    sigset_t mask, old_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, &old_mask);
}

static void xdpsock_cleanup(int xsk_idx)
{
	dump_stats();
	if(xsk_idx > -1){
		xsk_socket__delete(xsks[xsk_idx]->xsk);
	}
}

void notify_threads(pthread_t current_thread_id) {
    pthread_mutex_lock(&mutex);
    int socket_index = -1;
    for (size_t i = 0; i < opt_num_xsks; i++) {
        if (threads[i] == current_thread_id) {
			socket_index = i;
            continue; // Skip the current thread
        }

        if (!finish_flag) {
            pthread_kill(threads[i], SIGINT);
        }
    }

    if (!finish_flag) {
        finish_flag = true;
    }
	if(current_thread_id != pt){
		xdpsock_cleanup(socket_index);
	}
    pthread_mutex_unlock(&mutex);
}



void xdp_exit(void) {
    handle_signals();
    pthread_t thread_id = pthread_self();
    notify_threads(thread_id);
    pthread_exit(NULL);
}


static void int_exit(int sig)
{
	benchmark_done = true;
	xdp_exit();
}

static inline void hex_dump(void *pkt, size_t length, u64 addr)
{
	const unsigned char *address = (unsigned char *)pkt;
	const unsigned char *line = address;
	size_t line_size = 32;
	unsigned char c;
	char buf[32];
	int i = 0;

	if (!DEBUG_HEXDUMP)
		return;

	sprintf(buf, "addr=%llu", addr);
	printf("length = %zu\n", length);
	printf("%s | ", buf);
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
			if (length > 0)
				printf("%s | ", buf);
		}
	}
	printf("\n");
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

struct pktgen_hdr {
	__be32 pgh_magic;
	__be32 seq_num;
	__be32 tv_sec;
	__be32 tv_usec;
};


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

#define ETH_FCS_SIZE 4

#define ETH_HDR_SIZE (opt_vlan_tag ? sizeof(struct vlan_ethhdr) : \
		      sizeof(struct ethhdr))
#define PKTGEN_HDR_SIZE (sizeof(struct pktgen_hdr))
#define PKT_HDR_SIZE (ETH_HDR_SIZE + sizeof(struct iphdr) + \
		      sizeof(struct udphdr) + PKTGEN_HDR_SIZE)
// #define PKTGEN_HDR_OFFSET (ETH_HDR_SIZE + sizeof(struct iphdr) + \
			   sizeof(struct udphdr))
#define PKTGEN_SIZE_MIN (PKTGEN_HDR_OFFSET + sizeof(struct pktgen_hdr) + \
			 ETH_FCS_SIZE)

#define PKT_SIZE		(opt_pkt_size - ETH_FCS_SIZE)
#define IP_PKT_SIZE		(PKT_SIZE - ETH_HDR_SIZE)
#define UDP_PKT_SIZE		(IP_PKT_SIZE - sizeof(struct iphdr))
#define UDP_PKT_DATA_SIZE	(UDP_PKT_SIZE - \
				 (sizeof(struct udphdr) + PKTGEN_HDR_SIZE))

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
		.flags = opt_umem_flags
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

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem,
						    bool rx, bool tx, int queue_id)
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
	if (load_xdp_prog){
		cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
	}
	else
		cfg.libxdp_flags = 0;
	if (opt_attach_mode == XDP_MODE_SKB)
		cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
	else
		cfg.xdp_flags = XDP_FLAGS_DRV_MODE;
	cfg.bind_flags = opt_xdp_bind_flags;

	rxr = rx ? &xsk->rx : NULL;
	txr = tx ? &xsk->tx : NULL;

	ret = xsk_socket__create(&xsk->xsk, opt_if, queue_id, umem->umem,rxr, txr, &cfg);
	
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

inline static void kick_tx(struct xsk_socket_info *xsk)
{
	int ret;
	ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN ||
	    errno == EBUSY || errno == ENETDOWN)
		return;
	exit_with_error(errno);
}

static inline void complete_tx_release_rx(struct xsk_socket_info *xsk)
{
	struct xsk_umem_info *umem = xsk->umem;
	u32 idx_cq = 0, idx_fq = 0;
	unsigned int rcvd;
	size_t ndescs;

	if (!xsk->outstanding_tx)
		return;

	ndescs = (xsk->outstanding_tx > opt_batch_size) ? opt_batch_size :
		xsk->outstanding_tx;

	/* re-add completed Tx buffers */
	rcvd = xsk_ring_cons__peek(&umem->cq, ndescs, &idx_cq);
	if (rcvd > 0) {
		unsigned int i;
		int ret;

		ret = xsk_ring_prod__reserve(&umem->fq, rcvd, &idx_fq);
		while (ret != rcvd) {
			if (ret < 0)
				exit_with_error(-ret);
			if (xsk_ring_prod__needs_wakeup(&umem->fq)) {
				xsk->app_stats.fill_fail_polls++;
				recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL,
					 NULL);
			}
			ret = xsk_ring_prod__reserve(&umem->fq, rcvd, &idx_fq);
		}

		for (i = 0; i < rcvd; i++)
			*xsk_ring_prod__fill_addr(&umem->fq, idx_fq++) =
				*xsk_ring_cons__comp_addr(&umem->cq, idx_cq++);

		xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
		xsk_ring_cons__release(&xsk->umem->cq, rcvd);
		xsk_ring_cons__release(&xsk->rx, rcvd);
		xsk->outstanding_tx -= rcvd;
	}
}

static inline void complete_tx_only(struct xsk_socket_info *xsk,
				    int batch_size)
{
	unsigned int rcvd;
	u32 idx;

	if (!xsk->outstanding_tx)
		return;

	if (!opt_need_wakeup || xsk_ring_prod__needs_wakeup(&xsk->tx)) {
		xsk->app_stats.tx_wakeup_sendtos++;
		kick_tx(xsk);
	}

	rcvd = xsk_ring_cons__peek(&xsk->umem->cq, batch_size, &idx);
	if (rcvd > 0) {
		xsk_ring_cons__release(&xsk->umem->cq, rcvd);
		xsk->outstanding_tx -= rcvd;
	}
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

static void enter_xsks_into_map_by_index(int xsk_index)
{
	struct bpf_map *data_map;
	int i, xsks_map;
	data_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(xdp_prog), ".bss");
	if (!data_map || !bpf_map__is_internal(data_map)) {
		fprintf(stderr, "ERROR: bss map found!\n");
		exit(EXIT_FAILURE);
	}

	xsks_map = lookup_bpf_map(xdp_program__fd(xdp_prog));
	if (xsks_map < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(xsks_map));
			exit(EXIT_FAILURE);
	}


	int fd = xsk_socket__fd(xsks[xsk_index]->xsk);
	int ret;
	int key = xsk_index;
	ret = bpf_map_update_elem(xsks_map, &key, &fd, 0);
	if (ret) {
		fprintf(stderr, "ERROR: bpf_map_update_elem %d\n", i);
		exit(EXIT_FAILURE);
	}
}

static void apply_setsockopt(struct xsk_socket_info *xsk)
{
	int sock_opt;

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


inline static u16 fill_rx_array(u16 xsk_id, 
						 struct packet_desc *rx_array,
						 u16 array_size) {

    unsigned int rcvd, i, eop_cnt = 0;
    u32 idx_rx = 0, wanted_num_of_packets = 0;
	struct xsk_socket_info *xsk = xsks[xsk_id];

    // Peek into the receive ring buffer to check the number of received packets
    rcvd = xsk_ring_cons__peek(&xsk->rx, opt_batch_size, &idx_rx);
	
    // If no packets are received, perform optional polling or wait for a wakeup signal
    if (!rcvd) {
        if (xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
            xsk->app_stats.rx_empty_polls++;
            recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL); // Read 0 bits from fd to null
        }
        return 0;
    }
    // Determine the number of packets to process, capped by the array size or the received count
    wanted_num_of_packets = array_size < rcvd ? array_size : rcvd;

    // Process each packet and populate the provided array
    for (i = 0; i < wanted_num_of_packets; i++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
        u64 addr = desc->addr;
        u32 len = desc->len;
        eop_cnt += IS_EOP_DESC(desc->options);

        addr = xsk_umem__add_offset_to_addr(addr);
        char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
        rx_array[i].addr = (u64)pkt;
        rx_array[i].len = len;
        rx_array[i].option = desc->options;
	}

    // Update statistics
    xsk->ring_stats.rx_npkts += eop_cnt;
    xsk->ring_stats.rx_frags += rcvd;
	return wanted_num_of_packets;
}


inline static void release_rx(u16 xsk_id, u32 done_packets,
							 struct packet_desc* pkt_array) 
    // we need to Check if the number of done_packets is less than rx_size and pkt_array_id is within bounds
    // Also, ensure that xsks[pkt_array_id] is not NULL
    // If any of these conditions are not met, exit with an error code
{
	unsigned int rcvd, i;
	u32 idx_fq = 0;
	int ret;
	struct xsk_socket_info *xsk = xsks[xsk_id];
	rcvd = done_packets < XSK_RING_CONS__DEFAULT_NUM_DESCS ? done_packets : XSK_RING_CONS__DEFAULT_NUM_DESCS;
	ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	while (ret != rcvd) {
		if (ret < 0)
			exit_with_error(-ret);
		if (xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			xsk->app_stats.fill_fail_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	}

	for (i = 0; i < rcvd; i++) {
		u64 addr = CONVERT_TO_RELATIVE_ADDRESS(pkt_array[i].addr);
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = addr;
	}

	xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
	xsk_ring_cons__release(&xsk->rx, rcvd);
}
#define PKTGEN_HDR_OFFSET (ETH_HDR_SIZE + sizeof(struct iphdr) + \
			   sizeof(struct udphdr))
#define PKTGEN_SIZE_MIN (PKTGEN_HDR_OFFSET + sizeof(struct pktgen_hdr) + \
			 ETH_FCS_SIZE)
static u32 sequence;
u32 frame_nb[MAX_SOCKS] = {0};
static int tx_only(int xsk_id, int batch_size, unsigned long tx_ns)
{
	u32 idx, tv_sec, tv_usec;
	unsigned int i;

	while (xsk_ring_prod__reserve(&xsks[xsk_id]->tx, batch_size, &idx) <
				      batch_size) {
		complete_tx_only(xsks[xsk_id], batch_size);
		if (benchmark_done)
			return 0;
	}

	tv_sec = (u32)(tx_ns / NSEC_PER_SEC);
	tv_usec = (u32)((tx_ns % NSEC_PER_SEC) / 1000);


	for (i = 0; i < batch_size; i++) {
		u32 len = PKT_SIZE;

		struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsks[xsk_id]->tx, idx + i);
		tx_desc->addr = frame_nb[xsk_id] * opt_xsk_frame_size;
		tx_desc->len = len;
		tx_desc->options = 0;
		xsks[xsk_id]->ring_stats.tx_npkts++;

		frame_nb[xsk_id] = (frame_nb[xsk_id] + 1) % NUM_FRAMES;

		struct pktgen_hdr *pktgen_hdr;
		u64 addr = tx_desc->addr;
		char *pkt;

		pkt = xsk_umem__get_data(xsks[xsk_id]->umem->buffer, addr);
		pktgen_hdr = (struct pktgen_hdr *)(pkt + PKTGEN_HDR_OFFSET);

		pktgen_hdr->seq_num = htonl(sequence++);
		pktgen_hdr->tv_sec = htonl(tv_sec);
		pktgen_hdr->tv_usec = htonl(tv_usec);

		hex_dump(pkt, PKT_SIZE, addr);
	}

	xsk_ring_prod__submit(&xsks[xsk_id]->tx, batch_size);
	xsks[xsk_id]->outstanding_tx += batch_size;
	xsks[xsk_id]->ring_stats.tx_frags += batch_size;
	complete_tx_only(xsks[xsk_id], batch_size);

	return batch_size / frames_per_pkt;
}


inline static int send_tx_array(u32 xsk_idx, struct packet_desc* tx_array, int batch_size, u32 pkt_cnt)
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
			hex_dump((u64*)tx_array[i].addr, len, (u64)tx_array[i].addr);

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
		complete_tx_release_rx(xsk);
	}
	return batch_size / frames_per_pkt;
}


void xdp_general_init(int number_of_sockets, char* interface_name, pthread_t *threads_array)
{
	threads=threads_array;
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	opt_num_xsks = number_of_sockets;
	int ret;
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);
	opt_if = interface_name;
	opt_ifindex = if_nametoindex(opt_if);

	
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (load_xdp_prog)
		load_xdp_program();

	frames_per_pkt = (opt_pkt_size - 1) / XSK_UMEM__DEFAULT_FRAME_SIZE + 1;

	if (!opt_quiet) {
		ret = pthread_create(&pt, NULL, poller, NULL);
		if (ret)
			exit_with_error(ret);
	}

}

void xdp_init_thread(int number_of_sockets, char* interface_name, int thread_id)
{
	bool rx = true, tx = true;
	struct sched_param schparam;
	int ret;
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

	/* Reserve memory for the umem. Use hugepages if unaligned chunk mode */
	bufs_array[thread_id] = mmap(NULL, NUM_FRAMES * opt_xsk_frame_size,
		    PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | opt_mmap_flags, -1, 0);
	if (bufs_array[thread_id] == MAP_FAILED) {
		printf("ERROR: mmap failed\n");
		exit(EXIT_FAILURE);
	}

	/* Create sockets... */
	umems[thread_id] = xsk_configure_umem(bufs_array[thread_id], NUM_FRAMES * opt_xsk_frame_size);

	xsk_populate_fill_ring(umems[thread_id]);
		
	num_socks++;
	xsks[thread_id] = xsk_configure_socket(umems[thread_id], rx, tx, thread_id);
	apply_setsockopt(xsks[thread_id]);

	if (load_xdp_prog)
		enter_xsks_into_map_by_index(thread_id);

	setlocale(LC_ALL, "");

	prev_time = get_nsecs();
	start_time = prev_time;

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


void final_cleanup(){

	munmap(bufs, NUM_FRAMES * opt_xsk_frame_size);
	if (load_xdp_prog)
			remove_xdp_program();
	for(int i=0; i < opt_num_xsks; i++){
		(void)xsk_umem__delete(umems[i]->umem);
	}
}

static u8 pkt_data[MAX_PKT_SIZE];

void gen_eth_hdr_data(void)
{
	struct pktgen_hdr *pktgen_hdr;
	struct udphdr *udp_hdr;
	struct iphdr *ip_hdr;


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
	int opt_txdmac = 0;
	int opt_txsmac = 0;

	memcpy(eth_hdr->h_dest, &opt_txdmac, ETH_ALEN);
	memcpy(eth_hdr->h_source, &opt_txsmac, ETH_ALEN);
	eth_hdr->h_proto = htons(ETH_P_IP);


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

	/* UDP data */
	u32 opt_pkt_fill_pattern = 0x12345678;
	memset32_htonl(pkt_data + PKT_HDR_SIZE, opt_pkt_fill_pattern,
		       UDP_PKT_DATA_SIZE);

	/* UDP header checksum */
	udp_hdr->check = 0;
	udp_hdr->check = udp_csum(ip_hdr->saddr, ip_hdr->daddr, UDP_PKT_SIZE,
				  IPPROTO_UDP, (u16 *)udp_hdr);
}

// void gen_eth_frame(int xsk_id, int frame_number, struct packet_desc* desc_to_fill)
// {
// 	static u32 len;
// 	u32 copy_len = opt_xsk_frame_size;
// 	u64 addr = frame_number * opt_xsk_frame_size;

// 	if (!len)
// 		len = PKT_SIZE;

// 	if (len < opt_xsk_frame_size)
// 		copy_len = len;
// 	memcpy(xsk_umem__get_data(xsks[xsk_id]->umem->buffer, xsk_umem__add_offset_to_addr(addr)),
// 			pkt_data + PKT_SIZE - len, copy_len);
// 	len -= copy_len;
// 	struct packet_desc* result_desc;
// 	desc_to_fill->addr = addr;
// 	desc_to_fill->len = copy_len;
// 	desc_to_fill->option = 0;
// }

void gen_eth_frame(int xsk_id, u64 addr)
{
	static u32 len;
	u32 copy_len = opt_xsk_frame_size;

	if (!len)
		len = PKT_SIZE;

	if (len < opt_xsk_frame_size)
		copy_len = len;
	memcpy(xsk_umem__get_data(umems[xsk_id]->buffer, addr),
			pkt_data + PKT_SIZE - len, copy_len);
	len -= copy_len;
}

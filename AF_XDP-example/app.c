#include "xdpsock.c"
#include "xdpsock.h"


#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
//#include <linux/ip.h> // For csum_replace2
#include <stdint.h>


inline uint16_t checksum(u16 *data, int len) {
  uint32_t sum = 0;
  int i;

  // Accumulate checksum in 16-bit words
  for (i = 0; i < len; i += 2) {
    sum += data[i];
  }

  // Handle odd-length data
  if (len & 1) {
    uint8_t last_byte = ((uint8_t *)data)[len - 1];
    sum += last_byte << 8;
  }

  // Fold 32-bit sum into 16 bits
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return ~sum;
}
void answer_ping(void* pkt, u32 len);

#define USER_FUNC answer_ping_V4
#define PKT_ARRAY_SIZE 128

static inline __sum16 csum16_add(__sum16 csum, __be16 addend) {
    uint16_t res = (__u16)csum;

    res += (__u16)addend;
    return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend) {
    return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

inline struct packet_desc answer_ping_V4(struct packet_desc pkt_desc){
    uint8_t tmp_mac[ETH_ALEN];
    struct ethhdr *eth = (struct ethhdr *) pkt_desc.addr;
    struct iphdr *ipv4 = (struct iphdr *) (eth + 1);
    struct icmphdr *icmp = (struct icmphdr *) (ipv4 + 1);

    if (ntohs(eth->h_proto) != ETH_P_IP ||
        pkt_desc.len < (sizeof(*eth) + sizeof(*ipv4) + sizeof(*icmp)) ||
        ipv4->protocol != IPPROTO_ICMP ||
        icmp->type != ICMP_ECHO)
        return pkt_desc;

    memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    uint32_t tmp_ip = ipv4->saddr;
    ipv4->saddr = ipv4->daddr;
    ipv4->daddr = tmp_ip;
    // __u32 *data_ptr = (__u32 *)((__u8 *)icmp + sizeof(struct icmphdr));
    if (pkt_desc.len >= sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 4) {
            // __u32 *data_ptr = (__u32 *)((__u8 *)icmp + sizeof(struct icmphdr));
            // (*data_ptr) = htonl(ntohl(*data_ptr) + 1);
            //icmp->checksum = 0;
        }
    
    icmp->type = ICMP_ECHOREPLY;

    // Recompute the ICMP checksum
    icmp->checksum = 0;
    icmp->checksum = htons(checksum((u16*)icmp, pkt_desc.len - sizeof(struct ethhdr) - sizeof(struct iphdr)));

    return pkt_desc;
}

void print_packet_desc_array(const struct packet_desc *arr, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("Packet %zu:\n", i + 1);
        printf("  Address: %llx\n", arr[i].addr);
        printf("  Length: %u\n", arr[i].len);
        printf("  Option: %u\n", arr[i].option);

        // Print the packet data if available
        if (arr[i].addr) {
            for(int j=0; j< arr[i].len; j++)
                printf("%02x ", *(char*)(arr[i].addr+j));
        } else {
            printf("  Packet Data: (null)\n");
        }

        printf("\n");
    }
}

void generate_packets(struct packet_desc* pkt_desc_array_tx, int xsk_id){
    int tx_cnt = 0;
	unsigned long next_tx_ns = 0;
    unsigned long tx_ns = 0;
	struct timespec next;
    long diff;
    gen_eth_hdr_data();

	for (int i = 0; i < NUM_FRAMES; i++){
        gen_eth_frame(xsk_id, i * opt_xsk_frame_size);
	}
    	/* Measure periodic Tx scheduling variance */
    tx_ns = get_nsecs();
    diff = tx_ns - next_tx_ns;
    if (diff < tx_cycle_diff_min)
        tx_cycle_diff_min = diff;

    if (diff > tx_cycle_diff_max)
        tx_cycle_diff_max = diff;

    tx_cycle_diff_ave += (double)diff;
    tx_cycle_cnt++;

    tx_only(xsk_id, 2048, tx_ns);

    
    // for(int i=0; i < PKT_ARRAY_SIZE; i++){
    //     gen_eth_frame(xsk_id, frame_number, &pkt_desc_array_tx[i]);
    //     frame_number++;
    // }

}


void work(void* args){
    int* xsk_id = (int*)args;
    struct packet_desc pkt_desc_array_rx[PKT_ARRAY_SIZE];
    struct packet_desc pkt_desc_array_tx[PKT_ARRAY_SIZE];

    while(__glibc_likely(1)){
        int pkt_cnt = fill_rx_array(*xsk_id, pkt_desc_array_rx, PKT_ARRAY_SIZE);
        if(!pkt_cnt){
            continue;
        }
        for(int i=0; i< pkt_cnt; i++){
            struct packet_desc tmp_desc = answer_ping_V4(pkt_desc_array_rx[i]);
            
            pkt_desc_array_tx[i] = tmp_desc;
        }

        send_tx_array(*xsk_id, pkt_desc_array_tx, PKT_ARRAY_SIZE, pkt_cnt);

    }
}

void work_tx(void* args){
    int* xsk_id = (int*)args;
    struct packet_desc pkt_desc_array_rx[PKT_ARRAY_SIZE];
    struct packet_desc pkt_desc_array_tx[PKT_ARRAY_SIZE];

    while(__glibc_likely(1)){
        generate_packets(pkt_desc_array_tx, *xsk_id);

        // send_tx_array(*xsk_id, pkt_desc_array_tx, PKT_ARRAY_SIZE, PKT_ARRAY_SIZE);

    }
}

int main()
{    
    int number_of_sockets = 16;
    char* interface_name = "enp3s0f0";
    pthread_t threads[number_of_sockets];
    opt_num_xsks = number_of_sockets;
    signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);
    

    xdp_general_init(number_of_sockets, interface_name, threads);

    int id[number_of_sockets];
    for(int i=0; i<number_of_sockets; i++){
        id[i] = i;
        xdp_init_thread(number_of_sockets, interface_name, i);
        pthread_create(&threads[i], NULL, (void*)work_tx, (void*)&id[i]);
    }
    sigset_t mask, old_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, &old_mask);
    // Wait for the threads to finish
    for(int i=0; i<number_of_sockets; i++){
        pthread_join(threads[i], NULL);
    }

    final_cleanup();
    return 0;
}









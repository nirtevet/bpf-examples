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

uint16_t checksum(u16 *data, int len) {
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
#define PKT_ARRAY_SIZE 32

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

static void hex_dump2(void *pkt, size_t length)
{
	const unsigned char *address = (unsigned char *)pkt;
	const unsigned char *line = address;
	size_t line_size = 32;
	unsigned char c;
	char buf[32];
	int i = 0;

	//sprintf(buf, "addr=%llu", addr);
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


static void swap_mac_addresses_and_edit_data(void *data)
{
    //printf("\n inside our app swap \n");
	struct ether_header *eth = (struct ether_header *)data;
	struct ether_addr *src_addr = (struct ether_addr *)&eth->ether_shost;
	struct ether_addr *dst_addr = (struct ether_addr *)&eth->ether_dhost;
	struct ether_addr tmp;

	tmp = *src_addr;
	*src_addr = *dst_addr;
	*dst_addr = tmp;
}

struct packet_desc answer_ping_V4(struct packet_desc pkt_desc){
    int ret;
    uint8_t tmp_mac[ETH_ALEN];
    struct ethhdr *eth = (struct ethhdr *) pkt_desc.addr;
    struct iphdr *ipv4 = (struct iphdr *) (eth + 1);
    struct icmphdr *icmp = (struct icmphdr *) (ipv4 + 1);

    if (ntohs(eth->h_proto) != ETH_P_IP ||
        pkt_desc.len < (sizeof(*eth) + sizeof(*ipv4) + sizeof(*icmp)) ||
        ipv4->protocol != IPPROTO_ICMP ||
        icmp->type != ICMP_ECHO)
        return;

    memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    uint32_t tmp_ip = ipv4->saddr;
    ipv4->saddr = ipv4->daddr;
    ipv4->daddr = tmp_ip;
    __u32 *data_ptr = (__u32 *)((__u8 *)icmp + sizeof(struct icmphdr));
    if (pkt_desc.len >= sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 4) {
            __u32 *data_ptr = (__u32 *)((__u8 *)icmp + sizeof(struct icmphdr));
            // (*data_ptr) = htonl(ntohl(*data_ptr) + 1);
            //icmp->checksum = 0;
        }
    
    icmp->type = ICMP_ECHOREPLY;

    // Recompute the ICMP checksum
    icmp->checksum = 0;
    icmp->checksum = (checksum((u16*)icmp, pkt_desc.len - sizeof(struct ethhdr) - sizeof(struct iphdr) - 4));
    //icmp->checksum = ntohs(checksum((u16*)ipv4, pkt_desc.len - sizeof(struct ethhdr) - 4));
    //printf("answer ping: %d\n", sizeof(struct ethhdr));
    // csum_replace2(&icmp->checksum,
    //         htons(ICMP_ECHO << 8),
    //         htons(ICMP_ECHOREPLY << 8));
    // printf("\n\nhex dump2:\n");
    // hex_dump2(pkt_desc.addr, pkt_desc.len);
    return pkt_desc;
}
/*
// Function to create an ICMP Echo Request packet
void createPingPacket(int seqNum, char *packet, int packetSize) {
    // ICMP header
    struct icmphdr *icmp = (struct icmphdr *)packet;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = seqNum;

    // Fill the rest of the packet with arbitrary data
    memset(packet + sizeof(struct icmphdr), 0xa5, packetSize - sizeof(struct icmphdr));

    // Calculate ICMP checksum
    icmp->checksum = 0;
    icmp->checksum = checksum((unsigned short *)icmp, packetSize);
}
*/
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

int main(){
    
    int number_of_sockets = 1;
    char* interface_name = "enp3s0f0";
    signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

    xdp_init(number_of_sockets, interface_name);
    struct packet_desc pkt_desc_array_rx[PKT_ARRAY_SIZE];
    struct packet_desc pkt_desc_array_tx[PKT_ARRAY_SIZE];
    if(!pkt_desc_array_rx || !pkt_desc_array_tx){
        return -1;
    }

    while(__glibc_likely(1)){
        int pkt_cnt = ophir_rx_only(0, pkt_desc_array_rx, PKT_ARRAY_SIZE);
        if(!pkt_cnt){
            continue;
        }

        for(int i=0; i< pkt_cnt; i++){
            struct packet_desc tmp_desc = answer_ping_V4(pkt_desc_array_rx[i]);
            pkt_desc_array_tx[i] = tmp_desc;
        }

        int ret = ophir_tx_only(0,pkt_desc_array_tx, PKT_ARRAY_SIZE, pkt_cnt);


    }
    xdp_exit();


return 0;
}

void work(void* args){
    int* xsk_id = (int*)args;
    struct packet_desc pkt_desc_array_rx[PKT_ARRAY_SIZE];
    struct packet_desc pkt_desc_array_tx[PKT_ARRAY_SIZE];
    if(!pkt_desc_array_rx || !pkt_desc_array_tx){
        return -1;
    }

    while(__glibc_likely(1)){
        int pkt_cnt = ophir_rx_only(*xsk_id, pkt_desc_array_rx, PKT_ARRAY_SIZE);
        if(!pkt_cnt){
            continue;
        }

        for(int i=0; i< pkt_cnt; i++){
            printf("\nping: \n");
            hex_dump2(pkt_desc_array_rx[i].addr, pkt_desc_array_rx[i].len);
            struct packet_desc tmp_desc = answer_ping_V4(pkt_desc_array_rx[i]);
            
            printf("\nping_reply: \n");
            hex_dump2(tmp_desc.addr, tmp_desc.len);
            pkt_desc_array_tx[i] = tmp_desc;
        }

        int ret = ophir_tx_only(*xsk_id, pkt_desc_array_tx, PKT_ARRAY_SIZE, pkt_cnt);
        printf("main: xsk number %d\n", *xsk_id);

    }
}

// int main()
// {    
//     int number_of_sockets = 4;
//     char* interface_name = "enp3s0f0";
//     opt_num_xsks = number_of_sockets;
//     signal(SIGINT, int_exit);
// 	signal(SIGTERM, int_exit);
// 	signal(SIGABRT, int_exit);

//     xdp_init(number_of_sockets, interface_name);
//     pthread_t sockets[number_of_sockets];
//     int id[number_of_sockets];
//     for(int i=0; i<number_of_sockets; i++){
//         id[i] = i;
//         pthread_create(&sockets[i], NULL, work, (void*)&id[i]);
//     }

//     // Wait for the threads to finish
//     for(int i=0; i<number_of_sockets; i++){
//         pthread_join(sockets[i], NULL);
//     }

//     xdp_exit();

//     return 0;
// }

// int parseString(char* input, char*** argv) {
//     char* token = strtok(input, " ");  // Tokenize the input string using spaces as delimiters
//     int count = 0;

//     while (token != NULL) {
//         (*argv)[count] = strdup(token);  // Copy the token into argv
//         token = strtok(NULL, " ");  // Get the next token
//         count++;
//     }

//     return count;
// }







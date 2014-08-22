#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h> 
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include "analyzer.h"

int prevCheck = 0;

void diep(char *str) {
	perror(str);
	exit(EXIT_FAILURE);
}

void diepcap(char *func, char *str) {
	fprintf(stderr, "[-] %s: %s\n", func, str);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
	char err_buff[PCAP_ERRBUF_SIZE];
	unsigned char *buff = NULL;
	pcap_t *pdes;
	bpf_u_int32 netp, maskp;
	struct bpf_program bp;
	
	if(argc < 2) {
		fprintf(stderr, "Usage: %s interface\n", argv[0]);
		return 1;
	}
	
	if((pdes = pcap_open_live(argv[1], SNAP_LEN, IFF_PROMISC, 500, err_buff)) == NULL)
		diepcap("pcap_open_live", err_buff);
	
	if(pcap_lookupnet(argv[1], &netp, &maskp, err_buff) == -1)
		diepcap("pcap_lookupnet", err_buff);
	
	if(pcap_compile(pdes, &bp, "", 0x100, maskp) < 0)
		diepcap("pcap_compile", pcap_geterr(pdes));
	
	if(pcap_setfilter(pdes, &bp) < 0)
		diepcap("pcap_setfilter", pcap_geterr(pdes)); 

	if(pcap_loop(pdes, -1, callback, buff) < 0)
		diepcap("pcap_loop", pcap_geterr(pdes));
	
	return 0;
}

unsigned char *utoip(int ip, unsigned char *buf) {
    buf[0] = ip & 0xFF;
    buf[1] = (ip >> 8) & 0xFF;
    buf[2] = (ip >> 16) & 0xFF;
    buf[3] = (ip >> 24) & 0xFF;
    
    return buf;
}

void callback(unsigned char *user, const struct pcap_pkthdr *h, const u_char *buff) {
	struct ether_header *eptr;
	struct ether_header *ethheader;
	u_char *packet;
	struct iphdr *ipheader;
	unsigned char src[16], dst[16];
	(void) *user;
	(void) *h;
	
	eptr = (struct ether_header *) buff;
	
	if(eptr->ether_type == 8) {
		ethheader = (struct ether_header *) buff;
		packet = (unsigned char *)(buff + sizeof(*ethheader));
		ipheader = (struct iphdr *) packet;
		
		utoip(ipheader->saddr, src);
		utoip(ipheader->daddr, dst);
		
		if(src[0] == 192 && dst[0] == 192)
			return;
		
		printf(
			"%d.%d.%d.%d -> %d.%d.%d.%d\n",
			src[0], src[1], src[2], src[3],
			dst[0], dst[1], dst[2], dst[3]
		);
		
		fflush(stdout);
	}
}

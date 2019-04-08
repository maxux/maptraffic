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
#include <hiredis/hiredis.h>

#define SNAP_LEN    1514 // ethernet
#define FILTER      "scr port not 1441 or dst port not 1441" // not self websocket scanning

typedef struct pcap_user_t {
    redisContext *redis;

} pcap_user_t;

int prevCheck = 0;

void diep(char *str) {
    perror(str);
    exit(EXIT_FAILURE);
}

void diepcap(char *func, char *str) {
    fprintf(stderr, "[-] %s: %s\n", func, str);
    exit(EXIT_FAILURE);
}

unsigned char *utoip(int ip, unsigned char *buf) {
    buf[0] = ip & 0xFF;
    buf[1] = (ip >> 8) & 0xFF;
    buf[2] = (ip >> 16) & 0xFF;
    buf[3] = (ip >> 24) & 0xFF;

    return buf;
}

void callback(unsigned char *_user, const struct pcap_pkthdr *h, const u_char *buff) {
    struct ether_header *eptr;
    struct ether_header *ethheader;
    u_char *packet;
    struct iphdr *ipheader;
    unsigned char src[16], dst[16];
    pcap_user_t *user = (pcap_user_t *) _user;
    redisReply *reply;
    (void) *h;

    eptr = (struct ether_header *) buff;

    if(eptr->ether_type == 8) {
        ethheader = (struct ether_header *) buff;
        packet = (unsigned char *)(buff + sizeof(*ethheader));
        ipheader = (struct iphdr *) packet;

        char strsrc[16], strdst[16];

        utoip(ipheader->saddr, src);
        utoip(ipheader->daddr, dst);

        // ignore local traffic
        if(src[0] == 192 && dst[0] == 192)
            return;

        if(src[0] == 10 && dst[0] == 10)
            return;

        sprintf(strsrc, "%d.%d.%d.%d", src[0], src[1], src[2], src[3]);
        sprintf(strdst, "%d.%d.%d.%d", dst[0], dst[1], dst[2], dst[3]);

        printf("%s -> %s\n", strsrc, strdst);
        fflush(stdout);

        reply = redisCommand(user->redis, "PUBLISH maptraffic '{\"src\":\"%s\",\"dst\":\"%s\"}'", strsrc, strdst);
        if(!reply || reply->type != REDIS_REPLY_INTEGER)
            fprintf(stderr, "wrong redis reply: %s\n", reply->str);

        freeReplyObject(reply);

    }
}

int main(int argc, char *argv[]) {
    char err_buff[PCAP_ERRBUF_SIZE];
    pcap_t *pdes;
    bpf_u_int32 netp, maskp;
    struct bpf_program bp;
    pcap_user_t user = {
        .redis = NULL,
    };

    if(argc < 2) {
        fprintf(stderr, "[-] usage: %s interface\n", argv[0]);
        return 1;
    }

    // connect redis backend tcp
    if(!(user.redis = redisConnect("127.0.0.1", 6379)))
        diep("redis");

    if(user.redis->err) {
        fprintf(stderr, "redis (tcp): %s\n", user.redis->errstr);
        exit(EXIT_FAILURE);
    }

    if((pdes = pcap_open_live(argv[1], SNAP_LEN, IFF_PROMISC, 500, err_buff)) == NULL)
        diepcap("pcap_open_live", err_buff);

    if(pcap_lookupnet(argv[1], &netp, &maskp, err_buff) == -1)
        diepcap("pcap_lookupnet", err_buff);

    if(pcap_compile(pdes, &bp, "", 0x100, maskp) < 0)
        diepcap("pcap_compile", pcap_geterr(pdes));

    if(pcap_setfilter(pdes, &bp) < 0)
        diepcap("pcap_setfilter", pcap_geterr(pdes));

    if(pcap_loop(pdes, -1, callback, (void *) &user) < 0)
        diepcap("pcap_loop", pcap_geterr(pdes));

    return 0;
}


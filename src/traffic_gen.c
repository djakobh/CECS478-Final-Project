#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#define PCAP_OUT    "data/capture.pcap"
#define GT_OUT      "data/ground_truth.txt"
#define TOTAL 100   /* total packets to generate (40% legit, 60% malicious) */

/* Ethernet header (14 bytes) */
typedef struct {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
} __attribute__((packed)) EthHdr;

/* IPv4 header (20 bytes, no options) */
typedef struct {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
} __attribute__((packed)) IpHdr;

/* TCP header (20 bytes, no options) */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg;
} __attribute__((packed)) TcpHdr;

/* UDP header (8 bytes) */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed)) UdpHdr;

#define FRAME_BUF 2048

static uint16_t ip_checksum(void *buf, int len) {
    uint16_t *p = buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

static int build_tcp_frame(uint8_t *buf, uint16_t dst_port,
                            const uint8_t *payload, uint16_t plen) {
    memset(buf, 0, FRAME_BUF);
    EthHdr *eth = (EthHdr *)buf;
    memset(eth->dst, 0xff, 6);
    memset(eth->src, 0x01, 6);
    eth->ethertype = htons(0x0800);

    IpHdr *ip = (IpHdr *)(buf + sizeof(EthHdr));
    ip->ver_ihl  = 0x45;
    ip->ttl      = 64;
    ip->protocol = 6;
    ip->src      = htonl(0x7f000001);
    ip->dst      = htonl(0x7f000001);
    ip->tot_len  = htons((uint16_t)(sizeof(IpHdr) + sizeof(TcpHdr) + plen));
    ip->checksum = ip_checksum(ip, sizeof(IpHdr));

    TcpHdr *tcp = (TcpHdr *)(buf + sizeof(EthHdr) + sizeof(IpHdr));
    tcp->src_port = htons(12345);
    tcp->dst_port = htons(dst_port);
    tcp->data_off = 0x50;
    tcp->flags    = 0x18;
    tcp->window   = htons(65535);

    memcpy(buf + sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr), payload, plen);
    return (int)(sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr) + plen);
}

static int build_udp_frame(uint8_t *buf, uint16_t dst_port,
                            const uint8_t *payload, uint16_t plen) {
    memset(buf, 0, FRAME_BUF);
    EthHdr *eth = (EthHdr *)buf;
    memset(eth->dst, 0xff, 6);
    memset(eth->src, 0x01, 6);
    eth->ethertype = htons(0x0800);

    IpHdr *ip = (IpHdr *)(buf + sizeof(EthHdr));
    ip->ver_ihl  = 0x45;
    ip->ttl      = 64;
    ip->protocol = 17;
    ip->src      = htonl(0x7f000001);
    ip->dst      = htonl(0x7f000001);
    ip->tot_len  = htons((uint16_t)(sizeof(IpHdr) + sizeof(UdpHdr) + plen));
    ip->checksum = ip_checksum(ip, sizeof(IpHdr));

    UdpHdr *udp = (UdpHdr *)(buf + sizeof(EthHdr) + sizeof(IpHdr));
    udp->src_port = htons(54321);
    udp->dst_port = htons(dst_port);
    udp->length   = htons((uint16_t)(sizeof(UdpHdr) + plen));

    memcpy(buf + sizeof(EthHdr) + sizeof(IpHdr) + sizeof(UdpHdr), payload, plen);
    return (int)(sizeof(EthHdr) + sizeof(IpHdr) + sizeof(UdpHdr) + plen);
}

static void write_packet(pcap_dumper_t *dumper, FILE *gt,
                         const uint8_t *frame, int flen, int malicious) {
    struct pcap_pkthdr hdr;
    hdr.caplen = (uint32_t)flen;
    hdr.len    = (uint32_t)flen;
    gettimeofday(&hdr.ts, NULL);
    pcap_dump((u_char *)dumper, &hdr, frame);
    fprintf(gt, "%d\n", malicious);
}

int main(void) {
    uint8_t frame[FRAME_BUF];
    int flen;

    pcap_t *dead = pcap_open_dead(DLT_EN10MB, 65535);
    if (!dead) { fprintf(stderr, "pcap_open_dead failed\n"); return 1; }

    pcap_dumper_t *dumper = pcap_dump_open(dead, PCAP_OUT);
    if (!dumper) {
        fprintf(stderr, "pcap_dump_open: %s\n", pcap_geterr(dead));
        pcap_close(dead);
        return 1;
    }

    FILE *gt = fopen(GT_OUT, "w");
    if (!gt) { perror("fopen ground_truth.txt"); return 1; }

    /* --- Packet templates --- */

    /* Legit */
    const char *http_get  = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const char *http_post = "POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
    const char *http_put  = "PUT /resource HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
    const char *http_head = "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    uint8_t dns_a[] = {
        0x00,0x01, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00,
        0x00,0x01, 0x00,0x01
    };
    uint8_t dns_b[] = {
        0x00,0x02, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        0x04,'t','e','s','t', 0x05,'l','o','c','a','l', 0x00,
        0x00,0x01, 0x00,0x01
    };
    uint8_t dns_c[] = {
        0x00,0x03, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        0x06,'g','o','o','g','l','e', 0x03,'c','o','m', 0x00,
        0x00,0x01, 0x00,0x01
    };

    /* Malicious */
    const char *http_on_dns  = "GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n";
    const char *bad_method   = "BADVERB / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const char *no_host      = "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
    const char *no_version   = "GET / \r\nHost: example.com\r\n\r\n";
    const char *post_on_dns  = "POST /exfil HTTP/1.1\r\nHost: evil.com\r\nContent-Length: 0\r\n\r\n";
    uint8_t trunc_dns[]      = { 0x00,0x03, 0x01,0x00 };

    int legit_count = 0;
    int mal_count   = 0;

    for (int i = 0; i < TOTAL; i++) {
        /* 40% legit (i%10 < 4), 60% malicious — interleaved */
        if (i % 10 < 4) {
            switch (legit_count % 10) {
                case 0: flen = build_tcp_frame(frame, 80,  (uint8_t *)http_get,  (uint16_t)strlen(http_get));  break;
                case 1: flen = build_tcp_frame(frame, 80,  (uint8_t *)http_post, (uint16_t)strlen(http_post)); break;
                case 2: flen = build_tcp_frame(frame, 80,  (uint8_t *)http_put,  (uint16_t)strlen(http_put));  break;
                case 3: flen = build_tcp_frame(frame, 80,  (uint8_t *)http_head, (uint16_t)strlen(http_head)); break;
                case 4: flen = build_tcp_frame(frame, 443, (uint8_t *)http_get,  (uint16_t)strlen(http_get));  break;
                case 5: flen = build_tcp_frame(frame, 443, (uint8_t *)http_post, (uint16_t)strlen(http_post)); break;
                case 6: flen = build_udp_frame(frame, 53,  dns_a, (uint16_t)sizeof(dns_a)); break;
                case 7: flen = build_udp_frame(frame, 53,  dns_b, (uint16_t)sizeof(dns_b)); break;
                case 8: flen = build_udp_frame(frame, 53,  dns_c, (uint16_t)sizeof(dns_c)); break;
                case 9: flen = build_udp_frame(frame, 53,  dns_a, (uint16_t)sizeof(dns_a)); break;
            }
            write_packet(dumper, gt, frame, flen, 0);
            legit_count++;
        } else {
            switch (mal_count % 10) {
                case 0: flen = build_udp_frame(frame, 53, (uint8_t *)http_on_dns,  (uint16_t)strlen(http_on_dns));  break;
                case 1: flen = build_tcp_frame(frame, 80, dns_a, (uint16_t)sizeof(dns_a)); break;
                case 2: flen = build_tcp_frame(frame, 80, (uint8_t *)bad_method,   (uint16_t)strlen(bad_method));   break;
                case 3: flen = build_tcp_frame(frame, 80, (uint8_t *)no_host,      (uint16_t)strlen(no_host));      break;
                case 4: flen = build_tcp_frame(frame, 80, (uint8_t *)"", 0); break;
                case 5: flen = build_udp_frame(frame, 53, trunc_dns, (uint16_t)sizeof(trunc_dns)); break;
                case 6: flen = build_udp_frame(frame, 53, (uint8_t *)post_on_dns,  (uint16_t)strlen(post_on_dns));  break;
                case 7: flen = build_tcp_frame(frame, 80, (uint8_t *)no_version,   (uint16_t)strlen(no_version));   break;
                case 8: flen = build_tcp_frame(frame, 80, dns_b, (uint16_t)sizeof(dns_b)); break;
                case 9: flen = build_udp_frame(frame, 53, trunc_dns, (uint16_t)sizeof(trunc_dns)); break;
            }
            write_packet(dumper, gt, frame, flen, 1);
            mal_count++;
        }
    }

    fclose(gt);
    pcap_dump_close(dumper);
    pcap_close(dead);

    printf("traffic_gen: wrote %s and %s\n", PCAP_OUT, GT_OUT);
    printf("traffic_gen: %d legit packets, %d malicious packets (%d total)\n",
           legit_count, mal_count, TOTAL);
    return 0;
}

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "../src/common.h"
#include "../src/feature_extract/feature_extract.h"

/* Build a minimal Ethernet/IP/TCP frame in buf, return frame length */
static int build_tcp_frame(uint8_t *buf, uint16_t dst_port,
                            const char *payload) {
    memset(buf, 0, 256);
    uint16_t plen = (uint16_t)strlen(payload);

    /* Ethernet */
    memset(buf, 0xff, 6);          /* dst MAC */
    memset(buf + 6, 0x01, 6);      /* src MAC */
    buf[12] = 0x08; buf[13] = 0x00; /* IPv4 */

    /* IP */
    uint8_t *ip = buf + 14;
    ip[0] = 0x45;  /* version=4, IHL=5 */
    ip[9] = 6;     /* TCP */
    uint16_t tot = htons((uint16_t)(20 + 20 + plen));
    ip[2] = tot >> 8; ip[3] = tot & 0xff;

    /* TCP */
    uint8_t *tcp = ip + 20;
    tcp[0] = 0x30; tcp[1] = 0x39; /* src_port = 12345 */
    tcp[2] = dst_port >> 8; tcp[3] = dst_port & 0xff;
    tcp[12] = 0x50; /* data offset = 5 */

    /* Payload */
    memcpy(tcp + 20, payload, plen);

    return 14 + 20 + 20 + plen;
}

static int build_udp_frame(uint8_t *buf, uint16_t dst_port,
                            const uint8_t *payload, uint16_t plen) {
    memset(buf, 0, 256);

    /* Ethernet */
    memset(buf, 0xff, 6);
    memset(buf + 6, 0x01, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    /* IP */
    uint8_t *ip = buf + 14;
    ip[0] = 0x45;
    ip[9] = 17; /* UDP */
    uint16_t tot = htons((uint16_t)(20 + 8 + plen));
    ip[2] = tot >> 8; ip[3] = tot & 0xff;

    /* UDP */
    uint8_t *udp = ip + 20;
    udp[0] = 0xD4; udp[1] = 0x31; /* src_port = 54321 */
    udp[2] = dst_port >> 8; udp[3] = dst_port & 0xff;

    memcpy(udp + 8, payload, plen);
    return 14 + 20 + 8 + plen;
}

/* Happy path: TCP frame — correct port and payload extraction */
static void test_tcp_ports_and_payload(void) {
    uint8_t buf[256];
    const char *pl = "GET / HTTP/1.1\r\nHost: x.com\r\n\r\n";
    int flen = build_tcp_frame(buf, 80, pl);

    PacketFeatures pkt;
    int rc = feature_extract(buf, (uint32_t)flen, 0, &pkt);
    assert(rc == 0);
    assert(pkt.dst_port == 80);
    assert(pkt.src_port == 12345);
    assert(pkt.protocol == 6);
    assert(pkt.payload_len == (uint32_t)strlen(pl));
    printf("PASS test_tcp_ports_and_payload\n");
}

/* Happy path: UDP frame */
static void test_udp_port(void) {
    uint8_t buf[256];
    uint8_t dns[] = { 0x00,0x01,0x01,0x00,0x00,0x01,0x00,0x00,
                      0x00,0x00,0x00,0x00 };
    int flen = build_udp_frame(buf, 53, dns, sizeof(dns));

    PacketFeatures pkt;
    int rc = feature_extract(buf, (uint32_t)flen, 1, &pkt);
    assert(rc == 0);
    assert(pkt.dst_port == 53);
    assert(pkt.protocol == 17);
    assert(pkt.payload_len == sizeof(dns));
    printf("PASS test_udp_port\n");
}

/* Edge: frame too short — must return error */
static void test_short_frame(void) {
    uint8_t buf[10] = { 0 };
    PacketFeatures pkt;
    int rc = feature_extract(buf, 10, 0, &pkt);
    assert(rc == -1);
    printf("PASS test_short_frame\n");
}

/* Edge: zero-length payload on TCP frame */
static void test_zero_payload(void) {
    uint8_t buf[256];
    int flen = build_tcp_frame(buf, 443, "");

    PacketFeatures pkt;
    int rc = feature_extract(buf, (uint32_t)flen, 0, &pkt);
    assert(rc == 0);
    assert(pkt.payload_len == 0);
    printf("PASS test_zero_payload\n");
}

int main(void) {
    test_tcp_ports_and_payload();
    test_udp_port();
    test_short_frame();
    test_zero_payload();
    printf("All feature_extract tests passed\n");
    return 0;
}

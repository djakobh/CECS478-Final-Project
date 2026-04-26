#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../src/common.h"
#include "../src/dns_validator/dns_validator.h"

/* Minimal valid DNS query for example.com */
static uint8_t VALID_DNS[] = {
    0x00, 0x01, 0x01, 0x00,  /* ID + flags */
    0x00, 0x01,              /* QDCOUNT=1 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* AN/NS/AR = 0 */
    0x07,'e','x','a','m','p','l','e',
    0x03,'c','o','m',
    0x00,                    /* end of name */
    0x00, 0x01, 0x00, 0x01   /* QTYPE=A QCLASS=IN */
};

static PacketFeatures make_udp_pkt(int dst_port,
                                   const uint8_t *payload, uint32_t plen) {
    PacketFeatures p;
    memset(&p, 0, sizeof(p));
    p.protocol = 17;
    p.src_port = 54321;
    p.dst_port = dst_port;
    p.payload_len = plen;
    memcpy(p.payload, payload, plen);
    return p;
}

/* Happy path: valid DNS query */
static void test_valid_query(void) {
    PacketFeatures p = make_udp_pkt(53, VALID_DNS, sizeof(VALID_DNS));
    ValidationResult r = dns_validate(&p);
    assert(r.is_valid == 1);
    printf("PASS test_valid_query\n");
}

/* Negative: wrong port */
static void test_wrong_port(void) {
    PacketFeatures p = make_udp_pkt(80, VALID_DNS, sizeof(VALID_DNS));
    ValidationResult r = dns_validate(&p);
    assert(r.is_valid == 0);
    printf("PASS test_wrong_port\n");
}

/* Edge: truncated header (only 4 bytes) */
static void test_truncated_header(void) {
    uint8_t trunc[] = { 0x00, 0x01, 0x01, 0x00 };
    PacketFeatures p = make_udp_pkt(53, trunc, sizeof(trunc));
    ValidationResult r = dns_validate(&p);
    assert(r.is_valid == 0);
    printf("PASS test_truncated_header\n");
}

/* Edge: QDCOUNT = 0 */
static void test_qdcount_zero(void) {
    uint8_t zero_qd[sizeof(VALID_DNS)];
    memcpy(zero_qd, VALID_DNS, sizeof(VALID_DNS));
    zero_qd[4] = 0x00;
    zero_qd[5] = 0x00; /* QDCOUNT = 0 */
    PacketFeatures p = make_udp_pkt(53, zero_qd, sizeof(zero_qd));
    ValidationResult r = dns_validate(&p);
    assert(r.is_valid == 0);
    printf("PASS test_qdcount_zero\n");
}

/* Negative: HTTP payload on port 53 */
static void test_http_on_dns_port(void) {
    const char *http = "GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n";
    PacketFeatures p = make_udp_pkt(53, (const uint8_t *)http,
                                    (uint32_t)strlen(http));
    ValidationResult r = dns_validate(&p);
    /* HTTP text won't have a valid null-terminated DNS name */
    assert(r.is_valid == 0);
    printf("PASS test_http_on_dns_port\n");
}

int main(void) {
    test_valid_query();
    test_wrong_port();
    test_truncated_header();
    test_qdcount_zero();
    test_http_on_dns_port();
    printf("All dns_validator tests passed\n");
    return 0;
}

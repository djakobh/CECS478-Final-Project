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

/* Subtle: QR bit set (response masquerading as query) must be rejected */
static void test_qr_bit_set(void) {
    uint8_t pkt[sizeof(VALID_DNS)];
    memcpy(pkt, VALID_DNS, sizeof(VALID_DNS));
    pkt[2] |= 0x80; /* set QR bit */
    PacketFeatures p = make_udp_pkt(53, pkt, sizeof(pkt));
    ValidationResult r = dns_validate(&p);
    assert(r.is_valid == 0);
    printf("PASS test_qr_bit_set\n");
}

/* Subtle: label longer than 32 bytes (DNS tunneling) must be rejected */
static void test_long_label(void) {
    uint8_t pkt[128];
    /* Header: ID + standard query flags + QDCOUNT=1 + zeroes */
    uint8_t hdr[] = { 0x00,0x10, 0x01,0x00, 0x00,0x01,
                      0x00,0x00, 0x00,0x00, 0x00,0x00 };
    memcpy(pkt, hdr, 12);
    uint32_t off = 12;
    pkt[off++] = 40; /* 40-byte label — exceeds 32-byte heuristic */
    memset(pkt + off, 'A', 40);
    off += 40;
    pkt[off++] = 0x03; pkt[off++] = 'c'; pkt[off++] = 'o'; pkt[off++] = 'm';
    pkt[off++] = 0x00;
    pkt[off++] = 0x00; pkt[off++] = 0x01; /* QTYPE=A */
    pkt[off++] = 0x00; pkt[off++] = 0x01; /* QCLASS=IN */
    PacketFeatures p = make_udp_pkt(53, pkt, off);
    ValidationResult r = dns_validate(&p);
    assert(r.is_valid == 0);
    printf("PASS test_long_label\n");
}

/* Subtle: unrecognized QTYPE must be rejected */
static void test_invalid_qtype(void) {
    uint8_t pkt[sizeof(VALID_DNS)];
    memcpy(pkt, VALID_DNS, sizeof(VALID_DNS));
    /* QTYPE is the 2 bytes after the null terminator of the name.
       In VALID_DNS the name ends at byte 24 (the 0x00), so QTYPE is at 25-26. */
    pkt[sizeof(VALID_DNS) - 4] = 0x00;
    pkt[sizeof(VALID_DNS) - 3] = 0x00; /* QTYPE = 0 — invalid */
    PacketFeatures p = make_udp_pkt(53, pkt, sizeof(pkt));
    ValidationResult r = dns_validate(&p);
    assert(r.is_valid == 0);
    printf("PASS test_invalid_qtype\n");
}

int main(void) {
    test_valid_query();
    test_wrong_port();
    test_truncated_header();
    test_qdcount_zero();
    test_http_on_dns_port();
    test_qr_bit_set();
    test_long_label();
    test_invalid_qtype();
    printf("All dns_validator tests passed\n");
    return 0;
}

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../src/common.h"
#include "../src/http_validator/http_validator.h"

static PacketFeatures make_tcp_pkt(int dst_port, const char *payload) {
    PacketFeatures p;
    memset(&p, 0, sizeof(p));
    p.protocol = 6;
    p.src_port = 12345;
    p.dst_port = dst_port;
    p.payload_len = (uint32_t)strlen(payload);
    memcpy(p.payload, payload, p.payload_len);
    return p;
}

/* Happy path: valid GET request */
static void test_valid_get(void) {
    PacketFeatures p = make_tcp_pkt(80,
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    ValidationResult r = http_validate(&p);
    assert(r.is_valid == 1);
    printf("PASS test_valid_get\n");
}

/* Happy path: valid POST request */
static void test_valid_post(void) {
    PacketFeatures p = make_tcp_pkt(80,
        "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n");
    ValidationResult r = http_validate(&p);
    assert(r.is_valid == 1);
    printf("PASS test_valid_post\n");
}

/* Negative: missing Host header */
static void test_missing_host(void) {
    PacketFeatures p = make_tcp_pkt(80,
        "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n");
    ValidationResult r = http_validate(&p);
    assert(r.is_valid == 0);
    printf("PASS test_missing_host\n");
}

/* Negative: invalid method */
static void test_bad_method(void) {
    PacketFeatures p = make_tcp_pkt(80,
        "BADVERB / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    ValidationResult r = http_validate(&p);
    assert(r.is_valid == 0);
    printf("PASS test_bad_method\n");
}

/* Edge: empty payload */
static void test_empty_payload(void) {
    PacketFeatures p = make_tcp_pkt(80, "");
    p.payload_len = 0;
    ValidationResult r = http_validate(&p);
    assert(r.is_valid == 0);
    printf("PASS test_empty_payload\n");
}

/* Edge: wrong port (UDP port 53) */
static void test_wrong_port(void) {
    PacketFeatures p = make_tcp_pkt(53,
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    ValidationResult r = http_validate(&p);
    assert(r.is_valid == 0);
    printf("PASS test_wrong_port\n");
}

/* Subtle: non-standard HTTP version (1.9) must be rejected */
static void test_invalid_http_version(void) {
    PacketFeatures p = make_tcp_pkt(80,
        "GET / HTTP/1.9\r\nHost: example.com\r\n\r\n");
    ValidationResult r = http_validate(&p);
    assert(r.is_valid == 0);
    printf("PASS test_invalid_http_version\n");
}

/* Subtle: null byte anywhere in payload must be rejected */
static void test_null_byte_payload(void) {
    PacketFeatures p;
    memset(&p, 0, sizeof(p));
    p.protocol = 6;
    p.src_port = 12345;
    p.dst_port = 80;
    /* Valid HTTP headers followed by null byte + binary */
    const char *prefix = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    uint32_t plen = (uint32_t)strlen(prefix);
    memcpy(p.payload, prefix, plen);
    p.payload[plen]     = 0x00;
    p.payload[plen + 1] = 'X';
    p.payload_len = plen + 2;
    ValidationResult r = http_validate(&p);
    assert(r.is_valid == 0);
    printf("PASS test_null_byte_payload\n");
}

/* Subtle: duplicate Content-Length (request smuggling) must be rejected */
static void test_duplicate_content_length(void) {
    PacketFeatures p = make_tcp_pkt(80,
        "POST /upload HTTP/1.1\r\nHost: example.com\r\n"
        "Content-Length: 0\r\nContent-Length: 999\r\n\r\n");
    ValidationResult r = http_validate(&p);
    assert(r.is_valid == 0);
    printf("PASS test_duplicate_content_length\n");
}

int main(void) {
    test_valid_get();
    test_valid_post();
    test_missing_host();
    test_bad_method();
    test_empty_payload();
    test_wrong_port();
    test_invalid_http_version();
    test_null_byte_payload();
    test_duplicate_content_length();
    printf("All http_validator tests passed\n");
    return 0;
}

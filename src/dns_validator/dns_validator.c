#include "dns_validator.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#define DNS_HDR_MIN 12

ValidationResult dns_validate(const PacketFeatures *pkt) {
    ValidationResult r = { 0, "" };

    /* Rule 1: must be UDP (or TCP on port 53 for DNS-over-TCP) */
    if (pkt->protocol != 17 && pkt->protocol != 6) {
        snprintf(r.reason, sizeof(r.reason), "unsupported protocol %d", pkt->protocol);
        return r;
    }

    /* Rule 2: dst port must be 53 */
    if (pkt->dst_port != 53) {
        snprintf(r.reason, sizeof(r.reason), "dst_port=%d not 53", pkt->dst_port);
        return r;
    }

    /* Rule 3: payload must be at least 12 bytes (DNS header) */
    if (pkt->payload_len < DNS_HDR_MIN) {
        snprintf(r.reason, sizeof(r.reason),
                 "payload too short (%u < 12)", pkt->payload_len);
        return r;
    }

    const uint8_t *p = pkt->payload;

    /* Rule 4: QDCOUNT (bytes 4-5, big-endian) must be > 0 */
    uint16_t qdcount = (uint16_t)((p[4] << 8) | p[5]);
    if (qdcount == 0) {
        snprintf(r.reason, sizeof(r.reason), "QDCOUNT=0");
        return r;
    }

    /* Rule 5: question name must be valid length-prefixed labels ending with 0x00 */
    uint32_t offset = DNS_HDR_MIN;
    int label_ok = 0;
    while (offset < pkt->payload_len) {
        uint8_t label_len = p[offset];
        if (label_len == 0) {
            label_ok = 1;
            break;
        }
        /* Reject compression pointers (0xC0) as invalid in a generated query */
        if (label_len & 0xC0) {
            snprintf(r.reason, sizeof(r.reason),
                     "compression pointer in question name at offset %u", offset);
            return r;
        }
        offset += 1 + label_len;
        if (offset >= pkt->payload_len) break;
    }

    if (!label_ok) {
        snprintf(r.reason, sizeof(r.reason), "question name not null-terminated");
        return r;
    }

    r.is_valid = 1;
    snprintf(r.reason, sizeof(r.reason), "valid DNS");
    return r;
}

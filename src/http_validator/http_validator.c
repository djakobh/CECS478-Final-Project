#include "http_validator.h"
#include <string.h>
#include <stdio.h>

static const char *VALID_METHODS[] = {
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", NULL
};

ValidationResult http_validate(const PacketFeatures *pkt) {
    ValidationResult r = { 0, "" };

    /* Rule 1: must be TCP */
    if (pkt->protocol != 6) {
        snprintf(r.reason, sizeof(r.reason), "not TCP (proto=%d)", pkt->protocol);
        return r;
    }

    /* Rule 2: dst port must be 80 or 443 */
    if (pkt->dst_port != 80 && pkt->dst_port != 443) {
        snprintf(r.reason, sizeof(r.reason),
                 "dst_port=%d not 80 or 443", pkt->dst_port);
        return r;
    }

    /* Rule 3: payload must be non-empty */
    if (pkt->payload_len == 0) {
        snprintf(r.reason, sizeof(r.reason), "empty payload");
        return r;
    }

    /* Rule 8: no null bytes anywhere in payload (null byte injection) */
    if (memchr(pkt->payload, '\0', pkt->payload_len)) {
        snprintf(r.reason, sizeof(r.reason), "null byte in payload");
        return r;
    }

    /* Null-terminate a copy for string ops (safe — payload is bounded) */
    char buf[MAX_PAYLOAD + 1];
    uint32_t len = pkt->payload_len < MAX_PAYLOAD ? pkt->payload_len : MAX_PAYLOAD;
    memcpy(buf, pkt->payload, len);
    buf[len] = '\0';

    /* Rule 4: must start with a valid HTTP method */
    int method_ok = 0;
    for (int i = 0; VALID_METHODS[i]; i++) {
        if (strncmp(buf, VALID_METHODS[i], strlen(VALID_METHODS[i])) == 0) {
            method_ok = 1;
            break;
        }
    }
    if (!method_ok) {
        snprintf(r.reason, sizeof(r.reason), "invalid HTTP method");
        return r;
    }

    /* Rule 5: must contain a recognized HTTP version (1.0, 1.1, or 2) */
    if (!strstr(buf, "HTTP/1.0") && !strstr(buf, "HTTP/1.1") &&
        !strstr(buf, "HTTP/2")) {
        snprintf(r.reason, sizeof(r.reason), "invalid or missing HTTP version");
        return r;
    }

    /* Rule 6: must contain Host: header */
    if (!strstr(buf, "Host:") && !strstr(buf, "host:")) {
        snprintf(r.reason, sizeof(r.reason), "missing Host header");
        return r;
    }

    /* Rule 7: must contain at least one Key: value style header (beyond request line) */
    char *crlf = strstr(buf, "\r\n");
    if (!crlf || !strstr(crlf + 2, ":")) {
        snprintf(r.reason, sizeof(r.reason), "no headers found after request line");
        return r;
    }

    /* Rule 9: duplicate Content-Length header indicates request smuggling */
    {
        int cl_count = 0;
        const char *p = buf;
        while ((p = strstr(p, "Content-Length:")) != NULL) {
            cl_count++;
            p++;
        }
        if (cl_count > 1) {
            snprintf(r.reason, sizeof(r.reason),
                     "duplicate Content-Length header (request smuggling)");
            return r;
        }
    }

    r.is_valid = 1;
    snprintf(r.reason, sizeof(r.reason), "valid HTTP");
    return r;
}

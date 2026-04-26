#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../src/common.h"
#include "../src/detector/detector.h"

static PacketFeatures make_http_pkt(void) {
    PacketFeatures p;
    memset(&p, 0, sizeof(p));
    p.protocol = 6;
    p.dst_port = 80;
    const char *pl = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    p.payload_len = (uint32_t)strlen(pl);
    memcpy(p.payload, pl, p.payload_len);
    p.ground_truth_malicious = 0;
    return p;
}

static PacketFeatures make_malicious_pkt(void) {
    PacketFeatures p;
    memset(&p, 0, sizeof(p));
    p.protocol = 6;
    p.dst_port = 80;
    const char *pl = "BADVERB / HTTP/1.1\r\nHost: evil.com\r\n\r\n";
    p.payload_len = (uint32_t)strlen(pl);
    memcpy(p.payload, pl, p.payload_len);
    p.ground_truth_malicious = 1;
    return p;
}

/* Happy path: legit HTTP packet should not be flagged */
static void test_legit_not_flagged(void) {
    PacketFeatures p = make_http_pkt();
    int predicted;
    char reason[256];
    detector_classify(&p, &predicted, reason, sizeof(reason));
    assert(predicted == 0);
    printf("PASS test_legit_not_flagged\n");
}

/* Negative: malicious packet should be flagged */
static void test_malicious_flagged(void) {
    PacketFeatures p = make_malicious_pkt();
    int predicted;
    char reason[256];
    detector_classify(&p, &predicted, reason, sizeof(reason));
    assert(predicted == 1);
    printf("PASS test_malicious_flagged\n");
}

/* Metrics: all legit → no false positives */
static void test_metrics_all_legit(void) {
    Metrics m;
    memset(&m, 0, sizeof(m));
    for (int i = 0; i < 5; i++) {
        PacketFeatures p = make_http_pkt();
        int predicted;
        char reason[256];
        detector_classify(&p, &predicted, reason, sizeof(reason));
        detector_update_metrics(&m, predicted, 0);
    }
    detector_finalise_metrics(&m, 1.0);
    assert(m.fp == 0);
    assert(m.tn == 5);
    printf("PASS test_metrics_all_legit\n");
}

/* Metrics: all malicious → no false negatives */
static void test_metrics_all_malicious(void) {
    Metrics m;
    memset(&m, 0, sizeof(m));
    for (int i = 0; i < 3; i++) {
        PacketFeatures p = make_malicious_pkt();
        int predicted;
        char reason[256];
        detector_classify(&p, &predicted, reason, sizeof(reason));
        detector_update_metrics(&m, predicted, 1);
    }
    detector_finalise_metrics(&m, 1.0);
    assert(m.fn == 0);
    assert(m.tp == 3);
    printf("PASS test_metrics_all_malicious\n");
}

int main(void) {
    test_legit_not_flagged();
    test_malicious_flagged();
    test_metrics_all_legit();
    test_metrics_all_malicious();
    printf("All detector tests passed\n");
    return 0;
}

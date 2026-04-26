#include "detector.h"
#include "../http_validator/http_validator.h"
#include "../dns_validator/dns_validator.h"
#include <string.h>
#include <stdio.h>

int detector_classify(const PacketFeatures *pkt,
                      int *predicted_malicious,
                      char *reason, int reason_len) {
    ValidationResult http = http_validate(pkt);
    ValidationResult dns  = dns_validate(pkt);

    if (http.is_valid) {
        *predicted_malicious = 0;
        snprintf(reason, reason_len, "http: %s", http.reason);
    } else if (dns.is_valid) {
        *predicted_malicious = 0;
        snprintf(reason, reason_len, "dns: %s", dns.reason);
    } else {
        *predicted_malicious = 1;
        snprintf(reason, reason_len, "http_fail=[%s] dns_fail=[%s]",
                 http.reason, dns.reason);
    }
    return 0;
}

void detector_update_metrics(Metrics *m,
                             int predicted_malicious,
                             int ground_truth_malicious) {
    m->total++;
    if (predicted_malicious && ground_truth_malicious)  m->tp++;
    else if (predicted_malicious && !ground_truth_malicious) m->fp++;
    else if (!predicted_malicious && !ground_truth_malicious) m->tn++;
    else m->fn++;
}

void detector_finalise_metrics(Metrics *m, double ms_elapsed) {
    m->ms_elapsed = ms_elapsed;
    m->detection_rate      = (m->tp + m->fn) > 0
                             ? (double)m->tp / (m->tp + m->fn) : 0.0;
    m->false_positive_rate = (m->fp + m->tn) > 0
                             ? (double)m->fp / (m->fp + m->tn) : 0.0;
    m->accuracy            = m->total > 0
                             ? (double)(m->tp + m->tn) / m->total : 0.0;
}

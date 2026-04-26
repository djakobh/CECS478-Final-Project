#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#define MAX_PAYLOAD 1500
#define MAX_PACKETS 1000

typedef struct {
    int packet_index;
    int src_port;
    int dst_port;
    int protocol;               /* IPPROTO_TCP or IPPROTO_UDP */
    uint32_t payload_len;
    uint8_t payload[MAX_PAYLOAD];
    int ground_truth_malicious; /* 0 = legit, 1 = malicious (loaded from ground_truth.txt) */
} PacketFeatures;

typedef struct {
    int is_valid;
    char reason[256];
} ValidationResult;

typedef struct {
    int total;
    int tp;  /* true positive  — malicious correctly flagged */
    int fp;  /* false positive — legit incorrectly flagged   */
    int tn;  /* true negative  — legit correctly cleared     */
    int fn;  /* false negative — malicious missed            */
    double detection_rate;      /* tp / (tp + fn) */
    double false_positive_rate; /* fp / (fp + tn) */
    double accuracy;            /* (tp + tn) / total */
    double ms_elapsed;
} Metrics;

#endif /* COMMON_H */

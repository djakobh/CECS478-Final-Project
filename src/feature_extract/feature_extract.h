#ifndef FEATURE_EXTRACT_H
#define FEATURE_EXTRACT_H

#include "../common.h"
#include <stdint.h>

/*
 * Parse a raw Ethernet/IP/TCP-or-UDP frame into pkt.
 * Returns 0 on success, -1 if the frame is too short or unsupported.
 * pkt->ground_truth_malicious is left untouched — caller fills it.
 */
int feature_extract(const uint8_t *frame, uint32_t frame_len,
                    int index, PacketFeatures *pkt);

#endif /* FEATURE_EXTRACT_H */

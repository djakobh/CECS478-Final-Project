#ifndef DETECTOR_H
#define DETECTOR_H

#include "../common.h"

/*
 * Run both validators on pkt.
 * Sets *predicted_malicious = 1 if neither HTTP nor DNS validates.
 * Sets *reason to a short description of the verdict.
 * Returns 0 always (no fatal errors).
 */
int detector_classify(const PacketFeatures *pkt,
                      int *predicted_malicious,
                      char *reason, int reason_len);

/* Accumulate one packet result into m. */
void detector_update_metrics(Metrics *m,
                             int predicted_malicious,
                             int ground_truth_malicious);

/* Finalise ratios in m (call after all packets are processed). */
void detector_finalise_metrics(Metrics *m, double ms_elapsed);

#endif /* DETECTOR_H */

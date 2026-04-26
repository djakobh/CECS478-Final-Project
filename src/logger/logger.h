#ifndef LOGGER_H
#define LOGGER_H

#include "../common.h"

/* Open log file for writing. Returns 0 on success, -1 on failure. */
int logger_open(const char *path);

/* Log a single packet verdict with timestamp. */
void logger_log_packet(const PacketFeatures *pkt, int predicted_malicious, const char *reason);

/* Log a free-form message (info/error). */
void logger_log_message(const char *level, const char *msg);

/* Flush and close the log file. */
void logger_close(void);

#endif /* LOGGER_H */

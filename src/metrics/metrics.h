#ifndef METRICS_H
#define METRICS_H

#include "../common.h"

/* Open CSV file and write header row. Returns 0 on success, -1 on failure. */
int metrics_open_csv(const char *path);

/* Append one row for a single packet. */
void metrics_write_row(int index, int src_port, int dst_port,
                       int predicted_malicious, int ground_truth_malicious);

/* Close the CSV file. */
void metrics_close_csv(void);

/* Write the summary JSON file. Returns 0 on success, -1 on failure. */
int metrics_write_summary(const char *path, const Metrics *m);

#endif /* METRICS_H */

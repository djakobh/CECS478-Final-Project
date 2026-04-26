#include "metrics.h"
#include <stdio.h>

static FILE *csv_fp = NULL;

int metrics_open_csv(const char *path) {
    csv_fp = fopen(path, "w");
    if (!csv_fp) return -1;
    fprintf(csv_fp, "index,src_port,dst_port,predicted_malicious,actual_malicious\n");
    return 0;
}

void metrics_write_row(int index, int src_port, int dst_port,
                       int predicted_malicious, int ground_truth_malicious) {
    if (!csv_fp) return;
    fprintf(csv_fp, "%d,%d,%d,%d,%d\n",
            index, src_port, dst_port,
            predicted_malicious, ground_truth_malicious);
}

void metrics_close_csv(void) {
    if (csv_fp) { fclose(csv_fp); csv_fp = NULL; }
}

int metrics_write_summary(const char *path, const Metrics *m) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f,
        "{\n"
        "  \"total\": %d,\n"
        "  \"tp\": %d,\n"
        "  \"fp\": %d,\n"
        "  \"tn\": %d,\n"
        "  \"fn\": %d,\n"
        "  \"detection_rate\": %.4f,\n"
        "  \"false_positive_rate\": %.4f,\n"
        "  \"accuracy\": %.4f,\n"
        "  \"processing_ms\": %.2f\n"
        "}\n",
        m->total, m->tp, m->fp, m->tn, m->fn,
        m->detection_rate, m->false_positive_rate,
        m->accuracy, m->ms_elapsed);
    fclose(f);
    return 0;
}

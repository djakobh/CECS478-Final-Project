#include <stdio.h>
#include <string.h>
#include <time.h>

#include "common.h"
#include "logger/logger.h"
#include "pcap_reader/pcap_reader.h"
#include "feature_extract/feature_extract.h"
#include "detector/detector.h"
#include "metrics/metrics.h"

#define LOG_PATH     "artifacts/release/results.log"
#define CSV_PATH     "artifacts/release/metrics.csv"
#define SUMMARY_PATH "artifacts/release/summary.json"

/* Shared state passed through the pcap callback */
typedef struct {
    FILE   *gt_file;     /* ground_truth.txt handle */
    Metrics m;
    int     errors;
} PipelineCtx;

/* Path safety: reject anything with ".." or not starting with "data/" */
static int path_is_safe(const char *path) {
    if (strstr(path, "..")) return 0;
    if (strncmp(path, "data/", 5) != 0 &&
        strncmp(path, "/app/data/", 10) != 0) return 0;
    return 1;
}

static void on_packet(const uint8_t *frame, uint32_t frame_len,
                      int index, void *user) {
    PipelineCtx *ctx = (PipelineCtx *)user;

    /* Read ground truth for this packet */
    int gt = 0;
    if (fscanf(ctx->gt_file, "%d\n", &gt) != 1) {
        logger_log_message("WARN", "ground_truth.txt shorter than pcap");
        gt = 0; /* treat as legit if unknown */
    }

    PacketFeatures pkt;
    if (feature_extract(frame, frame_len, index, &pkt) != 0) {
        logger_log_message("WARN", "feature_extract failed — skipping packet");
        ctx->errors++;
        return;
    }
    pkt.ground_truth_malicious = gt;

    int predicted;
    char reason[512];
    detector_classify(&pkt, &predicted, reason, sizeof(reason));
    detector_update_metrics(&ctx->m, predicted, gt);

    logger_log_packet(&pkt, predicted, reason);
    metrics_write_row(index, pkt.src_port, pkt.dst_port, predicted, gt);
}

int main(int argc, char *argv[]) {
    const char *pcap_path = "data/capture.pcap";
    const char *gt_path   = "data/ground_truth.txt";

    if (argc >= 2) pcap_path = argv[1];
    if (argc >= 3) gt_path   = argv[2];

    /* Security: validate pcap path */
    if (!path_is_safe(pcap_path)) {
        fprintf(stderr, "error: unsafe pcap path '%s'\n", pcap_path);
        return 1;
    }

    if (logger_open(LOG_PATH) != 0) {
        fprintf(stderr, "error: cannot open log file %s\n", LOG_PATH);
        return 1;
    }
    if (metrics_open_csv(CSV_PATH) != 0) {
        fprintf(stderr, "error: cannot open csv file %s\n", CSV_PATH);
        logger_close();
        return 1;
    }

    FILE *gt_file = fopen(gt_path, "r");
    if (!gt_file) {
        fprintf(stderr, "error: cannot open ground_truth file %s\n", gt_path);
        metrics_close_csv();
        logger_close();
        return 1;
    }

    logger_log_message("INFO", "Pipeline started");

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    PipelineCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.gt_file = gt_file;

    int total = pcap_reader_run(pcap_path, on_packet, &ctx);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (double)(t1.tv_sec - t0.tv_sec) * 1000.0
              + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;

    fclose(gt_file);

    detector_finalise_metrics(&ctx.m, ms);

    metrics_close_csv();
    metrics_write_summary(SUMMARY_PATH, &ctx.m);

    /* Print summary to stdout */
    printf("=== Protocol Impersonation Detection — Results ===\n");
    printf("Packets processed : %d\n", total);
    printf("Parse errors      : %d\n", ctx.errors);
    printf("True  Positives   : %d\n", ctx.m.tp);
    printf("False Positives   : %d\n", ctx.m.fp);
    printf("True  Negatives   : %d\n", ctx.m.tn);
    printf("False Negatives   : %d\n", ctx.m.fn);
    printf("Detection rate    : %.1f%%\n", ctx.m.detection_rate * 100.0);
    printf("False positive    : %.1f%%\n", ctx.m.false_positive_rate * 100.0);
    printf("Accuracy          : %.1f%%\n", ctx.m.accuracy * 100.0);
    printf("Processing time   : %.2f ms\n", ms);
    printf("Log               : %s\n", LOG_PATH);
    printf("Metrics CSV       : %s\n", CSV_PATH);
    printf("Summary JSON      : %s\n", SUMMARY_PATH);

    logger_log_message("INFO", "Pipeline complete");
    logger_close();
    return 0;
}

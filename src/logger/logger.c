#include "logger.h"
#include <stdio.h>
#include <time.h>

static FILE *log_fp = NULL;

static void write_timestamp(void) {
    time_t now = time(NULL);
    struct tm *t = gmtime(&now);
    fprintf(log_fp, "[%04d-%02d-%02d %02d:%02d:%02d UTC] ",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec);
}

int logger_open(const char *path) {
    log_fp = fopen(path, "w");
    if (!log_fp) return -1;
    logger_log_message("INFO", "Logger started");
    return 0;
}

void logger_log_packet(const PacketFeatures *pkt, int predicted_malicious, const char *reason) {
    if (!log_fp) return;
    write_timestamp();
    fprintf(log_fp,
            "PACKET idx=%d proto=%s src_port=%d dst_port=%d payload_len=%u "
            "predicted=%s actual=%s reason=\"%s\"\n",
            pkt->packet_index,
            pkt->protocol == 6 ? "TCP" : "UDP",
            pkt->src_port,
            pkt->dst_port,
            pkt->payload_len,
            predicted_malicious ? "MALICIOUS" : "LEGIT",
            pkt->ground_truth_malicious ? "MALICIOUS" : "LEGIT",
            reason);
}

void logger_log_message(const char *level, const char *msg) {
    if (!log_fp) return;
    write_timestamp();
    fprintf(log_fp, "%s %s\n", level, msg);
}

void logger_close(void) {
    if (log_fp) {
        logger_log_message("INFO", "Logger closed");
        fclose(log_fp);
        log_fp = NULL;
    }
}

#include "pcap_reader.h"
#include <pcap/pcap.h>
#include <stdio.h>

typedef struct {
    packet_cb cb;
    void *user;
    int count;
} CallbackCtx;

static void dispatch(u_char *user, const struct pcap_pkthdr *hdr,
                     const u_char *bytes) {
    CallbackCtx *ctx = (CallbackCtx *)user;
    ctx->cb(bytes, hdr->caplen, ctx->count, ctx->user);
    ctx->count++;
}

int pcap_reader_run(const char *path, packet_cb cb, void *user) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(path, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_offline(%s): %s\n", path, errbuf);
        return -1;
    }

    CallbackCtx ctx = { cb, user, 0 };
    pcap_loop(handle, 0, dispatch, (u_char *)&ctx);
    pcap_close(handle);
    return ctx.count;
}

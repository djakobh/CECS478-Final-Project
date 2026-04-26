#ifndef PCAP_READER_H
#define PCAP_READER_H

#include "../common.h"

/*
 * Callback fired for each raw packet.
 * frame     — raw frame bytes starting at Ethernet header
 * frame_len — captured byte count
 * index     — 0-based packet number
 */
typedef void (*packet_cb)(const uint8_t *frame, uint32_t frame_len,
                          int index, void *user);

/*
 * Open a pcap file and call cb for every packet.
 * Returns total packet count on success, -1 on error.
 */
int pcap_reader_run(const char *path, packet_cb cb, void *user);

#endif /* PCAP_READER_H */

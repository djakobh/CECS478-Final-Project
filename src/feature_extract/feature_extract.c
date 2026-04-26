#include "feature_extract.h"
#include <string.h>
#include <arpa/inet.h>

/* Minimum frame sizes */
#define ETH_HDR_LEN  14
#define IP_HDR_LEN   20
#define TCP_HDR_LEN  20
#define UDP_HDR_LEN   8

int feature_extract(const uint8_t *frame, uint32_t frame_len,
                    int index, PacketFeatures *pkt) {
    memset(pkt, 0, sizeof(PacketFeatures));
    pkt->packet_index = index;

    if (frame_len < ETH_HDR_LEN + IP_HDR_LEN)
        return -1;

    /* Ethernet: check EtherType = IPv4 (0x0800) */
    uint16_t ethertype = (uint16_t)((frame[12] << 8) | frame[13]);
    if (ethertype != 0x0800)
        return -1;

    const uint8_t *ip = frame + ETH_HDR_LEN;

    /* IP: version must be 4, IHL must be 5 (no options — simple packets) */
    uint8_t ihl = (ip[0] & 0x0f) * 4;
    if ((ip[0] >> 4) != 4 || ihl < IP_HDR_LEN)
        return -1;

    pkt->protocol = ip[9]; /* IPPROTO_TCP=6, IPPROTO_UDP=17 */

    if (pkt->protocol == 6) {
        /* TCP */
        if (frame_len < ETH_HDR_LEN + ihl + TCP_HDR_LEN)
            return -1;

        const uint8_t *tcp = ip + ihl;
        pkt->src_port = (tcp[0] << 8) | tcp[1];
        pkt->dst_port = (tcp[2] << 8) | tcp[3];

        uint8_t tcp_hdr_len = ((tcp[12] >> 4) & 0xf) * 4;
        if (tcp_hdr_len < TCP_HDR_LEN)
            return -1;

        const uint8_t *payload = tcp + tcp_hdr_len;
        uint32_t payload_offset = (uint32_t)(ETH_HDR_LEN + ihl + tcp_hdr_len);
        pkt->payload_len = (frame_len > payload_offset) ? frame_len - payload_offset : 0;
        if (pkt->payload_len > MAX_PAYLOAD)
            pkt->payload_len = MAX_PAYLOAD;
        memcpy(pkt->payload, payload, pkt->payload_len);

    } else if (pkt->protocol == 17) {
        /* UDP */
        if (frame_len < ETH_HDR_LEN + ihl + UDP_HDR_LEN)
            return -1;

        const uint8_t *udp = ip + ihl;
        pkt->src_port = (udp[0] << 8) | udp[1];
        pkt->dst_port = (udp[2] << 8) | udp[3];

        const uint8_t *payload = udp + UDP_HDR_LEN;
        uint32_t payload_offset = (uint32_t)(ETH_HDR_LEN + ihl + UDP_HDR_LEN);
        pkt->payload_len = (frame_len > payload_offset) ? frame_len - payload_offset : 0;
        if (pkt->payload_len > MAX_PAYLOAD)
            pkt->payload_len = MAX_PAYLOAD;
        memcpy(pkt->payload, payload, pkt->payload_len);

    } else {
        return -1; /* unsupported protocol */
    }

    return 0;
}

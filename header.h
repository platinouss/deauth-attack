#include <pcap.h>
#include <libnet.h>

#define RADIOTAP_LEN 12
#define MAC_ADDR_LEN 6

#ifndef HEADER_H
#define HEADER_H

#pragma pack(push, 1)

struct Radiotaps {
    uint8_t revision = 0x00;
    uint8_t pad = 0x00;
    uint16_t len = 0x000c;
    uint32_t present_flag = 0x008004;
    uint32_t data = 0x020018;
};

struct Deaut_frame {
    uint8_t type = 0xc0;
    uint8_t subtype = 0x00;
    uint16_t duration = 0x0000;
    u_char recv_dst_addr[MAC_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    u_char trans_src_addr[MAC_ADDR_LEN];
    u_char bssid_addr[MAC_ADDR_LEN];
    uint16_t frag_sequence_num = 0x1000;
};

struct Fixed_param {
    uint16_t reason_code = 0x0007;
};

#pragma pack(pop)
#endif // HEADER_H

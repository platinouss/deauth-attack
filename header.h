#include <pcap.h>
#include <libnet.h>

#define RADIOTAP_LEN 12
#define MAC_ADDR_LEN 6

#ifndef HEADER_H
#define HEADER_H

struct Radiotap {
    u_char radio_tap[RADIOTAP_LEN] = { };
};

struct Deaut_frame {
    uint16_t type = 0x000c;
    uint16_t duration = 0;
    u_char recv_dst_addr[MAC_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    u_char trans_src_bssid_addr[MAC_ADDR_LEN];
    uint16_t frag_sequence_num = 0x1000;
};

struct Fixed_param {
    uint16_t reason_code = 0x0007;
};

struct Deauth_packet final {
    Radiotap rtap;
    Deaut_frame d_frame;
    Fixed_param fixed_param;
};

#endif // HEADER_H

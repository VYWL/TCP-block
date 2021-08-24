#include "functions.h"

int main(int argc, char* argv[]) {
	if (argc <= 3) {
		usage();
		return -1;
	}

	// open
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// Do tasks
	block(handle);

	// close
	pcap_close(handle);
}

void block(pcap_t *handle) {

	// std::string msg = "Host: "


	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		// Capture Packet
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		// check Validation
		// if(!isValidPacket(packet)) continue;

		// Generate Packet
		// const u_char *blockingPacket = genBlockingTCP(packet);

		// Send Packet


	}
}
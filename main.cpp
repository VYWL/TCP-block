#include "functions.h"


int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

	// init
	init(argv);

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
		if(!isValidPacket(packet)) continue;

		// Print RAW TCP Packet
		// newLine();
		// printf("RAW\n");
		// printTCP(packet);

		// Generate Packet
		u_char *forwardPacket = genBlockingForward(packet, FORWARD_FIN_ACK);

		// Print MODIFIED TCP Packet
		// newLine();
		// printf("MODIFIED\n");
		// printTCP(forwardPacket);

		// const u_char *backwardPacket = genBlockingBackward(packet, BACKWARD_RST_FIN, msg.c_str());

		// Send Packet
		int forwardPacketSize = sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr);
		sendPacket(forwardPacket, forwardPacketSize, handle);
		// sendPacket(backwardPacket, handle);

		// Free new
		free(forwardPacket);
		// free(backwardPacket);

	}
}

u_char *genBlockingForward(const u_char *packet, int flag) {
	// 먼저 패킷크기에 해당하는 만큼 deep copy

	uint32_t packetLen = SIZE_OF_PACKET;
	u_char *forwardPacket = (u_char *)malloc(packetLen);
	memcpy(forwardPacket, packet, packetLen);


	// 반환 패킷을 shallow copy => 수정에 용이하도록
	Packet *packetClone = makePacket();
	setPacket(packetClone, forwardPacket);

	// FORWARD는 무조건 RST를 보내기에 data는 추가부분이 없음

	// FORWARD의 TCP헤더는 flag와 크기를 수정해야함(RST). 이때 SYN은 RESET
	packetClone->_tcpHdr->_flags = flag;
	packetClone->_tcpHdr->_winSz = 0;
	// flag = FORWARD_RST_ACK;
	// windowsize = 0;

	// FORWARD의 IP헤더는 길이만을 수정해주면 된다.
	packetClone->_ipHdr->_totLen = sizeof(IpHdr) + sizeof(TcpHdr);
	// len = sizeof(IP) + sizeof(TCP);

	// FORWARD의 IP 및 TCP의 Checksum 계산을 수행해준다.
	setTcpCheckSum(packetClone->_ipHdr, packetClone->_tcpHdr, nullptr, 0);
	setIpCheckSum(packetClone->_ipHdr);

	// FORWARD의 Ether헤더는 smac과 dmac을 수정해준다.
	// 기존에 계산해 두었던 mymac을 smac에 넣어주는게 전부이다.
	memcpy(packetClone->_ethHdr->_smac, myMac, MAC_ALEN);

	free(packetClone);

	return forwardPacket;
}

u_char *genBlockingBackward(const u_char *packet, int flag, const char *msg) {
	// 먼저 패킷크기에 해당하는 만큼 deep copy

	// BACKWARD는 FIN를 보내는 경우에 한해서 data를 추가.
	// len = sizeof

	// BACKWARD의 TCP헤더는 flag와 크기를 수정해야함(RST). 이때 SYN은 RESET
	// flag = BACKWARD_RST_ACK or BACKWARD_FIN_ACK;
	// windowsize = 0;

	// BACKWARD의 IP헤더는 길이만을 수정해주면 된다.
	// len = sizeof(IP) + sizeof(TCP);

	// BACKWARD의 IP 및 TCP의 Checksum 계산을 수행해준다.

	// BACKWARD의 Ether헤더는 smac과 dmac을 수정해준다.
	// 기존에 계산해 두었던 mymac을 smac에 넣어주는게 전부이다
	// dmac은 Packet의 smac을 사용한다.

}

void sendPacket(u_char *packet, int size, pcap_t *handle) {

	printf("SENT!\n");
	printTCP(packet);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), size);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		fprintf(stderr, "Size : %lu\n", size);
		exit(-1);
	}
}

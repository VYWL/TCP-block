#include "functions.h"

const uint32_t SIZE_OF_PACKET = (uint32_t)sizeof(EthHdr) + (uint32_t)sizeof(IpHdr) + (uint32_t)sizeof(TcpHdr);
const char *msg = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
const uint32_t SIZE_OF_PACKET_WITH_MSG = SIZE_OF_PACKET + strlen(msg);
char *hostName;
uint8_t myMac[6];
std::vector<int> pi;

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"HOST: test.com\" \n");
}

void init(char* argv[]) {
	// Set target host
	setTarget(argv[2]);

	// Get host pi
	getPi(argv[2]);

	// Get MyMac
	getMyMacAddr(argv[1]);
}

void block(pcap_t *handle) {

	// 지속적으로 Packet Capture
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

		// check Validation :: IP - TCP - Payload Check
		if(!isValidPacket(packet)) continue;

		// Port check
		bool isHTTP = checkHTTP(packet);

		// Generate Packet
		u_char *forwardPacket = genBlockingForward(packet, FORWARD_RST_ACK);

		u_char *backwardPacket = nullptr;

		if(isHTTP)
			backwardPacket = genBlockingBackward(packet, BACKWARD_FIN_ACK, msg);
		else
			backwardPacket = genBlockingBackward(packet, BACKWARD_RST_ACK, nullptr);

		// Send Packet
		sendPacket(forwardPacket, SIZE_OF_PACKET, handle, 0);

		if(isHTTP)
			sendPacket(backwardPacket, SIZE_OF_PACKET_WITH_MSG, handle, PRINT_DETAIL);
		else
			sendPacket(backwardPacket, SIZE_OF_PACKET, handle, PRINT_DETAIL);

		// Free new
		free(forwardPacket);
		free(backwardPacket);

	}
}

bool checkHTTP(const u_char *packet) {
	packet += ETHERNET_HEADER_SIZE;
	auto ipHdrLen = ((IpHdr *)(packet))->_hlen * 4;
	TcpHdr *tcpHdr = (TcpHdr *)(packet + ipHdrLen);

	return ntohs(tcpHdr->_dPort) == 80;
}

u_char *genBlockingForward(const u_char *packet, int flag) {

	// 먼저 패킷크기에 해당하는 만큼 deep copy
	u_char *forwardPacket = (u_char *)malloc(SIZE_OF_PACKET);
	memcpy(forwardPacket, packet, SIZE_OF_PACKET);

	// 반환할 패킷을 shallow copy => 수정에 용이하도록
	Packet *packetClone = makePacket();
	setPacket(packetClone, forwardPacket);

	// FORWARD의 TCP헤더는 flag와 크기를 수정해야함(RST). 이때 SYN은 Disable
	auto dataLen = ntohs(packetClone->_ipHdr->_totLen) - (packetClone->_ipHdr->_hlen + packetClone->_tcpHdr->_offset) * 4;
	packetClone->_tcpHdr->_flags 	= flag;
	packetClone->_tcpHdr->_seq		= htonl(ntohl(packetClone->_tcpHdr->_seq) + dataLen);
	packetClone->_tcpHdr->_offset 	= 5;
	packetClone->_tcpHdr->_urgP   	= 0;
	packetClone->_tcpHdr->_unused 	= 0;

	// FORWARD의 IP헤더는 길이만을 수정해주면 된다.
	packetClone->_ipHdr->_totLen = htons(sizeof(IpHdr) + sizeof(TcpHdr));

	// FORWARD의 IP 및 TCP의 Checksum 계산을 수행해준다.
	setTcpCheckSum(packetClone->_ipHdr, packetClone->_tcpHdr, nullptr, 0);
	setIpCheckSum(packetClone->_ipHdr);

	// 수정용도로 할당했던 패킷 메모리 해제
	free(packetClone);

	return forwardPacket;
}

u_char *genBlockingBackward(const u_char *packet, int flag, const char *_msg) {

	// 먼저 패킷크기에 해당하는 만큼 deep copy
	u_char *backwardPacket = NULL;
	if (flag == BACKWARD_FIN_ACK)
		backwardPacket = (u_char *)malloc(SIZE_OF_PACKET_WITH_MSG * sizeof(u_char));
	if (flag == BACKWARD_RST_ACK)
		backwardPacket = (u_char *)malloc(SIZE_OF_PACKET * sizeof(u_char));
	
	memcpy(backwardPacket, packet, SIZE_OF_PACKET);

	// 반환 패킷을 shallow copy => 수정에 용이하도록
	Packet *  packetClone = makePacket();
	setPacket(packetClone, backwardPacket);

	// BACKWARD는 FIN를 보내는 경우에 한해서 data를 추가.
	if (flag == BACKWARD_FIN_ACK) {
		u_char *payload = (u_char *)(backwardPacket + SIZE_OF_PACKET);
		memcpy(payload, _msg, strlen(_msg));
	}

	// BACKWARD의 TCP헤더는 flag와 크기를 수정해야함(RST). 이때 SYN은 RESET
	std::swap(packetClone->_tcpHdr->_dPort,	packetClone->_tcpHdr->_sPort);
	std::swap(packetClone->_tcpHdr->_seq,	packetClone->_tcpHdr->_ack);
	packetClone->_tcpHdr->_flags	= flag;
	packetClone->_tcpHdr->_offset	= 5;
	packetClone->_tcpHdr->_urgP		= 0;
	packetClone->_tcpHdr->_unused	= 0;

	// BACKWARD의 IP헤더는 길이만을 수정해주면 된다.
	std::swap(packetClone->_ipHdr->_dIP, packetClone->_ipHdr->_sIP);
	packetClone->_ipHdr->_ttl    = 0x80;

	if (flag == BACKWARD_FIN_ACK)
		packetClone->_ipHdr->_totLen = htons(sizeof(IpHdr) + sizeof(TcpHdr) + strlen(_msg));
	if (flag == BACKWARD_RST_ACK)
		packetClone->_ipHdr->_totLen = htons(sizeof(IpHdr) + sizeof(TcpHdr));

	// BACKWARD의 IP 및 TCP의 Checksum 계산을 수행해준다.
	if (flag == BACKWARD_FIN_ACK)
		setTcpCheckSum(packetClone->_ipHdr, packetClone->_tcpHdr, (char *)_msg, strlen(_msg));
	if (flag == BACKWARD_RST_ACK)
		setTcpCheckSum(packetClone->_ipHdr, packetClone->_tcpHdr, NULL, 0);

	setIpCheckSum(packetClone->_ipHdr);

	// BACKWARD의 Ether헤더는 smac과 dmac을 수정해준다.
	std::swap(packetClone->_ethHdr->_dmac, packetClone->_ethHdr->_smac);
	
	// 수정용도로 할당했던 패킷 메모리 해제
	free(packetClone);

	return backwardPacket;
}

void sendPacket(u_char *packet, int size, pcap_t *handle, int flag) {	
	
	if(flag) printf("BLOCKED!\n");

	int res = pcap_sendpacket(handle, (const u_char *)packet, size);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		fprintf(stderr, "Size : %lu\n", size);
		exit(-1);
	}
}

bool isValidPacket(const u_char* packet) {
	// Ethernet Header :: IP check
	EthHdr *ethHeader = (EthHdr *)packet;
	bool isIpPacket = ntohs(ethHeader->_type) == 0x0800;

	if(!isIpPacket) return false;

	// Ip Header :: TCP check
    packet += ETHERNET_HEADER_SIZE;
    IpHdr *ipHeader = (IpHdr*)packet;

	bool isTcpPacket = (ipHeader->_protocol) == 0x06;

	if(!isTcpPacket) return false;

	// TCP Payload :: Host check
	int ipHeaderLength = ipHeader->_hlen * 4;
    packet += ipHeaderLength;
	TcpHdr *tcpHdr = (TcpHdr *)(packet);

    int tcpHeaderLength = (int)(tcpHdr->_offset * 4);

    char *httpPayload = (char *)(packet + tcpHeaderLength);

    std::string keyWord = hostName;

	bool isDetected = useKMP(httpPayload, keyWord.c_str());

	packet -= ETHERNET_HEADER_SIZE + ipHeaderLength;

    return isDetected;
}

void getPi(const char * word) {
    int wordLength = strlen(word);
    std::vector<int> tempPi(wordLength, 0);
	pi = tempPi;

    for(int nowIdx = 1, matchIdx = 0; nowIdx < wordLength; ++nowIdx) {
        if(word[nowIdx] == word[matchIdx]) {
            pi[nowIdx] = ++matchIdx;
        }
        else if (matchIdx != 0) {
            --nowIdx; matchIdx = pi[matchIdx - 1];
        }
    }
}

int useKMP(const char * sentence, const char * word) {
    int sentenceLength = strlen(sentence);
    int wordLength = strlen(word);

    for(int nowIdx = 0, matchIdx = 0; nowIdx < sentenceLength; ++nowIdx) {
        if(sentence[nowIdx] == word[matchIdx]){
            if(++matchIdx == wordLength) {
                return 1;
            }
        } 
        else if (matchIdx != 0) {
            --nowIdx; matchIdx = pi[matchIdx - 1];
        }
    }

    return 0;
}

void setTarget(const char *target) {
	hostName = (char *)target;
}

void setPacket(Packet *packet, const u_char *captured) {
	
	EthHdr *ethHdr = (EthHdr *)captured;
	captured += ETHERNET_HEADER_SIZE;
	
	IpHdr *ipHdr = (IpHdr *)captured;
	captured += ipHdr->_hlen * 4;
	TcpHdr *tcpHdr = (TcpHdr *)captured;

	packet->_ethHdr = ethHdr;
	packet->_ipHdr  = ipHdr;
	packet->_tcpHdr = tcpHdr;
}

void getMyMacAddr(char *ifname) {
	struct ifreq ifr;
	int sockfd, ret;

	// Open Socket
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0) {
		fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
		exit(-1);
	}

	// Check the MAC address of Network Interface
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if (ret < 0) {
		fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sockfd);
		exit(-1);
	}
	
	memcpy(myMac, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
	return;
}


uint16_t getCheckSum(uint16_t *buffer, int size)
{
    unsigned long cksum = 0;
    while(size >1)
    {
        cksum+=*buffer++;
        size -=sizeof(uint16_t);
    }
    if(size)
        cksum += *(u_char *)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (uint16_t)(~cksum);
}

uint16_t setTcpCheckSum(IpHdr *iph, TcpHdr *tcph, char* data, int size)
{
	tcph->_chksum = 0;
	PsdHeader psd_header;
	psd_header.m_daddr = iph->_dIP;
	psd_header.m_saddr = iph->_sIP;
	psd_header.m_mbz = 0;
	psd_header.m_ptcl = iph->_protocol;
	psd_header.m_tcpl = htons(tcph->_offset * 4 + size);

	char tcpBuf[65536];
	memcpy(tcpBuf, &psd_header, sizeof(PsdHeader));
	memcpy(tcpBuf + sizeof(PsdHeader), tcph, sizeof(TcpHdr));
	memcpy(tcpBuf + sizeof(PsdHeader) + sizeof(TcpHdr), data, size);
	return tcph->_chksum = getCheckSum((uint16_t *)tcpBuf,
		sizeof(PsdHeader)+sizeof(TcpHdr)+size);
}

uint16_t setIpCheckSum(IpHdr *iph)
{
	iph->_hdrChksum = 0;

	char ipBuf[65536];
	memcpy(ipBuf, iph, sizeof(IpHdr));
	return iph->_hdrChksum = getCheckSum((uint16_t *)ipBuf, sizeof(IpHdr));
}

// 이하는 출력함수들

void printTCP(const u_char *captured) {

	Packet *nowPacket = makePacket();
	setPacket(nowPacket, captured);
	

	newLine();
	printEthHdr(nowPacket->_ethHdr);
	newLine();
	printIpHdr(nowPacket->_ipHdr);
	newLine();
	printTcpHdr(nowPacket->_tcpHdr);

	free(nowPacket);
}

Packet *makePacket() {
	Packet *newPacket = (Packet *)malloc(sizeof(Packet));
	newPacket->_ethHdr = NULL;
	newPacket->_ipHdr = NULL;
	newPacket->_tcpHdr = NULL;

	return newPacket;
}

void freePacket(Packet *removePacket) {
	removePacket->_ethHdr = NULL;
	removePacket->_ipHdr  = NULL;
	removePacket->_tcpHdr = NULL;

	free(removePacket);
}

void newLine() {
	printf("=======================\n");
}

void printMAC(const uint8_t *mac) {
	for(int i=0; i<6;i++) {
		if(!i) printf("%02x", mac[i]);
		else printf(":%02x", mac[i]);
	}
	printf("\n");
}

void printEthHdr(const EthHdr *ethHdr) {
	printf("DMAC => "); printMAC(ethHdr->_dmac);
	printf("SMAC => "); printMAC(ethHdr->_smac);
	printf("TYPE => "); printf("IP\n");
}

void printIpHdr(const IpHdr *ipHdr) {
	printf("%-15s => ", "IPVER");         printInt8((ipHdr->_ver));
	printf("%-15s => ", "HLEN");          printInt8((ipHdr->_hlen));
	printf("%-15s => ", "TOS");           printInt8((ipHdr->_tos));
	printf("%-15s => ", "TOTLEN");        printInt16((ipHdr->_totLen));
	printf("%-15s => ", "ID");            printInt16((ipHdr->_id));
	printf("%-15s => ", "TTL");           printInt8((ipHdr->_ttl));
	printf("%-15s => ", "PROTOCOL");      printf("TCP\n");
	printf("%-15s => ", "CHECKSUM");      printInt16b((ipHdr->_hdrChksum));
	printf("%-15s => ", "SOURCEIP");      printIP((ipHdr->_sIP));
	printf("%-15s => ", "DESTINATIONIP"); printIP((ipHdr->_dIP));
}

void printTcpHdr(const TcpHdr *tcpHdr) {
	printf("%-15s => ", "SOURCEPORT");         printInt16(tcpHdr->_sPort);
	printf("%-15s => ", "DESTINATIONPORT");    printInt16(tcpHdr->_dPort);
	printf("%-15s => ", "SEQUENCENUMBER");     printInt32b(tcpHdr->_seq);
	printf("%-15s => ", "ACKNOWLEDGENUM");     printInt32b(tcpHdr->_ack);
	printf("%-15s => ", "OFFSET");             printInt8(tcpHdr->_offset);
	printf("%-15s => ", "FLAGS");              printInt8(tcpHdr->_flags);
	printf("%-15s => ", "WINDOWSIZE");         printInt16(tcpHdr->_winSz);
	printf("%-15s => ", "CHECKSUM");           printInt16(tcpHdr->_chksum);
}

void printInt8(const uint8_t num) {
	printf("%x\n", (num));
}
void printInt16(const uint16_t num) {
	printf("%d\n", ntohs(num));
}
void printInt16b(const uint16_t num) {
	printf("%x\n", ntohs(num));
}

void printIP(const in_addr ip) {
	printf("%s\n", inet_ntoa(ip));
}

void printInt32(const uint32_t num) {
	printf("%d\n", ntohl(num));
}
void printInt32b(const uint32_t num) {
	printf("%x\n", ntohl(num));
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 8 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

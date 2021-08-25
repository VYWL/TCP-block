#include "functions.h"

const uint32_t SIZE_OF_PACKET = (uint32_t)sizeof(EthHdr) + (uint32_t)sizeof(IpHdr) + (uint32_t)sizeof(TcpHdr);
const char *msg = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
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

bool isValidPacket(const u_char* packet) {
	EthHdr *ethHeader = (EthHdr *)packet;
	
	bool isIpPacket = (ethHeader->_type) == 0x08;

	if(!isIpPacket) return false;

    packet += ETHERNET_HEADER_SIZE;
    IpHdr *ipHeader = (IpHdr*)packet;
	int ipHeaderLength = ipHeader->_hlen * 4;
    packet += ipHeaderLength;
	TcpHdr *tcpHdr = (TcpHdr *)(packet);

	bool isTcpPacket = (ipHeader->_protocol) == 0x06;

	if(!isTcpPacket) return false;

	// check HOST
    int tcpHeaderLength = (int)(tcpHdr->_offset * 4);

    char *httpPayload = (char *)(packet + tcpHeaderLength);

    std::string keyWord = hostName;

	bool isDetected = useKMP(httpPayload, keyWord.c_str());

	packet -= ETHERNET_HEADER_SIZE + ipHeaderLength;

	if(isDetected) {
		printf("TARGET :: %s\n", hostName);
		printf("STATUS :: %s\n", isDetected ? "DETECTED" : "NON-DETECTED");
	}


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

uint16_t setTcpCheckSum(IpHdr *iph, TcpHdr *tcph, char* data,int size)
{
	tcph->_chksum = 0;
	PsdHeader psd_header;
	psd_header.m_daddr = iph->_dIP;
	psd_header.m_saddr = iph->_sIP;
	psd_header.m_mbz = 0;
	psd_header.m_ptcl = IPPROTO_TCP;
	psd_header.m_tcpl = htons(sizeof(TcpHdr)+size);

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
	printf("%-15s => ", "TTL");           printInt16((ipHdr->_ttl));
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
#include "functions.h"

const uint32_t SIZE_OF_PACKET = (uint32_t)sizeof(EthHdr) + (uint32_t)sizeof(IpHdr) + (uint32_t)sizeof(TcpHdr);

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"HOST: test.com\" \n");
}

bool isValidPacket(const u_char* packet) {
	
	EthHdr *ethHeader = (EthHdr *)packet;
	
	bool isIpPacket = (ethHeader->_type) == 0x08;

	if(!isIpPacket) return false;

    packet += ETHERNET_HEADER_SIZE;
    IpHdr *ipHeader = (IpHdr*)packet;
    packet -= ETHERNET_HEADER_SIZE;

	bool isTcpPacket = (ipHeader->_protocol) == 0x06;

    return isTcpPacket;
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

// 이하는 출력함수들

void printTCP(const Packet *packet) {
	newLine();
	printEthHdr(packet->_ethHdr);
	newLine();
	printIpHdr(packet->_ipHdr);
	newLine();
	printTcpHdr(packet->_tcpHdr);
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
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include <vector>
#include <stdlib.h>
#include <string>

#define ETHERNET_HEADER_SIZE 14
#define FORWARD_FIN_ACK 0x011
#define BACKWARD_RST_ACK 0x014

#define MAC_ALEN 6

extern const uint32_t SIZE_OF_PACKET;
extern uint8_t myMac[6];
extern const char *msg;
extern char *hostName;
extern std::vector<int> pi;

typedef struct EthernetHeader{
    uint8_t _dmac[6];
    uint8_t _smac[6];
    uint16_t _type;
}EthHdr;

typedef struct IPHeader{
    uint8_t _hlen : 4;
    uint8_t _ver : 4;
    uint8_t _tos;
    uint16_t _totLen;
    uint16_t _id;
    uint16_t _flag : 3;
    uint16_t _fragOffset : 13;
    uint8_t _ttl;
    uint8_t _protocol;
    uint8_t _hdrChksum;
    struct in_addr _sIP;
    struct in_addr _dIP;
}IpHdr;

typedef struct tcpHeader {
    uint16_t _sPort;
    uint16_t _dPort;
    uint32_t _seq;
    uint32_t _ack;
    uint16_t _unused : 4;
    uint16_t _offset : 4;
    uint16_t _flags : 8;
    uint16_t _winSz;
    uint16_t _chksum;
    uint16_t _urgP;
}TcpHdr;

typedef struct packet {
    EthHdr *_ethHdr;
    IpHdr  *_ipHdr;
    TcpHdr *_tcpHdr;
}Packet;


typedef struct psdHeader {
	struct in_addr m_daddr;
	struct in_addr m_saddr;
	uint32_t m_mbz;
	uint16_t m_ptcl;
	uint16_t m_tcpl;
}PsdHeader;


void usage();
void init(char* argv[]);
void setTarget(const char *target);

void newLine();
void printEthHdr(const EthHdr *ethHdr);
void printIpHdr(const IpHdr *ipHdr);
void printTCP(const u_char *captured);
void printMAC(const uint8_t *mac);
void printIP(const in_addr ip);
void printTcpHdr(const TcpHdr *ipHdr);

void printInt8(const uint8_t num);
void printInt16(const uint16_t num);
void printInt16b(const uint16_t num);
void printInt32(const uint32_t num);
void printInt32b(const uint32_t num);

Packet *makePacket();
void sendPacket(u_char *packet, int size, pcap_t *handle);
bool isValidPacket(const u_char* packet);

void block(pcap_t *handle);
void setPacket(Packet *packet, const u_char *captured);
void getMyMacAddr(char *ifname);
uint16_t getCheckSum(uint16_t *buffer, int size);
uint16_t setIpCheckSum(IpHdr *iph);
uint16_t setTcpCheckSum(IpHdr *iph, TcpHdr *tcph, char* data,int size);

u_char *genBlockingForward(const u_char *packet, int flag);
u_char *genBlockingBackward(const u_char *packet, int flag, const char *msg);

void getPi(const char * word);
int useKMP(const char * sentence, const char * word);

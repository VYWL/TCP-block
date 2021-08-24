#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h> 
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include <vector>

typedef struct EthernetHeader{
    uint8_t destinationMAC[6];
    uint8_t sourceMAC[6];
    uint16_t type;
}EthHdr;

typedef struct IPHeader{
    uint8_t headerLength : 4;
    uint8_t version : 4;
    uint8_t typeOfService;
    uint16_t totalPacketLength;
    uint16_t identifier;
    uint16_t fragmentOffset;
    uint8_t ttl;
    uint8_t protocolID;
    uint8_t headerChecksum;
    struct in_addr sourceIP;
    struct in_addr destinationIP;
}IpHdr;

typedef struct tcpHeader {
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint32_t sequenceNumber;
    uint32_t acknowledgeNumber;
    uint16_t _unused : 4;
    uint16_t offset : 4;
    uint16_t flags : 8;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;
}TcpHdr;

void usage();
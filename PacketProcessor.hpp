/**
 * @file PacketProcessor.hpp
 * @brief Packet processor class header
 * 
 * @author Adam Valík <xvalik05@vutbr.cz>
 * 
*/

#ifndef PACKETPROCESSOR_H
#define PACKETPROCESSOR_H

#include <pcap/pcap.h>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h> 
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/igmp.h>

using namespace std;

/**
 * @class PacketProcessor
 * @brief Abstract class for processing packets
 */
class PacketProcessor {

    /**
     * @brief Print timestamp in RFC3339 format
     * @param ts struct timeval with timestamp
     * 
     * Print timestamp in RFC3339 format (YYYY-MM-DDTHH:MM:SS.sss±HH:MM)
     * 
     * @see https://cplusplus.com/reference/ctime/strftime/
     */
    static void printTimestamp(const struct timeval& ts);

    public:
        /**
         * @brief Process packet
         * @param user user data
         * @param h packet header
         * @param bytes packet data
         * 
         * Process packet, print timestamp, MAC addresses, frame length, IP addresses, ports, payload
         */
        static void proccess(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
};

#endif // PACKETPROCESSOR_H

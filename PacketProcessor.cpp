/**
 * @file PacketProcessor.cpp
 * @brief Packet processor class implementation
 * 
 * @author Adam Valík <xvalik05@vutbr.cz>
 * 
*/

#include "PacketProcessor.hpp"

#include <netinet/ip_icmp.h>


void PacketProcessor::proccess(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user; // unused

    cout << endl;

    // print timestamp
    PacketProcessor::printTimestamp(h->ts); 

    // print src&dst MAC addresses
    const struct ether_header *eth_header = (const struct ether_header *)bytes;
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    // print frame length
    printf("frame length: %d bytes\n", h->len);

    uint8_t protocol = 0;
    int offset = sizeof(struct ether_header);

    // print src&dst IP addresses
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // IPv4
        const struct ip *ip_header = (const struct ip *)(bytes + offset);
        // convert from binary to text using inet_ntoa()
        printf("src IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("dst IP: %s\n", inet_ntoa(ip_header->ip_dst));

        protocol = ip_header->ip_p;
        offset += ip_header->ip_hl * 4; // IPv4 header length is variable 20-60 bytes
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
        // IPv6
        const struct ip6_hdr *ip6_header = (const struct ip6_hdr *)(bytes + offset);
        char ip6_src[INET6_ADDRSTRLEN];
        char ip6_dst[INET6_ADDRSTRLEN];
        // convert from binary to text using inet_ntop()
        inet_ntop(AF_INET6, &ip6_header->ip6_src, ip6_src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_header->ip6_dst, ip6_dst, INET6_ADDRSTRLEN);
        printf("src IP: %s\n", ip6_src);
        printf("dst IP: %s\n", ip6_dst);

        protocol = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        offset += sizeof(struct ip6_hdr); // IPv6 header is always 40 bytes
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {     
        // ARP
        printf("ARP packet\n");
        const struct ether_arp *arp_header = (struct ether_arp *)(bytes + offset);

        // print ARP operation
        printf("Operation: %s\n", (ntohs(arp_header->arp_op) == ARPOP_REQUEST) ? "Request" : "Reply");

    }
    else {
        // unsupported protocol, print the type in hexa
        printf("unsupported protocol: 0x%04x\n", ntohs(eth_header->ether_type));
    }

    // print port numbers based on the transport protocol (on top of IPv4/IPv6)
    if (protocol == IPPROTO_TCP) {
        // TCP
        const struct tcphdr *tcp_header = (const struct tcphdr *)(bytes + offset);
        printf("src port: %d\n", ntohs(tcp_header->th_sport));
        printf("dst port: %d\n", ntohs(tcp_header->th_dport));
    }
    else if (protocol == IPPROTO_UDP) {
        // UDP
        const struct udphdr *udp_header = (const struct udphdr *)(bytes + offset);
        printf("src port: %d\n", ntohs(udp_header->uh_sport));
        printf("dst port: %d\n", ntohs(udp_header->uh_dport));
    }
    else if (protocol == IPPROTO_ICMP) {
        // ICMP 
        const struct icmp *icmp_header = (const struct icmp *)(bytes + offset);
        printf("ICMP type: %d\n", icmp_header->icmp_type);
        printf("ICMP code: %d\n", icmp_header->icmp_code);
    }
    else if (protocol == IPPROTO_IGMP) {
        // IGMP
        const struct igmp *igmp_header = (const struct igmp *)(bytes + offset);
        printf("IGMP type: %d\n", igmp_header->igmp_type);
        printf("IGMP code: %d\n", igmp_header->igmp_code);
    }
    else if (protocol == IPPROTO_ICMPV6) {
        // ICMPv6
        const struct icmp6_hdr *icmp6_header = (const struct icmp6_hdr *)(bytes + offset);
        printf("ICMPv6 type: %d\n", icmp6_header->icmp6_type);
        printf("ICMPv6 code: %d\n", icmp6_header->icmp6_code);
    }

    cout << endl;

    // print payload in format byte_offset: byte_offset_hexa  byte_offset_ASCII
    u_char *payload_data = (u_char *)bytes;
    const int data_len = h->len;

    int line_len = 16; // 16 bytes per line
    for (int i = 0; i < data_len; i += line_len) {
        printf("0x%04x: ", i);
        for (int j = 0; j < line_len; j++) {
            if (i + j < data_len) {
                printf("%02x ", payload_data[i + j]); 
            } else {
                cout << "   "; 
            }
        }
        cout << "  ";
        for (int j = 0; j < line_len && i + j < data_len; j++) {
            if (j == 8) {
                cout << " ";
            }
            if (isprint(payload_data[i + j])) { // is printable
                printf("%c", payload_data[i + j]);
            } else {
                printf("."); // period for non-printable chars
            }
        }
        cout << endl;
    }

    cout << endl << flush;
}

void PacketProcessor::printTimestamp(const struct timeval& ts) {

    struct tm *timeinfo = localtime(&ts.tv_sec);

    char time[30];
    strftime(time, sizeof(time), "%FT%T", timeinfo);
    char time_zone[10];
    strftime(time_zone, sizeof(time_zone), "%z", timeinfo);
    
    // RFC3339 format: YYYY-MM-DDTHH:MM:SS.sss±HH:MM
    printf("timestamp: %s.%03ld%.3s:%.2s\n", time, ts.tv_usec / 1000, time_zone, time_zone + 3);
}
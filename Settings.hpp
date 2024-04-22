/**
 * @file Settings.hpp
 * @brief Settings structure
 * 
 * @author Adam Valík <xvalik05@vutbr.cz>
 * 
*/

#ifndef SETTINGS_H
#define SETTINGS_H

#include <string>
#include <vector>

using namespace std;

/**
 * @brief Structure for settings
 */
struct Settings {
    string interface;   // interface name
    int port = 0;       // filter by port
    int portSrc = 0;    // filter by source port
    int portDst = 0;    // filter by destination port
    bool tcp = false;   // display TCP segments
    bool udp = false;   // display UDP datagrams
    bool icmp4 = false; // only ICMPv4 packets
    bool icmp6 = false; // only ICMPv6 echo request/response
    bool arp = false;   // only ARP frames
    bool ndp = false;   // only NDP packets, subset of ICMPv6
    bool igmp = false;  // only IGMP packets
    bool mld = false;   // only MLD packets, subset of ICMPv6
    int num = 1;        // number fo packets to display (default 1)
};

#endif // SETTINGS_H

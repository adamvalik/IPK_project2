/**
 * @file PacketCapturer.hpp
 * @brief Packet capturing class header
 * 
 * @author Adam Valík <xvalik05@vutbr.cz>
 * 
*/

#ifndef PACKETCAPTURER_H
#define PACKETCAPTURER_H

#include "SnifferException.hpp"
#include "PacketProcessor.hpp"

#include <string>
#include <pcap/pcap.h>

using namespace std;

/**
 * @class PacketCapturer
 * @brief Class for capturing packets
 */
class PacketCapturer {

    string interface;
    string filter;
    int cnt;
    pcap_t* handle;

    public:
        PacketCapturer() {};
        /**
         * @brief Set up the packet capturer
         * 
         * @param interface Network interface
         * @param filter Filter expression for packet capture
         * @param cnt Number of packets to capture
         */
        void setup(const string& interface, const string& filter, int cnt);

        /**
         * @brief Start capturing packets
         * @throws SnifferException
         * @see https://www.tcpdump.org/manpages/
         */
        void start();

        /**
         * @brief Close the packet capturer
         */
        void cleanup();
};

#endif // PACKETCAPTURER_H

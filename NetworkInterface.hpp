/**
 * @file NetworkInterface.hpp
 * @brief Network interface class header
 * 
 * @author Adam Valík <xvalik05@vutbr.cz>
 * 
*/

#ifndef NETWORKINTERFACE_H
#define NETWORKINTERFACE_H

#include "SnifferException.hpp"

#include <pcap/pcap.h>
#include <iostream>

using namespace std;

/**
 * @class NetworkInterface
 * @brief Abstract class for network interfaces
 */
class NetworkInterface {
    public:
        /**
         * @brief List all active interfaces
         * @throws SnifferException
         * @see https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html
         */
        static void listInterfaces();
};

#endif // NETWORKINTERFACE_H

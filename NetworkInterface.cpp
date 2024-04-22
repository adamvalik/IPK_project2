/**
 * @file NetworkInterface.cpp
 * @brief Network interface class implementation
 * 
 * @author Adam Valík <xvalik05@vutbr.cz>
 * 
*/

#include "NetworkInterface.hpp"

void NetworkInterface::listInterfaces() {
    pcap_if_t *alldevsp;
    char errbuf[PCAP_ERRBUF_SIZE];

    // find all active interfaces
    if (pcap_findalldevs(&alldevsp, errbuf) == PCAP_ERROR) {
        throw SnifferException(1, "pcap_findalldevs() failed: " + string(errbuf));
    }

    // list all active interfaces
    for (pcap_if_t* i = alldevsp; i; i = i->next) {
        cout << i->name << endl;
    }

    // free the device list
    pcap_freealldevs(alldevsp);
}
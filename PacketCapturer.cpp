/**
 * @file PacketCapturer.cpp
 * @brief Packet capturing class implementation
 * 
 * @author Adam Valík <xvalik05@vutbr.cz>
 * 
*/

#include "PacketCapturer.hpp"

void PacketCapturer::setup(const string& interface, const string& filter, int cnt) {
    this->interface = interface;
    this->filter = filter;
    this->cnt = cnt;
}

void PacketCapturer::start() {
    char errbuf[PCAP_ERRBUF_SIZE];
    string error;

    // find the network number and mask for the network interface 
    bpf_u_int32 net, mask;
    if (pcap_lookupnet(interface.c_str(), &net, &mask, errbuf) == PCAP_ERROR) {
        throw SnifferException(1, "pcap_lookupnet() failed: " + string(errbuf));
    }

    // open interface in promiscuous mode (1) with 500ms timeout
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 500, errbuf);
    if (handle == NULL) {
        throw SnifferException(1, "pcap_open_live() failed: " + string(errbuf));
    }

    // support only LINKTYPE_ETHERNET (corresponding to DLT_EN10MB) -> https://www.tcpdump.org/linktypes.html
    if (pcap_datalink(handle) != DLT_EN10MB && pcap_datalink(handle) != DLT_NULL){
        pcap_close(handle);
        throw SnifferException(1, "Unsupported link-layer header type");
    }

    // compile the filter expression 
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, net) == PCAP_ERROR) {
        error = pcap_geterr(handle);
        pcap_close(handle);
        throw SnifferException(1, "pcap_compile() failed: " + error);
    }

    // set the filter
    if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
        error = pcap_geterr(handle);
        pcap_close(handle);
        throw SnifferException(1, "pcap_setfilter() failed: " + error);
    }

    // process packets from a live capture, call PacketProcessor::process() for each packet
    if (pcap_loop(handle, this->cnt, PacketProcessor::proccess, NULL) < 0) {
        error = pcap_geterr(handle);
        pcap_close(handle);
        throw SnifferException(1, "pcap_loop() failed: " + error);
    }
}

void PacketCapturer::cleanup() {
    pcap_close(handle);
}
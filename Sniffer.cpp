/**
 * @file Sniffer.cpp
 * @brief Sniffer class implementation
 * 
 * @author Adam Valík <xvalik05@vutbr.cz>
 * 
*/

#include "Sniffer.hpp"

Sniffer::Sniffer(int argc, char** argv) {
    this->parseArguments(argc, argv);
    this->getFilter();
}

void Sniffer::sniff() {
    this->capturer.setup(this->settings.interface, this->filter, this->settings.num);
    this->capturer.start();
    this->capturer.cleanup();
}

void Sniffer::parseArguments(int argc, char** argv) {
    // "Cilem projektu neni se vyvredit u zpracovani argumentu." <3

    if (argc == 1 || (argc == 2 && (string(argv[1]) == "-i" || string(argv[1]) == "--interface"))) {
        // display list of active interfaces
        NetworkInterface::listInterfaces();
        throw SnifferException(0);
    }

    if (argc == 2 && (string(argv[1]) == "-h" || string(argv[1]) == "--help")) {
        this->printUsage();
        throw SnifferException(0);
    }

    // fill settings with specified arguments
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "-i" || arg == "--interface") {
            this->settings.interface = argv[++i];
        } else if (arg == "-p") {
            this->settings.port = atoi(argv[++i]);
        } else if (arg == "--port-source") {
            this->settings.portSrc = atoi(argv[++i]);
        } else if (arg == "--port-destination") {
            this->settings.portDst = atoi(argv[++i]);
        } else if (arg == "-t" || arg == "--tcp") {
            this->settings.tcp = true;
        } else if (arg == "-u" || arg == "--udp") {
            this->settings.udp = true;
        } else if (arg == "--icmp4") {
            this->settings.icmp4 = true;
        } else if (arg == "--icmp6") {
            this->settings.icmp6 = true;
        } else if (arg == "--arp") {
            this->settings.arp = true;
        } else if (arg == "--ndp") {
            this->settings.ndp = true;
        } else if (arg == "--igmp") {
            this->settings.igmp = true;
        } else if (arg == "--mld") {
            this->settings.mld = true;
        } else if (arg == "-n") {
            this->settings.num = atoi(argv[++i]);
        } else {
            this->printUsage();
            throw SnifferException(1, "Unknown argument");
        }
    }
}

void Sniffer::getFilter() {
    stringstream filter;

    // protocols
    if (settings.tcp) {
        filter << "tcp";
    }
    if (settings.udp) {
        if (!filter.str().empty()) filter << " or ";
        filter << "udp";
    }
    if (settings.icmp4) {
        if (!filter.str().empty()) filter << " or ";
        filter << "icmp";
    }
    if (settings.icmp6) {
        if (!filter.str().empty()) filter << " or ";
        filter << "icmp6 and (ip6[40] == 128 or ip6[40] == 129)";
    }
    if (settings.arp) {
        if (!filter.str().empty()) filter << " or ";
        filter << "arp";
    }
    if (settings.ndp) {
        if (!filter.str().empty()) filter << " or ";
        filter << "icmp6 and ip6[40] == 135";
    }
    if (settings.igmp) {
        if (!filter.str().empty()) filter << " or ";
        filter << "igmp";
    }
    if (settings.mld) {
        if (!filter.str().empty()) filter << " or ";
        filter << "icmp6 and ip6[40] == 143";
    }
    // unless protocols are explicitly specified, all are considered for printing
    if (filter.str().empty()) {
        filter << "tcp or udp or icmp or icmp6 or arp or igmp";
    }

    // ports
    if (this->settings.port != 0) {
        if (!filter.str().empty()) filter << " and ";
        filter << "port " << this->settings.port;
    }
    if (this->settings.portSrc != 0 && this->settings.portDst != 0) {
        if (!filter.str().empty()) filter << " and ";
        filter << "port " << this->settings.portSrc << " or port " << this->settings.portDst;
    }
    if (this->settings.portSrc != 0) {
        if (!filter.str().empty()) filter << " and ";
        filter << "src port " << this->settings.portSrc;
    }
    if (this->settings.portDst != 0) {
        if (!filter.str().empty()) filter << " and ";
        filter << "dst port " << this->settings.portDst;
    }

    this->filter = filter.str();
}

void Sniffer::printUsage() const {
    cerr << "Usage: ./ipk-sniffer\n";
    cerr << "  -i | --interface [INTERFACE]  interface to sniff\n";
    cerr << "  -p [PORT]                     filter by port\n";
    cerr << "  --port-source [PORT]          filter source by port\n";
    cerr << "  --port-destination [PORT]     filter destination by port\n";
    cerr << "  -t | --tcp                    sniff TCP segments\n";
    cerr << "  -u | --udp                    sniff UDP datagrams\n";
    cerr << "  --icmp4                       sniff ICMPv4 packets\n";
    cerr << "  --icmp6                       sniff ICMPv6 echo request/response\n";
    cerr << "  --arp                         sniff ARP frames\n";
    cerr << "  --ndp                         sniff NDP packets\n";
    cerr << "  --igmp                        sniff IGMP packets\n";
    cerr << "  --mld                         sniff MLD packets\n";
    cerr << "  -n [NUM]                      number of packets to print\n";
    cerr << "  -h|--help                     display usage\n\n";
    cerr << "If the number of packets is not specified, only one packet is printed.\n";
    cerr << "If the interface parameter is not specified, a list of active interfaces is displayed.\n";
    cerr << "Unless protocols are explicitly specified, all are considered for printing.\n\n";
}
/**
 * @file Sniffer.hpp
 * @brief Sniffer class header
 * 
 * @author Adam Valík <xvalik05@vutbr.cz>
 * 
*/

#ifndef SNIFFER_H
#define SNIFFER_H

#include "Settings.hpp"
#include "SnifferException.hpp"
#include "PacketCapturer.hpp"
#include "PacketProcessor.hpp"
#include "NetworkInterface.hpp"

#include <cstdlib>
#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include <sstream>

using namespace std;

/**
 * @class Sniffer
 * @brief Sniffer class for sniffing packets
 */
class Sniffer {

    Settings settings;
    PacketCapturer capturer;
    string filter;

    /**
     * @brief Parse command line arguments
     * @throws SnifferException
     * 
     * @param argc Number of arguments
     * @param argv Command-line arguments
     */
    void parseArguments(int argc, char** argv);

    /**
     * @brief Display help message
     */
    void printUsage() const;

    /**
     * @brief Get filter expression
     * 
     * Setup filter expression based on settings
     * 
     * @see https://www.tcpdump.org/manpages/pcap-filter.7.html
     */
    void getFilter();

    public:
        Sniffer(int argc, char** argv);

        /**
         * @brief Start sniffing packets using PacketCapturer
         */
        void sniff();
};

#endif // SNIFFER_H

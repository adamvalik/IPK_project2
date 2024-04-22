/**
 * @file main.cpp
 * @brief Main file for the network sniffer application
 * 
 * @author Adam Valík <xvalik05@vutbr.cz>
 * 
*/

#include "Sniffer.hpp"
#include "SnifferException.hpp"

#include <csignal>

/**
 * @brief Signal handler for SIGINT
 * 
 * @param signum Signal number
 */
void signalHandler(int signum) {
    exit(signum);
}

/**
 * @brief Main function
 * 
 * @param argc Number of arguments
 * @param argv Command-line arguments
 * @return int Exit code
 */
int main(int argc, char *argv[]) {
    signal(SIGINT, signalHandler);

    try {
        Sniffer sniffer(argc, argv);
        sniffer.sniff();
    } catch (const SnifferException& e) {
        if (e.getExitCode() != EXIT_SUCCESS) {
            cerr << "[ERROR] " << e.what() << endl;
        }
        return e.getExitCode();
    }

    return EXIT_SUCCESS;
}
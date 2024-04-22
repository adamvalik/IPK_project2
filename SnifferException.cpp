/**
 * @file SnifferException.cpp
 * @brief Sniffer exception class implementation
 * 
 * @author Adam Valík <xvalik05@vutbr.cz>
 * 
*/

#include "SnifferException.hpp"

const char* SnifferException::what() const noexcept {
    return message.c_str();
}

int SnifferException::getExitCode() const {
    return exitCode;
}
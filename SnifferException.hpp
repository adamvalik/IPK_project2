/**
 * @file SnifferException.hpp
 * @brief SnifferException class header
 * 
 * @author Adam Valík <xvalik05@vutbr.cz>
 * 
*/

#ifndef SNIFFEREXCEPTION_H
#define SNIFFEREXCEPTION_H

#include <string>
#include <exception>

using namespace std;

/**
 * @class SnifferException
 * @brief Exception class for sniffer
 */
class SnifferException : public exception {
    
    string message;
    int exitCode;
    
    public:
        SnifferException(int code, const string& msg) : message(msg), exitCode(code) {};
        SnifferException(int code) : exitCode(code) {};

        /**
         * @brief Get exception message
         * @return Exception message
         */
        const char* what() const noexcept override;
        
        /**
         * @brief Get exit code
         * @return Exit code
         */
        int getExitCode() const;
};

#endif // SNIFFEREXCEPTION_H

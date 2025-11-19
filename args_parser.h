#ifndef ENCRYPTED_REV_SHELL_ARGS_PARSER_H
#define ENCRYPTED_REV_SHELL_ARGS_PARSER_H

#include "utils.h"

struct config {
    std::string execType;
    unsigned int portNum{};
    std::string ipAddr;
};

inline config parse_args(int argc, char* argv[]) {
    config tmpCfg;

    if (argc >= 2) {
        if (strcmp(toLower(argv[1]),  "server") == 0) {

            tmpCfg.execType = argv[1];

            if (argc >= 3) {
                if (checkIfIpAddr(argv[2])) {
                    tmpCfg.ipAddr = argv[2];

                    if (argc >= 4) {
                        if (isPort(argv[3])) {
                            const int input_num = atoi(argv[3]);

                            tmpCfg.portNum = input_num;

                            return tmpCfg;
                        }
                        else {
                            std::cout << "Invalid Argument: " << argv[2] << " is NOT a valid PORT!" << std::endl;
                            std::cout << "Usage ./shell server LISTEN_IP LISTEN_PORT" << std::endl;
                        }
                    }
                    else {
                        std::cout << "Usage ./shell server SERVER_IP SERVER_PORT" << std::endl;
                    }

                }
                else {
                    std::cout << "Invalid Argument: " << argv[2] << " is NOT a valid IP address!" << std::endl;
                    std::cout << "Usage ./shell server LISTEN_IP LISTEN_PORT" << std::endl;
                }
            }
            else {
                std::cout << "Usage ./shell server SERVER_IP SERVER_PORT" << std::endl;
            }

        }
        // client
        else if (strcmp(toLower(argv[1]),  "client") == 0) {
            tmpCfg.execType = argv[1];

            if (argc >= 3) {

                if (checkIfIpAddr(argv[2])) {

                    tmpCfg.ipAddr = argv[2];

                    if (argc >= 4) {
                        if (isPort(argv[3])) {
                            tmpCfg.portNum = atoi(argv[3]);
                        }
                        else {
                            std::cout << "Invalid Argument: " << argv[3] << " Is not a port number!" << std::endl;
                            std::cout << "Usage ./shell client SERVER_IP SERVER_PORT" << std::endl;
                        }
                    }
                    else {
                        std::cout << "Usage ./shell client SERVER_IP SERVER_PORT" << std::endl;
                    }

                }
                else {
                    std::cout << "Invalid Argument: " << argv[2] << " is NOT a valid IP address!" << std::endl;
                    std::cout << "Usage ./shell client SERVER_IP SERVER_PORT" << std::endl;

                }
            }
            else {
                std::cout << "Usage ./shell client SERVER_IP SERVER_PORT" << std::endl;
            }
        }
        else {
            std::cout << "Invalid Argument: "  << argv[1] << std::endl;
            std::cout << "Usage: ./shell [SERVER or CLIENT]" << std::endl;;
        }
    }
    else {
        std::cout << "Usage: ./shell [SERVER or CLIENT]" << std::endl;
    }

    return tmpCfg;
}

#endif //ENCRYPTED_REV_SHELL_ARGS_PARSER_H
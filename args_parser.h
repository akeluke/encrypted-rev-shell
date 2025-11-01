#ifndef ENCRYPTED_REV_SHELL_ARGS_PARSER_H
#define ENCRYPTED_REV_SHELL_ARGS_PARSER_H

#include "utils.h"

struct config {
    std::string execType;
    unsigned int portNum;
    std::string ipAddr;
};

inline config parse_args(int argc, char* argv[]) {
    config tmpCfg;

    if (argc >= 2) {
        if (strcmp(toLower(argv[1]),  "server") == 0) {

            tmpCfg.execType = argv[1];
            // user has specified port
            if (argc >= 3) {
                if (isPort(argv[2])) {
                    const int input_num = atoi(argv[2]);

                    tmpCfg.portNum = input_num;

                    return tmpCfg;
                }
                else {
                    std::cout << "Invalid Argument: " << argv[2] << " Is not a port number!" << std::endl;
                    std::cout << "Usage ./shell server PORT" << std::endl;
                }
            }
            // no port specified, notify will by default run on 443
            else {
                tmpCfg.portNum = 443;
            }

        }
        // client
        else if (strcmp(toLower(argv[1]),  "client") == 0) {
            tmpCfg.execType = argv[1];

            if (argc >= 3) {

                if (checkIfIpAddr(argv[2])) {

                    tmpCfg.ipAddr = argv[2];

                    if (isPort(argv[3])) {
                        tmpCfg.portNum = atoi(argv[3]);
                    }
                    else {
                        std::cout << "Invalid Argument: " << argv[3] << " Is not a port number!" << std::endl;
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
}



#endif //ENCRYPTED_REV_SHELL_ARGS_PARSER_H
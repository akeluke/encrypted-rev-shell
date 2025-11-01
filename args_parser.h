#ifndef ENCRYPTED_REV_SHELL_ARGS_PARSER_H
#define ENCRYPTED_REV_SHELL_ARGS_PARSER_H

#include "utils.h"


inline void parse_args(int argc, char* argv[]) {
    if (argc >= 2) {
        if (strcmp(toLower(argv[1]),  "server") == 0) {
            // user has specified port
            if (argc >= 3) {
                if (isInteger(argv[2])) {
                    const int input_num = atoi(argv[2]);

                    if (input_num >= 1 && input_num <= 65535) {

                    }
                    else {
                        std::cout << "Invalid Argument: " << argv[2] << std::endl;
                        std::cout << argv[2] << " Is not a port number!" << std::endl;

                    }

                }
                else {
                    std::cout << "Invalid Argument: " << argv[2] << std::endl;
                    std::cout << "Usage ./Shell server PORT" << std::endl;
                }
            }
            // no port specified, notify will by default run on 443
            else {

            }

        }
        // client
        else if (strcmp(toLower(argv[1]),  "client") == 0) {

        }

        else {
            std::cout << "Invalid Argument: "  << argv[1] << std::endl;
            std::cout << "Usage: ./shell [SERVER or CLIENT]" << std::endl;;
        }
    }
}



#endif //ENCRYPTED_REV_SHELL_ARGS_PARSER_H
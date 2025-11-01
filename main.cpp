#include "utils.h"
#include "args_parser.h"


unsigned int defPort = 443;

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

    return 0;
}

// placeholder for now
void server(unsigned int portNum) {
}

void client(const std::string &ipAddr, unsigned int portNum) {
}
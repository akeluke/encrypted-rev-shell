#ifndef ENCRYPTED_REV_SHELL_SERVER_UTILS_H
#define ENCRYPTED_REV_SHELL_SERVER_UTILS_H

// server specific functions
inline fileTransfer s_parseCommand(char* inputCommand) {

    fileTransfer transferCfg;
    std::string inputStr = toLower(inputCommand);

    if (inputStr.find("upload") != std::string::npos) {
        transferCfg.type = "upload";
    }
    else if (inputStr.find("download") != std::string::npos) {
        transferCfg.type = "download";
    }
    else {
        transferCfg.type = "err";
    }
    // command will be ttyBuffer
    // delete useless information
    // return filePath to file wanting to upload

    // ttyBuffer will look like this =
    // "upload localFile remoteFile\nCONSOLE----"
    // need to extract localFile and remoteFile


    unsigned int newLinePos = inputStr.find("\n"); // first get everything before the newline

    std::string tmpStr = inputStr.substr(0, newLinePos);

    // tmpStr is now "upload /myfile/file.bin"
    // we now need to just extract everthing after "upload "
    // which we can do by just finding where the space is

    unsigned int spacePos = tmpStr.find(" ");

    std::string afterSpace = tmpStr.substr(spacePos + 1);

    // afterSpace = 'localFile remoteFile'
    spacePos = afterSpace.find(" ");

    transferCfg.pathToRead = afterSpace.substr(0, spacePos);
    transferCfg.pathToWrite = afterSpace.substr(spacePos + 1);

    return transferCfg;
}

inline void s_prepareClientToDownload(SSL* ssl, const std::string& command, const std::string& pathToRead, const std::string& pathToWrite) {
    SSL_write(ssl, command.c_str(), command.size());

    SSL_write(ssl, pathToRead.c_str(), pathToRead.size());

    SSL_write(ssl, pathToWrite.c_str(), pathToWrite.size());
}

#endif //ENCRYPTED_REV_SHELL_SERVER_UTILS_H
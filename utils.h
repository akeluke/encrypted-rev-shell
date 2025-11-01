#ifndef ENCRYPTED_REV_SHELL_UTILS_H
#define ENCRYPTED_REV_SHELL_UTILS_H

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstring>
#include <iostream>

inline char* toLower(char* arg) {

    //convert to string
    std::string inputStr = arg;

    // loop through and covert to lower char
    std::transform(inputStr.begin(), inputStr.end(), inputStr.begin(),
    [](unsigned char c){ return std::tolower(c); });

    //convert back to char array
    char* returnChar = new char[inputStr.length() + 1];
    strcpy(returnChar, inputStr.c_str());

    return returnChar;
}


inline bool isInteger(char* arg) {
    std::string inputStr = arg;

    return std::all_of(inputStr.begin(), inputStr.end(),
                     [](unsigned char c) { return std::isdigit(c); });
}

#endif //ENCRYPTED_REV_SHELL_UTILS_H
#include <iostream>
#include "utils.h"

int main() {


    auto lang = "C++";

    int calculation = check();

    std::cout << calculation << std::endl;

    std::cout << "Hello and welcome to " << lang << "!\n";

    for (int i = 1; i <= 5; i++) {

        std::cout << "i = " << i << std::endl;
    }

    return 0;
}
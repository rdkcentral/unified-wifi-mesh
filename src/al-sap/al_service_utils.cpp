#include "../../inc/al_service_utils.h"


// Define the printByteStream function
void printByteStream(const std::vector<unsigned char>& byteStream) {
    #ifdef DEBUG_MODE
    for (unsigned char byte : byteStream) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;
    #endif
}
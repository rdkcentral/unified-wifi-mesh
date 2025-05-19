#include <string.h>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <algorithm>
#include "al_service_utils.h"


// Define the printByteStream function
void printByteStream(const std::vector<unsigned char>& byteStream) {
    #ifdef DEBUG_MODE
    for (unsigned char byte : byteStream) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;
    #endif
}

struct sockaddr_un createUnixSocketAddress(const std::string &path)
{
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);
    return address;
}

struct sockaddr_in createUDPServerAddress(int port)
{
    sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = INADDR_ANY;
    return address;
}

struct sockaddr_in createUDPClientAddress(const std::string &ip, int port)
{
    sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = inet_addr(ip.c_str());
    return address;
}

std::string macAddressToString(const std::array<uint8_t, 6> arr)
{
    std::ostringstream oss;
    bool first = true;
    for (const auto &byte : arr)
    {
        if (!first)
        {
            oss << ":";
        }
        oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte);
        first = false;
    }
    return oss.str();
}

bool areMacsEqual(const std::array<uint8_t, 6> &first, const std::array<uint8_t, 6> &second)
{
    return std::equal(begin(first), end(first), begin(second));
}

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

std::vector<unsigned char> convert_u32_into_bytes(uint32_t number)
{
    return std::vector<unsigned char>{static_cast<unsigned char>(number >> 24),
                                      static_cast<unsigned char>(number >> 16),
                                      static_cast<unsigned char>(number >> 8),
                                      static_cast<unsigned char>(number >> 0)};
}

uint32_t convert_bytes_into_u32(const std::vector<unsigned char>& bytes)
{
    if (bytes.size() < 4)
        return 0;
    return static_cast<uint32_t>((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | (bytes[3] << 0));
}

std::vector<unsigned char> remove_length_delimited_part(const std::vector<unsigned char>& buffer)
{
    return std::vector<unsigned char>(buffer.cbegin() + sizeof(uint32_t), buffer.cend());
}

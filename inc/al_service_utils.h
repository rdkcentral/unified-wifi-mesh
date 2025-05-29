#ifndef AL_SERVICE_UTILS_H
#define AL_SERVICE_UTILS_H

#include <vector>
#include <iostream> // for std::cout
#include <iomanip>  // for std::hex
#include <sys/un.h>
#include <array>

// PrintByteStream function used for debugging only
/**!
 * @brief Prints the contents of a byte stream.
 *
 * This function takes a vector of unsigned characters and prints each byte in the stream.
 *
 * @param[in] byteStream A vector containing the byte stream to be printed.
 *
 * @note Ensure that the byte stream is not empty before calling this function.
 */
void printByteStream(const std::vector<unsigned char>& byteStream);

struct sockaddr_un createUnixSocketAddress(const std::string &path);

struct sockaddr_in createUDPServerAddress(int port);

struct sockaddr_in createUDPClientAddress(const std::string &ip, int port);

std::string macAddressToString(const std::array<uint8_t, 6> arr);

bool areMacsEqual(const std::array<uint8_t, 6> &first, const std::array<uint8_t, 6> &second);


std::vector<unsigned char> convert_u32_into_bytes(uint32_t number);
uint32_t convert_bytes_into_u32(const std::vector<unsigned char>& bytes);

std::vector<unsigned char> remove_length_delimited_part(const std::vector<unsigned char>& buffer);

#endif // AL_SERVICE_UTILS_H

#ifndef AL_SERVICE_UTILS_H
#define AL_SERVICE_UTILS_H

#include <vector>
#include <iostream> // for std::cout
#include <iomanip>  // for std::hex

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

#endif // AL_SERVICE_UTILS_H

/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _UTIL_H_
#define _UTIL_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include "wifi_hal.h"
#include <pthread.h>
#include <string>
#include <memory>
#include <vector>

#ifndef LOG_PATH_PREFIX
#define LOG_PATH_PREFIX "/nvram/"
#endif // LOG_PATH_PREFIX

/**
 * @brief Perform a byte swap if needed to convert little endian to/from host byte ordering
 * @param x Unsigned 16 bit integer
 * @return uint16_t x, byte-swapped if host is big endian, otherwise unchanged
 */
static inline uint16_t SWAP_LITTLE_ENDIAN(uint16_t x) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return x;
#else
    return __bswap_16(x);
#endif
}

typedef enum {
    EM_STDOUT,
    EM_AGENT,
    EM_CTRL,
    EM_MGR,
    EM_DB,
    EM_PROV,
    EM_CONF
}easymesh_dbg_type_t;

typedef enum {
    EM_LOG_LVL_DEBUG,
    EM_LOG_LVL_INFO,
    EM_LOG_LVL_ERROR
}easymesh_log_level_t;

namespace util {


	/**!
	 * @brief Logs a formatted message with a specified log level and module type.
	 *
	 * This function allows for logging messages with varying levels of severity and
	 * different module types, aiding in debugging and monitoring the system.
	 *
	 * @param[in] level The log level indicating the severity of the log message.
	 * @param[in] module The module type to which the log message belongs.
	 * @param[in] func The name of the function from which the log is being called.
	 * @param[in] line The line number in the source code where the log is called.
	 * @param[in] format The format string for the log message, followed by any additional arguments.
	 *
	 * @note This function uses variadic arguments to allow for flexible message formatting.
	 */
	void em_util_print(easymesh_log_level_t level, easymesh_dbg_type_t module, const char *func, int line, const char *format, ...);

	/**!
	 * @brief Introduces a delay for a specified amount of time.
	 *
	 * @param[in] duration The amount of time to delay, in milliseconds.
	 *
	 * @note This function will block the execution for the specified duration.
	 */
	void delay(int );

	/**!
	 * @brief Adds milliseconds to a given timespec structure.
	 *
	 * This function takes a timespec structure and a number of milliseconds,
	 * and adds the milliseconds to the timespec, updating it accordingly.
	 *
	 * @param[in,out] ts Pointer to a timespec structure to be updated.
	 * @param[in] milliseconds Number of milliseconds to add to the timespec.
	 *
	 * @note The function modifies the input timespec structure directly.
	 */
	void add_milliseconds(struct timespec *ts, long milliseconds);

	/**!
	 * @brief Retrieves the current date and time in RFC 3399 format.
	 *
	 * This function populates the provided buffer with the current date and time
	 * formatted according to the RFC 3399 standard.
	 *
	 * @param[out] buff A pointer to the buffer where the formatted date and time
	 * will be stored. The buffer must be large enough to hold the resulting string.
	 *
	 * @param[in] len The length of the buffer. This should be sufficient to store
	 * the complete RFC 3399 formatted date and time string.
	 *
	 * @returns A pointer to the buffer containing the formatted date and time.
	 *
	 * @note Ensure that the buffer provided is adequately sized to prevent
	 * buffer overflow.
	 */
	char *get_date_time_rfc3399(char *buff, unsigned int len);

	/**!
	 * @brief Prints a hex dump of the given buffer.
	 *
	 * This function outputs the contents of the buffer in hexadecimal format.
	 *
	 * @param[in] length The length of the buffer to be printed.
	 * @param[in] buffer Pointer to the buffer containing the data to be dumped.
	 * @param[in] module The module type for debugging output, default is EM_STDOUT.
	 *
	 * @note Ensure that the buffer is valid and the length is correct to avoid undefined behavior.
	 */
	void print_hex_dump(unsigned int length, uint8_t *buffer, easymesh_dbg_type_t module=EM_STDOUT);

	void print_hex_dump(const std::vector<uint8_t>& data, easymesh_dbg_type_t module=EM_STDOUT);



	/**
	 * @brief Captures and prints the current call stack to stderr.
	 *
	 * The stack trace is printed to stderr with each frame on a separate line.
	 *	 
	 * @note The stack trace information may be limited depending on compilation
	 *       flags. For best results, compile with debugging information (-g).
	 */
	void print_stacktrace();


	/**
	 * @brief Converts a MAC address to its string representation.
	 *
	 * This function takes a MAC address as an array of 6 bytes and converts it
	 * into a human-readable string format, with bytes separated by a specified
	 * delimiter.
	 *
	 * @param[in] mac The MAC address as an array of 6 bytes.
	 * @param[in] delim The delimiter between bytes (default: ":").
	 *
	 * @return A string representing the MAC address in the format "XX:XX:XX:XX:XX:XX".
	 */
	inline std::string mac_to_string(const uint8_t mac[6], const std::string& delim = ":") {
		char mac_str[18]; // Max size: 6 bytes * 2 hex chars + 5 delimiters + null terminator
		snprintf(mac_str, sizeof(mac_str), "%02x%s%02x%s%02x%s%02x%s%02x%s%02x", 
				mac[0], delim.c_str(), mac[1], delim.c_str(), mac[2], delim.c_str(),
				mac[3], delim.c_str(), mac[4], delim.c_str(), mac[5]);
		return std::string(mac_str);
	}




	/**!
	 * @brief Splits a string by a specified delimiter.
	 *
	 * This function takes a string and splits it into a vector of substrings
	 * based on the provided delimiter character.
	 *
	 * @param[in] s The string to be split.
	 * @param[in] delimiter The character used as the delimiter.
	 *
	 * @returns A vector of strings containing the split parts.
	 *
	 * @note This function does not include the delimiter in the resulting substrings.
	 */
	std::vector<std::string> split_by_delim(const std::string& s, char delimiter);


	/**
	 * @brief Splits a hex string without delimiters into a vector of bytes.
	 *
	 * This function takes a hex string (e.g., "0123456789ab") and converts it
	 * into a vector of bytes. The function expects the string to have an even
	 * length corresponding to the expected number of bytes.
	 *
	 * @param[in] s The hex string to be converted.
	 * @param[in] expected_bytes The expected number of bytes in the output vector.
	 *
	 * @return A vector of bytes representing the hex string, or an empty vector if the input is invalid.
	 *
	 * @note The input string must have a length of exactly `expected_bytes * 2`.
	 */
	inline std::vector<uint8_t> split_nodelim_hex_str(const std::string& s, size_t expected_bytes) {
		std::vector<uint8_t> bytes;
		if (s.length() != expected_bytes * 2) return bytes; // Invalid length

		bytes.reserve(expected_bytes);
		for (size_t i = 0; i < s.length(); i += 2) {
			std::string byte_str = s.substr(i, 2);
			try {
				uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
				bytes.push_back(byte);
			} catch (...) {
				return {};
			}
		}

		return bytes;
	}

	/**
	 * @brief Converts a MAC address string to a vector of bytes.
	 *
	 * This function takes a MAC address in string format (e.g., "01:23:45:67:89:ab")
	 * and converts it into a vector of 6 bytes. If the input string is invalid,
	 * an empty vector is returned.
	 *
	 * @param[in] mac_str The MAC address string to convert.
	 * @return A vector of 6 bytes representing the MAC address, or an empty vector if the input is invalid.
	 */
	inline std::vector<uint8_t> macstr_to_vector(const std::string& mac_str, const std::string& delim = ":") {
		std::vector<uint8_t> mac;

		// Special case for empty deliminator since a split cannot be determined
		if (delim.empty()){
			return split_nodelim_hex_str(mac_str, ETHER_ADDR_LEN);	
		}
		
		std::vector<std::string> parts = split_by_delim(mac_str, delim.c_str()[0]);
		if (parts.size() != 6) return {};
		for (auto& part : parts) {
			try {
				mac.push_back(
					static_cast<uint8_t>(std::stoi(part, nullptr, 16))
				);
			} catch (...) {
				return {};
			}
		}

		return mac;
	}


	/**
	 * @brief Remove whitespace from a string.
	 * 
	 * This function takes a string and removes all whitespace characters from it.
	 * 
	 * @param[in] str The string to remove whitespace from.
	 * @returns A new string with all whitespace removed.
	 * 
	 */
	std::string remove_whitespace(std::string str);


	/**
	 * @brief Convert channel info to frequency
	 *
	 * This function converts the given channel information into a frequency in MHz.
	 *
	 * @param[in] op_class Operating class
	 * @param[in] chan Channel number
	 * @param[in] country Country code, if known; otherwise, global operating class is used
	 *
	 * @return Frequency in MHz
	 * @retval -1 if the specified channel is unknown
	 *
	 * @note Channels/Op-classes/Frequencies adapted from `hostapd/src/common/ieee80211_common.c:ieee80211_chan_to_freq`
	 */
	int em_chan_to_freq(uint8_t op_class, uint8_t chan, const std::string& country="");


	/**
	 * @brief Converts a frequency to its corresponding operating class and channel number.
	 *
	 * Checks region-specific ranges first, then falls back to global ranges if no match is found.
	 *
	 * @param[in] frequency The frequency in MHz to convert.
	 * @param[in] region refers to the region code (e.g., "US", "EU", "JP", "CN").
	 *
	 * @return A pair of {operating_class, channel}.
	 *
	 * @note If the region is not specified, the function will only consider empty string.
	 */
	std::pair<uint8_t, uint8_t> em_freq_to_chan(unsigned int frequency, const std::string& region="");


	/**
	 * @brief Translate an AKM literal to its OUI representation case-insensitively.
	 *
	 * This function takes an AKM string literal and returns its corresponding OUI representation.
	 * If the AKM is not recognized, it returns an empty string.
	 *
	 * @param[in] akm The AKM string literal, for example, "psk".
	 * @return std::string The OUI representation, such as "000FAC02" for "psk", or an empty string if the AKM is not recognized.
	 */
	std::string akm_to_oui(std::string akm);

	/**
	 * @brief Translate an OUI representation to its AKM literal case-insensitively.
	 *
	 * This function takes an OUI string representation and returns its corresponding AKM literal.
	 * If the OUI is not recognized, it returns an empty string.
	 *
	 * @param[in] oui The OUI string representation, for example, "000FAC02".
	 * @return std::string The AKM literal, such as "psk" for "000FAC02", or an empty string if the OUI is not recognized.
	 */
	std::string oui_to_akm(std::string oui);


	/** * @brief Convert an AKM string literal to its byte representation.
	 * 
	 * This function translates an AKM string (e.g., "psk") to its corresponding OUI + suite type byte array
	 * representation (e.g., {0x00, 0x0F, 0xAC, 0x02}). If the AKM is not recognized, it returns
	 * an empty vector.
	 * 
	 * @param[in] akm The AKM string literal to convert.
	 * @return A vector of bytes representing the AKM, or an empty vector if the AKM is not recognized.
	 */
	std::vector<uint8_t> akm_to_bytes(std::string akm);

	/**
	 * @brief Retrieve a network byte ordered uint16_t from an address and convert to host byte ordering
	 * 
	 * @param[in] ptr Pointer to an address containing an unsigned 16 bit integer
	 * @return uint16_t The integer at *ptr, converted to host byte ordering, or 0 if ptr is NULL.
	 * 
	 * @note `ptr` is `void*` because this is typically invoked on data that must be reinterpreted from its assigned type.
	 * @note Byte reordering is achieved using `ntohs`. 
	 */
	uint16_t deref_net_uint16_to_host(const void* const ptr);

	/**
	 * @brief Set a network byte ordered uint16_t at an address, using a host byte ordered uint16_t as input
	 * 
	 * @param[in] host_val Unsigned 16 bit integer with host byte ordering
	 * @return bool true if successful, false otherwise. Only fails if `ptr` is NULL.
	 * 
	 * @note `ptr` is `void*` because this is typically invoked on data that must be reinterpreted from its assigned type.
	 * @note Byte reordering is achieved using `htons`. 
	 */
	bool set_net_uint16_from_host(const uint16_t host_val, void* const ptr);

} // namespace util

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define em_printf(format, ...)  util::em_util_print(EM_LOG_LVL_INFO, EM_AGENT, __func__, __LINE__, format, ##__VA_ARGS__)// general log
#define em_printfout(format, ...)  util::em_util_print(EM_LOG_LVL_INFO, EM_STDOUT, __FILENAME__, __LINE__, format, ##__VA_ARGS__)// general log
#define em_util_dbg_print(module, format, ...)  util::em_util_print(EM_LOG_LVL_DEBUG, module, __func__, __LINE__, format, ##__VA_ARGS__)
#define em_util_info_print(module, format, ...)  util::em_util_print(EM_LOG_LVL_INFO, module, __func__, __LINE__, format, ##__VA_ARGS__)
#define em_util_error_print(module, format, ...)  util::em_util_print(EM_LOG_LVL_ERROR, module, __func__, __LINE__, format, ##__VA_ARGS__)


// Used to avoid many many if-not-null checks
#define EM_ASSERT_MSG_FALSE(x, ret, errMsg, ...) \
    if(x) { \
        em_printfout(errMsg, ## __VA_ARGS__); \
        return ret; \
    }

#define EM_ASSERT_MSG_TRUE(x, ret, errMsg, ...) EM_ASSERT_MSG_FALSE(!(x), ret, errMsg, ## __VA_ARGS__)
#define EM_ASSERT_NOT_NULL(x, ret, errMsg, ...) EM_ASSERT_MSG_FALSE(x == NULL, ret, errMsg, ## __VA_ARGS__)

/**
 * @brief Asserts that a pointer is not NULL, and if it is, frees up to 3 pointers and returns a value
 * @param x The pointer to check for NULL
 * @param ret The value to return if x is NULL
 * @param ptr1 First pointer to free (can be NULL)
 * @param ptr2 Second pointer to free (can be NULL) 
 * @param ptr3 Third pointer to free (can be NULL)
 * @param errMsg Format string for error message
 * @param ... Additional arguments for the format string
 */
#define EM_ASSERT_NOT_NULL_FREE3(x, ret, ptr1, ptr2, ptr3, errMsg, ...) \
    do { \
        if(x == NULL) { \
            em_printfout(errMsg, ## __VA_ARGS__); \
            void *_tmp1 = (ptr1); \
            void *_tmp2 = (ptr2); \
            void *_tmp3 = (ptr3); \
            if (_tmp1) { \
                free(_tmp1); \
            } \
            if (_tmp2) { \
                free(_tmp2); \
            } \
            if (_tmp3) { \
                free(_tmp3); \
            } \
            return ret; \
        } \
    } while (0)

/**
 * @brief Asserts that a pointer is not NULL, and if it is, frees up to 2 pointers and returns a value
 */
#define EM_ASSERT_NOT_NULL_FREE2(x, ret, ptr1, ptr2, errMsg, ...) \
    EM_ASSERT_NOT_NULL_FREE3(x, ret, ptr1, ptr2, NULL, errMsg, ## __VA_ARGS__)

/**
 * @brief Asserts that a pointer is not NULL, and if it is, frees one pointer and returns a value
 */
#define EM_ASSERT_NOT_NULL_FREE(x, ret, ptr1, errMsg, ...) \
    EM_ASSERT_NOT_NULL_FREE2(x, ret, ptr1, NULL, errMsg, ## __VA_ARGS__)


#define EM_ASSERT_NULL(x, ret, errMsg, ...) EM_ASSERT_MSG_TRUE(x == 0, ret, errMsg, ## __VA_ARGS__)
#define EM_ASSERT_EQUALS(x, y, ret, errMsg, ...) EM_ASSERT_MSG_TRUE(x == y, ret, errMsg, ## __VA_ARGS__)
#define EM_ASSERT_NOT_EQUALS(x, y, ret, errMsg, ...) EM_ASSERT_MSG_FALSE(x == y, ret, errMsg, ## __VA_ARGS__)

/**
 * @brief Asserts that a std::optional has a value, and if it doesn't, frees up to 3 pointers and returns a value
 * @param x The std::optional to check for a value
 * @param ret The value to return if x is nullopt
 * @param ptr1 First pointer to free (can be NULL)
 * @param ptr2 Second pointer to free (can be NULL) 
 * @param ptr3 Third pointer to free (can be NULL)
 * @param errMsg Format string for error message
 * @param ... Additional arguments for the format string
 */
#define EM_ASSERT_OPT_HAS_VALUE_FREE3(x, ret, ptr1, ptr2, ptr3, errMsg, ...) \
    do { \
        if(!x.has_value()) { \
            em_printfout(errMsg, ## __VA_ARGS__); \
            void *_tmp1 = (ptr1); \
            void *_tmp2 = (ptr2); \
            void *_tmp3 = (ptr3); \
            if (_tmp1) { \
                free(_tmp1); \
            } \
            if (_tmp2) { \
                free(_tmp2); \
            } \
            if (_tmp3) { \
                free(_tmp3); \
            } \
            return ret; \
        } \
    } while (0)

/**
 * @brief Asserts that a std::optional has a value, and if it doesn't, frees up to 2 pointers and returns a value
 * @param x The std::optional to check for a value
 * @param ret The value to return if x is nullopt
 * @param ptr1 First pointer to free (can be NULL)
 * @param ptr2 Second pointer to free (can be NULL) 
 * @param errMsg Format string for error message
 * @param ... Additional arguments for the format string
 */
#define EM_ASSERT_OPT_HAS_VALUE_FREE2(x, ret, ptr1, ptr2, errMsg, ...) \
    EM_ASSERT_OPT_HAS_VALUE_FREE3(x, ret, ptr1, ptr2, NULL, errMsg, ## __VA_ARGS__)

/**
 * @brief Asserts that a std::optional has a value, and if it doesn't, frees a pointer and returns a value
 * @param x The std::optional to check for a value
 * @param ret The value to return if x is nullopt
 * @param ptr1 First pointer to free (can be NULL)
 * @param errMsg Format string for error message
 * @param ... Additional arguments for the format string
 */
#define EM_ASSERT_OPT_HAS_VALUE_FREE(x, ret, ptr1, errMsg, ...) \
    EM_ASSERT_OPT_HAS_VALUE_FREE2(x, ret, ptr1, NULL, errMsg, ## __VA_ARGS__)

/**
 * @brief Asserts that a std::optional has a value, and returns a value if it doesn't
 * @param x The std::optional to check for a value
 * @param ret The value to return if x is nullopt
 * @param errMsg Format string for error message
 * @param ... Additional arguments for the format string
 */
#define EM_ASSERT_OPT_HAS_VALUE(x, ret, errMsg, ...) EM_ASSERT_MSG_TRUE(x.has_value(), ret, errMsg, ## __VA_ARGS__)

#endif

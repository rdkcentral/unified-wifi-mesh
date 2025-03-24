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
#include <sys/prctl.h>

#include <string>
#include <memory>
#include <vector>

#ifndef LOG_PATH_PREFIX
#define LOG_PATH_PREFIX "/nvram/"
#endif // LOG_PATH_PREFIX

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

void em_util_print(easymesh_log_level_t level, easymesh_dbg_type_t module, const char *func, int line, const char *format, ...);
void delay(int );
void add_milliseconds(struct timespec *ts, long milliseconds);
char *get_date_time_rfc3399(char *buff, unsigned int len);
void print_hex_dump(unsigned int length, uint8_t *buffer, easymesh_dbg_type_t module=EM_STDOUT);

/**
 * Converts a MAC address to its string representation
 * 
 * @param mac The MAC address as an array of 6 bytes
 * @param delim The delimiter between bytes (default: ":")
 * @return The MAC address as a string in the format "XX:XX:XX:XX:XX:XX"
 */
inline std::string mac_to_string(const uint8_t mac[6], const std::string& delim = ":") {
    char mac_str[18]; // Max size: 6 bytes * 2 hex chars + 5 delimiters + null terminator
    snprintf(mac_str, sizeof(mac_str), "%02x%s%02x%s%02x%s%02x%s%02x%s%02x", 
             mac[0], delim.c_str(), mac[1], delim.c_str(), mac[2], delim.c_str(),
             mac[3], delim.c_str(), mac[4], delim.c_str(), mac[5]);
    return std::string(mac_str);
}

/**
 * Split a string by a delimiter
 * 
 * @param s The string to split
 * @param delimiter The delimiter character
 * @return A vector of strings containing the split parts
 */
std::vector<std::string> split_by_delim(const std::string& s, char delimiter);

/**
 * Remove whitespace from a string
 * 
 * @param str The string to remove whitespace from
 * @return The string with all whitespace removed
 */
std::string remove_whitespace(std::string str);

/**
 * em_chan_to_freq - Convert channel info to frequency
 * @param op_class: Operating class
 * @param chan: Channel number
 * @param country: Country code, if known; otherwise, global operating class is used
 * @return Frequency in MHz or -1 if the specified channel is unknown
 * 
 * @note Channels/Op-classes/Frequencies adapted from `hostapd/src/common/ieee80211_common.c:ieee80211_chan_to_freq`
 */
int em_chan_to_freq(uint8_t op_class, uint8_t chan, const std::string& country="");

/**
 * Converts a frequency to its corresponding operating class and channel number.
 * Checks region-specific ranges first, then falls back to global ranges if no match is found.
 * 
 * @param frequency The frequency in MHz to convert
 * @param region Two-letter region code (e.g., "US", "EU", "JP", "CN"). Empty string for global ranges only.
 * @return Returns pair of {operating_class, channel}. 
 */
std::pair<uint8_t, uint8_t> em_freq_to_chan(unsigned int frequency, const std::string& region="");

} // namespace util

#define em_printf(format, ...)  util::em_util_print(EM_LOG_LVL_INFO, EM_AGENT, __func__, __LINE__, format, ##__VA_ARGS__)// general log
#define em_util_dbg_print(module, format, ...)  util::em_util_print(EM_LOG_LVL_DEBUG, module, __func__, __LINE__, format, ##__VA_ARGS__)
#define em_util_info_print(module, format, ...)  util::em_util_print(EM_LOG_LVL_INFO, module, __func__, __LINE__, format, ##__VA_ARGS__)
#define em_util_error_print(module, format, ...)  util::em_util_print(EM_LOG_LVL_ERROR, module, __func__, __LINE__, format, ##__VA_ARGS__)

#endif

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>


#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>


#include "util.h"

char *get_date_time_rfc3399(char *buff, unsigned int len)
{
	time_t now;
    struct tm *timeinfo;

    time(&now);
    timeinfo = localtime(&now);

	memset(buff, 0, len);
	strftime(buff, len, "%Y-%m-%dT%H:%M:%SZ", timeinfo);

	return buff;
}

void add_milliseconds(struct timespec *ts, long milliseconds)
{
	long seconds = milliseconds / 1000;
    long nanoseconds = (milliseconds % 1000) * 1000000;

    ts->tv_sec += seconds;
    ts->tv_nsec += nanoseconds;

    // Handle potential overflow in nanoseconds
    if (ts->tv_nsec >= 1000000000) {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000;
    }

}

void delay(int seconds) {
    time_t start_time, current_time;

    // Get current time
    time(&start_time);

    do {
        // Update current time
        time(&current_time);
    } while ((current_time - start_time) < seconds); // Loop until desired delay is achieved
}

char *get_formatted_time_em(char *time)
{
    struct tm *tm_info;
    struct timeval tv_now;
    char tmp[128];

    gettimeofday(&tv_now, NULL);
    tm_info = (struct tm *)localtime(&tv_now.tv_sec);

    strftime(tmp, 128, "%m/%d/%y - %T", tm_info);

    snprintf(time, 128, "%s.%06lld", tmp, (long long)tv_now.tv_usec);
    return time;
}

void em_util_print(easymesh_log_level_t level, easymesh_dbg_type_t module, const char *func, int line, const char *format, ...)
{
    char buff[256] = {0};
    char time_buff[128] = {0};
    va_list list;
    FILE *fpg = NULL;
#if defined(__ENABLE_PID__) && (__ENABLE_PID__)
    pid_t pid;
#endif
    extern char *__progname;
    char filename_dbg_enable[64];
    char module_filename[32];
    char filename[100];
    const char *severity;

    switch (module) {
        case EM_AGENT:
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), LOG_PATH_PREFIX "emAgentDbg");
            snprintf(module_filename, sizeof(module_filename), "emAgent");
            break;
        case EM_CTRL:
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), LOG_PATH_PREFIX "emCtrlDbg");
            snprintf(module_filename, sizeof(module_filename), "emCtrl");
            break;
        case EM_MGR:
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), LOG_PATH_PREFIX "emMgrDbg");
            snprintf(module_filename, sizeof(module_filename), "emMgr");
            break;
        case EM_DB:
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), LOG_PATH_PREFIX "emDbDbg");
            snprintf(module_filename, sizeof(module_filename), "emDb");
            break;
        case EM_PROV:
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), LOG_PATH_PREFIX "emProvDbg");
            snprintf(module_filename, sizeof(module_filename), "emProv");
            break;
        case EM_CONF:
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), LOG_PATH_PREFIX "emConfDbg");
            snprintf(module_filename, sizeof(module_filename), "emConf");
            break;
        default:
            return;
    }

    if ((access(filename_dbg_enable, R_OK)) == 0) {
        snprintf(filename, sizeof(filename), "/tmp/%s", module_filename);
        fpg = fopen(filename, "a+");
        if (fpg == NULL) {
            return;
        }
    } else {
        switch (level) {
            case EM_LOG_LVL_INFO:
            case EM_LOG_LVL_ERROR:
                snprintf(filename, sizeof(filename), "/rdklogs/logs/%s.txt", module_filename);
                fpg = fopen(filename, "a+");
                if (fpg == NULL) {
                    return;
                }
                break;
            case EM_LOG_LVL_DEBUG:
            default:
                return;
        }
    }

    switch (level) {
        case EM_LOG_LVL_INFO:
            severity = "INFO";
            break;
        case EM_LOG_LVL_ERROR:
            severity = "ERROR";
            break;
        case EM_LOG_LVL_DEBUG:
            severity = "DEBUG";
            break;
        default:
            severity = "UNKNOWN";
            break;
    }

    get_formatted_time_em(time_buff);
    snprintf(buff, sizeof(buff), "\n[%s] %s %s:%s:%d: %s: ", __progname ? __progname : "", time_buff, module_filename, func, line, severity);
    fprintf(fpg, "%s", buff);

    va_start(list, format);
    vfprintf(fpg, format, list);
    va_end(list);

    fflush(fpg);
    fclose(fpg);
}



struct freq_range {
    uint16_t min_chan;    // Corresponds to the "if (chan < X" checks
    uint16_t max_chan;    // Corresponds to the "chan > Y)" checks
    uint32_t base_freq;   // The base frequency (e.g., 2407, 5000, 56160)
    uint16_t spacing;     // The multiplication factor (e.g., 5 MHz steps, 2160 MHz steps)
};

// Complete region definitions from original code
const std::vector<std::string> us_region = {"US", "CA"};
const std::vector<std::string> eu_region = {
    "AL", "AM", "AT", "AZ", "BA", "BE", "BG", "BY", "CH", "CY", "CZ", "DE",
    "DK", "EE", "EL", "ES", "FI", "FR", "GE", "HR", "HU", "IE", "IS", "IT",
    "LI", "LT", "LU", "LV", "MD", "ME", "MK", "MT", "NL", "NO", "PL", "PT",
    "RO", "RS", "RU", "SE", "SI", "SK", "TR", "UA", "UK", "GB"
};
const std::vector<std::string> jp_region = {"JP"};
const std::vector<std::string> cn_region = {"CN"};

// Complete frequency mappings for each region
// Maps: operating_class -> {min_channel, max_channel, base_frequency_MHz, channel_spacing_MHz}
// These maps replace the switch statements from the original code (ieee80211_chan_to_freq_us, 
// em_chan_to_freq_eu, etc.) Each entry corresponds to a case in those switch statements.
// 
// For example, in the original (ieee80211_chan_to_freq) US switch statement:
//   case 12: /* channels 1..11 */
//     if (chan < 1 || chan > 11) return -1;
//     return 2407 + 5 * chan;
// 
// Becomes in the map:
//   {12, {1, 11, 2407, 5}}
//
// The freq_range struct handles the channel range check and frequency calculation
// that was previously done in each switch case.

const std::unordered_map<uint8_t, freq_range> us_freq_map = {
    {12, {1, 11, 2407, 5}},      // 2.4 GHz channels 1-11
    {32, {1, 7, 2407, 5}},       // 2.4 GHz 40MHz channels 1-7
    {33, {5, 11, 2407, 5}},      // 2.4 GHz 40MHz channels 5-11
    {1, {36, 48, 5000, 5}},      // 5 GHz channels 36-48
    {2, {52, 64, 5000, 5}},      // 5 GHz channels 52-64
    {4, {100, 144, 5000, 5}},    // 5 GHz channels 100-144
    {5, {149, 165, 5000, 5}},    // 5 GHz channels 149-165
    {34, {1, 8, 56160, 2160}},   // 60 GHz channels 1-8
    {37, {9, 15, 56160, 2160}},  // 60 GHz EDMG CB2
    {38, {17, 22, 56160, 2160}}, // 60 GHz EDMG CB3
    {39, {25, 29, 56160, 2160}}  // 60 GHz EDMG CB4
};

const std::unordered_map<uint8_t, freq_range> eu_freq_map = {
    {4, {1, 13, 2407, 5}},       // 2.4 GHz channels 1-13
    {11, {1, 9, 2407, 5}},       // 2.4 GHz 40MHz channels 1-9
    {12, {5, 13, 2407, 5}},      // 2.4 GHz 40MHz channels 5-13
    {1, {36, 48, 5000, 5}},      // 5 GHz channels 36-48
    {2, {52, 64, 5000, 5}},      // 5 GHz channels 52-64
    {3, {100, 140, 5000, 5}},    // 5 GHz channels 100-140
    {17, {149, 169, 5000, 5}},   // 5 GHz channels 149-169
    {18, {1, 6, 56160, 2160}},   // 60 GHz channels 1-6
    {21, {9, 11, 56160, 2160}},  // 60 GHz EDMG CB2
    {22, {17, 18, 56160, 2160}}, // 60 GHz EDMG CB3
    {23, {25, 25, 56160, 2160}}  // 60 GHz EDMG CB4
};

const std::unordered_map<uint8_t, freq_range> jp_freq_map = {
    {30, {1, 13, 2407, 5}},      // 2.4 GHz channels 1-13
    {31, {14, 14, 2414, 5}},     // 2.4 GHz channel 14
    {1, {34, 64, 5000, 5}},      // 5 GHz channels 34-64
    {32, {52, 64, 5000, 5}},     // 5 GHz channels 52-64
    {34, {100, 140, 5000, 5}},   // 5 GHz channels 100-140
    {59, {1, 6, 56160, 2160}},   // 60 GHz channels 1-6
    {62, {9, 11, 56160, 2160}},  // 60 GHz EDMG CB2
    {63, {17, 18, 56160, 2160}}, // 60 GHz EDMG CB3
    {64, {25, 25, 56160, 2160}}  // 60 GHz EDMG CB4
};

const std::unordered_map<uint8_t, freq_range> cn_freq_map = {
    {7, {1, 13, 2407, 5}},       // 2.4 GHz channels 1-13
    {8, {1, 9, 2407, 5}},        // 2.4 GHz 40MHz channels 1-9
    {9, {5, 13, 2407, 5}},       // 2.4 GHz 40MHz channels 5-13
    {1, {36, 48, 5000, 5}},      // 5 GHz channels 36-48
    {2, {52, 64, 5000, 5}},      // 5 GHz channels 52-64
    {3, {149, 165, 5000, 5}},    // 5 GHz channels 149-165
    {6, {149, 157, 5000, 5}}     // 5 GHz 40MHz channels 149,157
};

// This function replaces the original em_chan_to_freq() function
// Instead of checking each region's frequency mapping with separate function calls,
// it uses the map structure to look up the correct frequency calculation parameters
// Global frequency map (from original em_chan_to_freq_global function)
const std::unordered_map<uint8_t, freq_range> global_freq_map = {
    // 2.4 GHz band
    {81, {1, 13, 2407, 5}},      // channels 1-13
    {82, {14, 14, 2414, 5}},     // channel 14
    {83, {1, 13, 2407, 5}},      // channels 1-9; 40 MHz
    {84, {5, 13, 2407, 5}},      // channels 5-13; 40 MHz

    // 5 GHz band
    {115, {36, 48, 5000, 5}},    // channels 36-48; indoor only
    {116, {36, 44, 5000, 5}},    // channels 36,44; 40 MHz
    {117, {40, 48, 5000, 5}},    // channels 40,48; 40 MHz
    {118, {52, 64, 5000, 5}},    // channels 52-64; dfs
    {119, {52, 60, 5000, 5}},    // channels 52,60; 40 MHz
    {120, {56, 64, 5000, 5}},    // channels 56,64; 40 MHz
    {121, {100, 140, 5000, 5}},  // channels 100-140
    {122, {100, 142, 5000, 5}},  // channels 100-142; 40 MHz
    {123, {104, 136, 5000, 5}},  // channels 104-136; 40 MHz
    {124, {149, 161, 5000, 5}},  // channels 149-161
    {125, {149, 177, 5000, 5}},  // channels 149-177
    {126, {149, 173, 5000, 5}},  // channels 149-173; 40 MHz
    {127, {153, 177, 5000, 5}},  // channels 153-177; 40 MHz
    {128, {36, 177, 5000, 5}},   // 80 MHz centered on 42,58,106,122,138,155,171
    {129, {36, 177, 5000, 5}},   // 160 MHz centered on 50,114,163
    {130, {36, 177, 5000, 5}},   // As class 128

    // 6 GHz band (UHB channels)
    {131, {1, 233, 5950, 5}},    // 20 MHz
    {132, {3, 233, 5950, 5}},    // 40 MHz
    {133, {7, 233, 5950, 5}},    // 80 MHz
    {134, {15, 233, 5950, 5}},   // 160 MHz
    {135, {7, 233, 5950, 5}},    // 80+80 MHz
    {136, {2, 2, 5935, 1}},      // Special case channel 2

    // 60 GHz band
    {180, {1, 8, 56160, 2160}},    // channels 1-8
    {181, {9, 15, 56160, 2160}},   // EDMG CB2
    {182, {17, 22, 56160, 2160}},  // EDMG CB3
    {183, {25, 29, 56160, 2160}}   // EDMG CB4
};

const std::unordered_map<uint8_t, freq_range>* get_region_map(const std::string& country) {
    static std::unordered_map<std::string, std::unordered_map<uint8_t, freq_range>> merged_maps;
    
    // Return cached merged map if it exists
    if (merged_maps.find(country) != merged_maps.end()) {
        return &merged_maps[country];
    }

    // Start with a copy of the global map
    std::unordered_map<uint8_t, freq_range> merged = global_freq_map;
    
    // Add region-specific entries (they will override global entries if they exist)
    if (country.length() == 2) {
        const std::unordered_map<uint8_t, freq_range>* region_map = nullptr;
        
        if (std::find(us_region.begin(), us_region.end(), country) != us_region.end())
            region_map = &us_freq_map;
        else if (std::find(eu_region.begin(), eu_region.end(), country) != eu_region.end())
            region_map = &eu_freq_map;
        else if (std::find(jp_region.begin(), jp_region.end(), country) != jp_region.end())
            region_map = &jp_freq_map;
        else if (std::find(cn_region.begin(), cn_region.end(), country) != cn_region.end())
            region_map = &cn_freq_map;
            
        if (region_map) {
            // Merge region-specific entries
            for (const auto& [op_class, range] : *region_map) {
                merged[op_class] = range;  // Overwrites global entry if it exists
            }
        }
    }
    
    // Cache the merged map
    merged_maps[country] = std::move(merged);
    
    return &merged_maps[country];
}

int em_chan_to_freq(const std::string& country, uint8_t op_class, uint8_t chan) {
    // Get region-specific frequency map
    const auto* freq_map = get_region_map(country);
    if (!freq_map){
        printf("%s:%d Failed to find frequency map\n", __func__, __LINE__);
        return -1;
    }

    // Look up frequency range for operating class
    auto range_it = freq_map->find(op_class);
    if (range_it == freq_map->end()){
        printf("%s:%d Failed to lookup frequency range\n", __func__, __LINE__);
        return -1;
    }

    // Check channel range and calculate frequency
    const auto& range = range_it->second;
    if (chan < range.min_chan || chan > range.max_chan) {
        printf("%s:%d Channel range check failed\n", __func__, __LINE__);
        return -1;
    }

    return range.base_freq + chan * range.spacing;
}

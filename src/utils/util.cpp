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
#include <sstream>

#include <cstdlib>
#include <execinfo.h>


#include "util.h"

extern "C" {
    extern char *__progname;
}

void util::print_stacktrace() {
    // Get the stack trace (Unix/Linux implementation)
    const int max_frames = 100;
    void* callstack[max_frames];
    int frames = backtrace(callstack, max_frames);
    char** symbols = backtrace_symbols(callstack, frames);
    
    // Print the stack trace
    fprintf(stderr, "Stack trace:\n");
    for (int i = 0; i < frames; i++) {
        fprintf(stderr, "%s\n", symbols[i]);
    }
    
    free(symbols);
}

char *util::get_date_time_rfc3399(char *buff, unsigned int len)
{
	time_t now;
    struct tm *timeinfo;

    time(&now);
    timeinfo = localtime(&now);

	memset(buff, 0, len);
	strftime(buff, len, "%Y-%m-%dT%H:%M:%SZ", timeinfo);

	return buff;
}

void util::add_milliseconds(struct timespec *ts, long milliseconds)
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

void util::delay(int seconds) {
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

std::pair<FILE*, std::string> get_module_log_fd_name(easymesh_dbg_type_t module, easymesh_log_level_t level) {
    std::string filename_dbg_enable = std::string(LOG_PATH_PREFIX);
    std::string module_filename;

    switch (module) {
        case EM_AGENT:
            filename_dbg_enable += "emAgentDbg";
            module_filename = "emAgent";
            break;
        case EM_CTRL:
            filename_dbg_enable += "emCtrlDbg";
            module_filename = "emCtrl";
            break;
        case EM_MGR:
            filename_dbg_enable += "emMgrDbg";
            module_filename = "emMgr";
            break;
        case EM_DB:
            filename_dbg_enable += "emDbDbg";
            module_filename = "emDb";
            break;
        case EM_PROV:
            filename_dbg_enable += "emProvDbg";
            module_filename = "emProv";
            break;
        case EM_CONF:
            filename_dbg_enable += "emConfDbg";
            module_filename = "emConf";
            break;
        case EM_STDOUT:
            return std::make_pair(stdout, "");
    }

    bool debug_enabled = ((access(filename_dbg_enable.c_str(), R_OK)) == 0);
    
    if (debug_enabled) {
        std::string filename = "/tmp/" + module_filename;
        return std::make_pair(fopen(filename.c_str(), "a+"), module_filename);
    }

    switch (level) {
        case EM_LOG_LVL_INFO:
        case EM_LOG_LVL_ERROR: {
            std::string filename = "/rdklogs/logs/" + module_filename + ".txt";
            return std::make_pair(fopen(filename.c_str(), "a+"), module_filename);
        }
        case EM_LOG_LVL_DEBUG:
        default:
            break;
    }

    return std::make_pair(nullptr, std::string());
}

void util::print_hex_dump(unsigned int length, uint8_t *buffer, easymesh_dbg_type_t module)
{
    int i;
    uint8_t buff[512] = {};
    const uint8_t * pc = (const uint8_t *)buffer;

    auto [fp, module_filename] = get_module_log_fd_name(module, EM_LOG_LVL_DEBUG);
    if (fp == NULL) {
        return;
    }

    if ((pc == NULL) || (length <= 0)) {
        fprintf(fp,"buffer NULL or BAD LENGTH = %d :\n", length);
        if (fp != stdout) fclose (fp);
        return;
    }

    for (i = 0; i < length; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                fprintf(fp,"  %s\n", buff);
            fprintf(fp,"  %04x ", i);
        }

        fprintf(fp," %02x", pc[i]);

        if (!isprint(pc[i]))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        fprintf(fp,"   ");
        i++;
    }

    fprintf(fp,"  %s\n", buff);
    if (fp != stdout) fclose (fp);
}



void util::em_util_print(easymesh_log_level_t level, easymesh_dbg_type_t module, const char *func, int line, const char *format, ...)
{
    char buff[256] = {0};
    char time_buff[128] = {0};
    va_list list;
#if defined(__ENABLE_PID__) && (__ENABLE_PID__)
    pid_t pid;
#endif
    
    const char *severity;

    auto [fp, module_filename] = get_module_log_fd_name(module, level);
    if (fp == NULL) return; 



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
    snprintf(buff, sizeof(buff), "[%s] %s %s:%s:%d: %s: ", __progname ? __progname : "", time_buff, module_filename.c_str(), func, line, severity);
    fprintf(fp, "%s", buff);

    va_start(list, format);
    vfprintf(fp, format, list);
    va_end(list);

    fprintf(fp, "\n");

    fflush(fp);
    if (fp != stdout) fclose (fp);
}


struct freq_range {
    uint8_t op_class;
    uint8_t min_chan;
    uint8_t max_chan;
    uint16_t base_freq;
    uint16_t spacing;
    std::string region;  // "" for global
};

const std::vector<freq_range> frequency_ranges = {
    // Global frequency ranges
    // 2.4 GHz band
    {81, 1, 13, 2407, 5, ""},      // channels 1-13
    {82, 14, 14, 2414, 5, ""},     // channel 14
    {83, 1, 13, 2407, 5, ""},      // channels 1-9; 40 MHz
    {84, 5, 13, 2407, 5, ""},      // channels 5-13; 40 MHz

    // 5 GHz band
    {115, 36, 48, 5000, 5, ""},    // channels 36-48; indoor only
    {116, 36, 44, 5000, 5, ""},    // channels 36,44; 40 MHz
    {117, 40, 48, 5000, 5, ""},    // channels 40,48; 40 MHz
    {118, 52, 64, 5000, 5, ""},    // channels 52-64; dfs
    {119, 52, 60, 5000, 5, ""},    // channels 52,60; 40 MHz
    {120, 56, 64, 5000, 5, ""},    // channels 56,64; 40 MHz
    {121, 100, 140, 5000, 5, ""},  // channels 100-140
    {122, 100, 142, 5000, 5, ""},  // channels 100-142; 40 MHz
    {123, 104, 136, 5000, 5, ""},  // channels 104-136; 40 MHz
    {124, 149, 161, 5000, 5, ""},  // channels 149-161
    {125, 149, 177, 5000, 5, ""},  // channels 149-177
    {126, 149, 173, 5000, 5, ""},  // channels 149-173; 40 MHz
    {127, 153, 177, 5000, 5, ""},  // channels 153-177; 40 MHz
    {128, 36, 177, 5000, 5, ""},   // 80 MHz centered on 42,58,106,122,138,155,171
    {129, 36, 177, 5000, 5, ""},   // 160 MHz centered on 50,114,163
    {130, 36, 177, 5000, 5, ""},   // As class 128

    // 6 GHz band (UHB channels)
    {131, 1, 233, 5950, 5, ""},    // 20 MHz
    {132, 3, 233, 5950, 5, ""},    // 40 MHz
    {133, 7, 233, 5950, 5, ""},    // 80 MHz
    {134, 15, 233, 5950, 5, ""},   // 160 MHz
    {135, 7, 233, 5950, 5, ""},    // 80+80 MHz
    {136, 2, 2, 5935, 1, ""},      // Special case channel 2

    // 60 GHz band
    {180, 1, 8, 56160, 2160, ""},    // channels 1-8
    {181, 9, 15, 56160, 2160, ""},   // EDMG CB2
    {182, 17, 22, 56160, 2160, ""},  // EDMG CB3
    {183, 25, 29, 56160, 2160, ""},  // EDMG CB4

    // US region specific
    {12, 1, 11, 2407, 5, "US"},      // 2.4 GHz channels 1-11
    {32, 1, 7, 2407, 5, "US"},       // 2.4 GHz 40MHz channels 1-7
    {33, 5, 11, 2407, 5, "US"},      // 2.4 GHz 40MHz channels 5-11
    {1, 36, 48, 5000, 5, "US"},      // 5 GHz channels 36-48
    {2, 52, 64, 5000, 5, "US"},      // 5 GHz channels 52-64
    {4, 100, 144, 5000, 5, "US"},    // 5 GHz channels 100-144
    {5, 149, 165, 5000, 5, "US"},    // 5 GHz channels 149-165
    {34, 1, 8, 56160, 2160, "US"},   // 60 GHz channels 1-8
    {37, 9, 15, 56160, 2160, "US"},  // 60 GHz EDMG CB2
    {38, 17, 22, 56160, 2160, "US"}, // 60 GHz EDMG CB3
    {39, 25, 29, 56160, 2160, "US"}, // 60 GHz EDMG CB4

    // EU region specific
    {4, 1, 13, 2407, 5, "EU"},       // 2.4 GHz channels 1-13
    {11, 1, 9, 2407, 5, "EU"},       // 2.4 GHz 40MHz channels 1-9
    {12, 5, 13, 2407, 5, "EU"},      // 2.4 GHz 40MHz channels 5-13
    {1, 36, 48, 5000, 5, "EU"},      // 5 GHz channels 36-48
    {2, 52, 64, 5000, 5, "EU"},      // 5 GHz channels 52-64
    {3, 100, 140, 5000, 5, "EU"},    // 5 GHz channels 100-140
    {17, 149, 169, 5000, 5, "EU"},   // 5 GHz channels 149-169
    {18, 1, 6, 56160, 2160, "EU"},   // 60 GHz channels 1-6
    {21, 9, 11, 56160, 2160, "EU"},  // 60 GHz EDMG CB2
    {22, 17, 18, 56160, 2160, "EU"}, // 60 GHz EDMG CB3
    {23, 25, 25, 56160, 2160, "EU"}, // 60 GHz EDMG CB4

    // JP region specific
    {30, 1, 13, 2407, 5, "JP"},      // 2.4 GHz channels 1-13
    {31, 14, 14, 2414, 5, "JP"},     // 2.4 GHz channel 14
    {1, 34, 64, 5000, 5, "JP"},      // 5 GHz channels 34-64
    {32, 52, 64, 5000, 5, "JP"},     // 5 GHz channels 52-64
    {34, 100, 140, 5000, 5, "JP"},   // 5 GHz channels 100-140
    {59, 1, 6, 56160, 2160, "JP"},   // 60 GHz channels 1-6
    {62, 9, 11, 56160, 2160, "JP"},  // 60 GHz EDMG CB2
    {63, 17, 18, 56160, 2160, "JP"}, // 60 GHz EDMG CB3
    {64, 25, 25, 56160, 2160, "JP"}, // 60 GHz EDMG CB4

    // CN region specific
    {7, 1, 13, 2407, 5, "CN"},       // 2.4 GHz channels 1-13
    {8, 1, 9, 2407, 5, "CN"},        // 2.4 GHz 40MHz channels 1-9
    {9, 5, 13, 2407, 5, "CN"},       // 2.4 GHz 40MHz channels 5-13
    {1, 36, 48, 5000, 5, "CN"},      // 5 GHz channels 36-48
    {2, 52, 64, 5000, 5, "CN"},      // 5 GHz channels 52-64
    {3, 149, 165, 5000, 5, "CN"},    // 5 GHz channels 149-165
    {6, 149, 157, 5000, 5, "CN"}     // 5 GHz 40MHz channels 149,157
};

int util::em_chan_to_freq(uint8_t op_class, uint8_t channel, const std::string& region) {
    for (const auto& range : frequency_ranges) {
        if ((range.region.empty() || range.region == region) && 
            range.op_class == op_class &&
            channel >= range.min_chan && 
            channel <= range.max_chan) {
            return range.base_freq + (channel * range.spacing);
        }
    }
    return -1;
}

std::pair<uint8_t, uint8_t> util::em_freq_to_chan(unsigned int frequency, const std::string& region) {
    std::pair<uint8_t, uint8_t> global_result;
    
    for (const auto& range : frequency_ranges) {
        int min_freq = range.base_freq + (range.min_chan * range.spacing);
        int max_freq = range.base_freq + (range.max_chan * range.spacing);
        
        if (frequency < min_freq || frequency > max_freq) continue;
        
        if ((frequency - range.base_freq) % range.spacing != 0) continue;
        
        // Calculate channel number and validate it's within uint8_t/channel range
        int channel_calc = (frequency - range.base_freq) / range.spacing;
        if (channel_calc < range.min_chan || channel_calc > range.max_chan) continue;
        
        uint8_t channel = static_cast<uint8_t>(channel_calc);
        
        // Frequency is within range, return op class and channel
        auto result = std::make_pair(range.op_class, channel);
        if (range.region == region) return result;
        
        // Save global result if no region-specific match
        if (range.region.empty()) {
            global_result = result;
        }
    }
    
    // No region-specific match was found, return global result if available
    return global_result;
}

std::vector<std::string> util::split_by_delim(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    
    return tokens;
}

std::string util::remove_whitespace(std::string str)
{
    str.erase(std::remove_if(str.begin(), str.end(), ::isspace), str.end());
    return str;
}
std::string util::akm_to_oui(std::string akm) {
    std::transform(akm.begin(), akm.end(), akm.begin(), [](unsigned char c){ return std::tolower(c); });
    static const std::unordered_map<std::string, std::string> akm_map = {
        {"psk", "000FAC02"},
        {"sae", "000FAC08"},
        {"dpp", "506F9A02"},
    };
    const auto it = akm_map.find(akm);
    if (it == akm_map.end()) return std::string();
    return it->second;
}

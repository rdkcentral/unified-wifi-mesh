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
#include <time.h>
#include "util.h"

void delay(int seconds) {
    time_t start_time, current_time;

    // Get current time
    time(&start_time);

    do {
        // Update current time
        time(&current_time);
    } while ((current_time - start_time) < seconds); // Loop until desired delay is achieved
}

char *get_formatted_time(char *time)
{
    struct tm *tm_info;
    struct timeval tv_now;
    char tmp[128];

    gettimeofday(&tv_now, NULL);
    tm_info = (struct tm *)localtime(&tv_now.tv_sec);

    strftime(tmp, 128, "%y%m%d-%T", tm_info);

    snprintf(time, 128, "%s.%06lld", tmp, (long long)tv_now.tv_usec);
    return time;
}


void em_util_print(easymesh_log_level_t level, easymesh_dbg_type_t module, const char *format, ...)
{
    char buff[256] = {0};
    va_list list;
    FILE *fpg = NULL;
#if defined(__ENABLE_PID__) && (__ENABLE_PID__)
    pid_t pid;
#endif
    extern char *__progname;
    char filename_dbg_enable[64];
    char module_filename[32];
    char filename[100];

    switch (module) {
        case EM_AGENT: {
                          snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), LOG_PATH_PREFIX "emAgentDbg");
                          snprintf(module_filename, sizeof(module_filename), "emAgent");
                          break;
                      }
        case EM_CTRL: {
                         snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), LOG_PATH_PREFIX "emCtrlDbg");
                         snprintf(module_filename, sizeof(module_filename), "emCtrl");
                         break;
                     }
        case EM_MGR: {
                        snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), LOG_PATH_PREFIX "emMgrDbg");
                        snprintf(module_filename, sizeof(module_filename), "emMgr");
                        break;
                    }
        case EM_DB: {
                       snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), LOG_PATH_PREFIX "emDbDbg");
                       snprintf(module_filename, sizeof(module_filename), "emDb");
                       break;
                   }
        case EM_PROV: {
                         snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), LOG_PATH_PREFIX "emProvDbg");
                         snprintf(module_filename, sizeof(module_filename), "emProv");
                         break;
                     }
        case EM_CONF: {
                         snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), LOG_PATH_PREFIX "emConfDbg");
                         snprintf(module_filename, sizeof(module_filename), "emConf");
                         break;
                     }
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
    snprintf(&buff[0], sizeof(buff), "[%s] ", __progname ? __progname : "");
    get_formatted_time(&buff[strlen(buff)]);

    fprintf(fpg, "%s ", buff);

    va_start(list, format);
    vfprintf(fpg, format, list);
    va_end(list);

    fflush(fpg);
    fclose(fpg);
}

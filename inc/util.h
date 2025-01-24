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
#ifdef __cplusplus
extern "C" {
#endif
#ifndef LOG_PATH_PREFIX
#define LOG_PATH_PREFIX "/nvram/"
#endif // LOG_PATH_PREFIX

typedef enum {
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

void em_util_print(easymesh_log_level_t level, easymesh_dbg_type_t module, const char *func, int line, const char *format, ...);
void delay(int );
void add_milliseconds(struct timespec *ts, long milliseconds);
char *get_date_time_rfc3399(char *buff, unsigned int len);

#define em_printf(format, ...)  em_util_print(EM_LOG_LVL_INFO, EM_AGENT, __func__, __LINE__, format, ##__VA_ARGS__)// general log
#define em_util_dbg_print(module, format, ...)  em_util_print(EM_LOG_LVL_DEBUG, module, __func__, __LINE__, format, ##__VA_ARGS__)
#define em_util_info_print(module, format, ...)  em_util_print(EM_LOG_LVL_INFO, module, __func__, __LINE__, format, ##__VA_ARGS__)
#define em_util_error_print(module, format, ...)  em_util_print(EM_LOG_LVL_ERROR, module, __func__, __LINE__, format, ##__VA_ARGS__)
#ifdef __cplusplus
}
#endif
#endif

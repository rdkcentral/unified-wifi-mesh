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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include "util.h"
#include "de_scan_result.h"

void de_scan_result_t::update(de_scan_result_t& res)
{
    strncpy(m_timestamp, res.m_timestamp, strlen(res.m_timestamp) + 1);
    m_agg_scan_dur = res.m_agg_scan_dur;
    m_scan_type = res.m_scan_type;
}

void de_scan_result_t::serialize(rbusObject_t& ob)
{
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_timestamp);
    rbusObject_SetValue(ob, "TimeStamp", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_agg_scan_dur);
    rbusObject_SetValue(ob, "AggregateScanDuration", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, m_scan_type);
    rbusObject_SetValue(ob, "ScanType", value);
    rbusValue_Release(value);
    
}

void de_scan_result_t::deserialize(rbusObject_t& ob)
{
    rbusValue_t value;
    const char *ptr;

    if ((value = rbusObject_GetValue(ob, "TimeStamp")) == NULL) {
        printf("%s:%d: Could not find TimeStamp value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_timestamp, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "AggregateScanDuration")) == NULL) {
        printf("%s:%d: Could not find AggregateScanDuration  value\n", __func__, __LINE__);
    } else {
        m_agg_scan_dur = rbusValue_GetUInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "ScanType")) == NULL) {
        printf("%s:%d: Could not find ScanType  value\n", __func__, __LINE__);
    } else {
        m_scan_type = rbusValue_GetBoolean(value);
    }
}

void de_scan_result_t::serialize(cJSON *ob)
{
    cJSON_AddStringToObject(ob, "TimeStamp", m_timestamp);
    cJSON_AddNumberToObject(ob, "AggregateScanDuration", m_agg_scan_dur);
    cJSON_AddBoolToObject(ob, "ScanType", m_scan_type);
}

void de_scan_result_t::deserialize(cJSON *ob)
{
    cJSON *elem;
    const char *str;

    elem = cJSON_GetObjectItem(ob, "TimeStamp");
    str = cJSON_GetStringValue(elem);
    strncpy(m_timestamp, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "AggregateScanDuration");
    m_agg_scan_dur = cJSON_GetNumberValue(elem);
    
    elem = cJSON_GetObjectItem(ob, "ScanType");
    m_scan_type = cJSON_IsTrue(elem);
}


int de_scan_result_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_scan_result_t::deinit()
{

}

de_scan_result_t::de_scan_result_t()
{

}

de_scan_result_t::~de_scan_result_t()
{

}

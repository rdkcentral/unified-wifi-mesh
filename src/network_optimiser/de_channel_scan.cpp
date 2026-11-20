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
#include "de_channel_scan.h"

void de_channel_scan_t::update(de_channel_scan_t& channel)
{
    m_channel = channel.m_channel;
    strncpy(m_timestamp, channel.m_timestamp, strlen(channel.m_timestamp) + 1);
    m_util = channel.m_util;
    m_noise = channel.m_noise;
    strncpy(m_status, channel.m_status, strlen(channel.m_status) + 1);
}

void de_channel_scan_t::serialize(rbusObject_t& ob)
{
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_channel);
    rbusObject_SetValue(ob, "Channel", value);
    rbusValue_Release(value); 
    
    rbusValue_Init(&value);
    rbusValue_SetString(value, m_timestamp);
    rbusObject_SetValue(ob, "TimeStamp", value);
    rbusValue_Release(value); 
    
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_util);
    rbusObject_SetValue(ob, "Utilization", value);
    rbusValue_Release(value); 
    
    rbusValue_Init(&value);
    rbusValue_SetInt32(value, m_noise);
    rbusObject_SetValue(ob, "Noise", value);
    rbusValue_Release(value); 
    
    rbusValue_Init(&value);
    rbusValue_SetString(value, m_status);
    rbusObject_SetValue(ob, "ScanStatus", value);
    rbusValue_Release(value); 
    
}

void de_channel_scan_t::deserialize(rbusObject_t& ob)
{
    rbusValue_t value;
    const char *ptr;

    if ((value = rbusObject_GetValue(ob, "Channel")) == NULL) {
        printf("%s:%d: Could not find Channel  value\n", __func__, __LINE__);
    } else {
        m_channel = rbusValue_GetUInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "TimeStamp")) == NULL) {
        printf("%s:%d: Could not find TimeStamp value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_timestamp, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "Utilization")) == NULL) {
        printf("%s:%d: Could not find Utilization  value\n", __func__, __LINE__);
    } else {
        m_util = rbusValue_GetUInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "Noise")) == NULL) {
        printf("%s:%d: Could not find Noise  value\n", __func__, __LINE__);
    } else {
        m_noise = rbusValue_GetInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "ScanStatus")) == NULL) {
        printf("%s:%d: Could not find ScanStatus value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_status, ptr, strlen(ptr) + 1);
    }
}

void de_channel_scan_t::serialize(cJSON *ob)
{
    cJSON_AddNumberToObject(ob, "Channel", m_channel);
    cJSON_AddStringToObject(ob, "TimeStamp", m_timestamp);
    cJSON_AddNumberToObject(ob, "Utilization", m_util);
    cJSON_AddNumberToObject(ob, "Noise", m_noise);
    cJSON_AddStringToObject(ob, "ScanStatus", m_status);
}

void de_channel_scan_t::deserialize(cJSON *ob)
{
    cJSON *elem;
    const char *str;

    elem = cJSON_GetObjectItem(ob, "Channel");
    m_channel = cJSON_GetNumberValue(elem);

    elem = cJSON_GetObjectItem(ob, "TimeStamp");
    str = cJSON_GetStringValue(elem);
    strncpy(m_timestamp, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "Utilization");
    m_util = cJSON_GetNumberValue(elem);

    elem = cJSON_GetObjectItem(ob, "Noise");
    m_noise = cJSON_GetNumberValue(elem);

    elem = cJSON_GetObjectItem(ob, "ScanStatus");
    str = cJSON_GetStringValue(elem);
    strncpy(m_status, str, strlen(str) + 1);

}


int de_channel_scan_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_channel_scan_t::deinit()
{

}

de_channel_scan_t::de_channel_scan_t()
{

}

de_channel_scan_t::~de_channel_scan_t()
{

}

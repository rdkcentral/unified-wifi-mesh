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
#include "de_assoc_event.h"

void de_assoc_event_t::update(de_assoc_event_t& assoc)
{
    strncpy(m_timestamp, assoc.m_timestamp, strlen(assoc.m_timestamp) + 1);
    strncpy(m_bssid, assoc.m_bssid, strlen(assoc.m_bssid) + 1);
    strncpy(m_mac, assoc.m_mac, strlen(assoc.m_mac) + 1);
    m_status_code = assoc.m_status_code;

    strncpy(m_ht_cap, assoc.m_ht_cap, strlen(assoc.m_ht_cap) + 1);
    strncpy(m_vht_cap, assoc.m_vht_cap, strlen(assoc.m_vht_cap) + 1);
    strncpy(m_he_cap, assoc.m_he_cap, strlen(assoc.m_he_cap) + 1);
    strncpy(m_cap, assoc.m_cap, strlen(assoc.m_cap) + 1);
    m_opclass = assoc.m_opclass;
    m_channel = assoc.m_channel;
    strncpy(m_cap, assoc.m_cap, strlen(assoc.m_cap) + 1);
    
    //strncpy(m_wifi6_cap, assoc.m_wifi6_cap, strlen(assoc.m_wifi6_cap) + 1);
}

void de_assoc_event_t::serialize(rbusObject_t& ob)
{
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_timestamp);
    rbusObject_SetValue(ob, "Timestamp", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_bssid);
    rbusObject_SetValue(ob, "BSSID", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_mac);
    rbusObject_SetValue(ob, "MACAddress", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_status_code);
    rbusObject_SetValue(ob, "StatusCode", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_ht_cap);
    rbusObject_SetValue(ob, "HTCapabilities", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_vht_cap);
    rbusObject_SetValue(ob, "VHTCapabilities", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_he_cap);
    rbusObject_SetValue(ob, "HECapabilities", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_Init(&value);
    rbusValue_SetString(value, m_cap);
    rbusObject_SetValue(ob, "ClientCapabilities", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_opclass);
    rbusObject_SetValue(ob, "OpClass", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_channel);
    rbusObject_SetValue(ob, "Channel", value);
    rbusValue_Release(value);

    //rbusValue_Init(&value);
    //rbusValue_SetString(value, m_wifi6_cap);
    //rbusObject_SetValue(ob, "WiFi6Capabilities", value);
    //rbusValue_Release(value);

}

void de_assoc_event_t::deserialize(rbusObject_t& ob)
{
    rbusValue_t value;
    const char *ptr;

    if ((value = rbusObject_GetValue(ob, "Timestamp")) == NULL) {
        printf("%s:%d: Could not find Timestamp value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_timestamp, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "BSSID")) == NULL) {
        printf("%s:%d: Could not find BSSID value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_bssid, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "MACAddress")) == NULL) {
        printf("%s:%d: Could not find mac address value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_mac, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "StatusCode")) == NULL) {
       printf("%s:%d: Could not find StatusCode value\n", __func__, __LINE__);
    } else {
       m_status_code = rbusValue_GetUInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "HTCapabilities")) == NULL) {
        printf("%s:%d: Could not find HT Capabilities value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_ht_cap, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "VHTCapabilities")) == NULL) {
        printf("%s:%d: Could not find VHT Capabilities value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_vht_cap, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "HECapabilities")) == NULL) {
        printf("%s:%d: Could not find HE Capabilities value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_he_cap, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "ClientCapabilities")) == NULL) {
        printf("%s:%d: Could not find Capabilities value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_cap, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "OpClass")) == NULL) {
       printf("%s:%d: Could not find OpClass value\n", __func__, __LINE__);
    } else {
       m_opclass = rbusValue_GetUInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "Channel")) == NULL) {
       printf("%s:%d: Could not find Channel value\n", __func__, __LINE__);
    } else {
       m_channel = rbusValue_GetUInt32(value);
    }

    //if ((value = rbusObject_GetValue(ob, "WiFi6Capabilities")) == NULL) {
    //    printf("%s:%d: Could not find WiFi6 Capabilities value\n", __func__, __LINE__);
    //} else {
    //    ptr = rbusValue_GetString(value, NULL);
    //    strncpy(m_wifi6_cap, ptr, strlen(ptr) + 1);
    //}

}

void de_assoc_event_t::serialize(cJSON *ob)
{

    cJSON_AddStringToObject(ob, "Timestamp", m_timestamp);
    cJSON_AddStringToObject(ob, "BSSID", m_bssid);
    cJSON_AddStringToObject(ob, "MACAddress", m_mac);
    cJSON_AddNumberToObject(ob, "StatusCode", m_status_code);
    cJSON_AddStringToObject(ob, "HTCapabilities", m_ht_cap);
    cJSON_AddStringToObject(ob, "VHTCapabilities", m_vht_cap);
    cJSON_AddStringToObject(ob, "HECapabilities", m_he_cap);
    cJSON_AddStringToObject(ob, "ClientCapabilities", m_cap);
    cJSON_AddNumberToObject(ob, "OpClass", m_opclass);
    cJSON_AddNumberToObject(ob, "Channel", m_channel);
    //cJSON_AddStringToObject(ob, "WiFi6Capabilities", m_wifi6_cap);
}

void de_assoc_event_t::deserialize(cJSON *ob)
{
    cJSON *elem;
    const char *str;

    elem = cJSON_GetObjectItem(ob, "Timestamp");
    str = cJSON_GetStringValue(elem);
    snprintf(m_timestamp, sizeof(m_timestamp), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(ob, "BSSID");
    str = cJSON_GetStringValue(elem);
    snprintf(m_bssid, sizeof(m_bssid), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(ob, "MACAddress");
    str = cJSON_GetStringValue(elem);
    snprintf(m_mac, sizeof(m_mac), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(ob, "StatusCode");
    m_status_code = static_cast<int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(ob, "HTCapabilities");
    str = cJSON_GetStringValue(elem);
    snprintf(m_ht_cap, sizeof(m_ht_cap), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(ob, "VHTCapabilities");
    str = cJSON_GetStringValue(elem);
    snprintf(m_vht_cap, sizeof(m_vht_cap), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(ob, "HECapabilities");
    str = cJSON_GetStringValue(elem);
    snprintf(m_he_cap, sizeof(m_he_cap), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(ob, "ClientCapabilities");
    str = cJSON_GetStringValue(elem);
    snprintf(m_cap, sizeof(m_cap), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(ob, "OpClass");
    m_opclass = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(ob, "Channel");
    m_channel = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    //elem = cJSON_GetObjectItem(ob, "WiFi6Capabilities");
    //str = cJSON_GetStringValue(elem);
    //strncpy(m_wifi6_cap, str, strlen(str) + 1);

}

int de_assoc_event_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_assoc_event_t::deinit()
{

}

de_assoc_event_t::de_assoc_event_t()
{
    memset(m_key, 0, sizeof(m_key));
    memset(m_timestamp, 0, sizeof(m_timestamp));
    memset(m_bssid, 0, sizeof(m_bssid));
    memset(m_mac, 0, sizeof(m_mac));
    m_status_code = 0;
    memset(m_ht_cap, 0, sizeof(m_ht_cap));
    memset(m_vht_cap, 0, sizeof(m_vht_cap));
    memset(m_he_cap, 0, sizeof(m_he_cap));
    memset(m_cap, 0, sizeof(m_cap));
    m_opclass = 0;  
    m_channel = 0;
}

de_assoc_event_t::~de_assoc_event_t()
{

}

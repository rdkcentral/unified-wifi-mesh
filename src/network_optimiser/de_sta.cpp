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
#include "de_sta.h"

void de_sta_t::update(de_sta_t& sta)
{
    strncpy(m_mac, sta.m_mac, strlen(sta.m_mac) + 1);
    m_rssi = sta.m_rssi;
    m_ul_rate = sta.m_ul_rate;
    m_dl_rate = sta.m_dl_rate;
    m_retrans = sta.m_retrans;
    m_pkts_rx = sta.m_pkts_rx;
    m_pkts_tx = sta.m_pkts_tx;
    m_bytes_rx = sta.m_bytes_rx;
    m_bytes_tx = sta.m_bytes_tx;
    strncpy(m_cap, sta.m_cap, strlen(sta.m_cap) + 1);
    //strncpy(m_wifi6_cap, sta.m_wifi6_cap, strlen(sta.m_wifi6_cap) + 1);
    strncpy(m_ht_cap, sta.m_ht_cap, strlen(sta.m_ht_cap) + 1);
    strncpy(m_vht_cap, sta.m_vht_cap, strlen(sta.m_vht_cap) + 1);
    strncpy(m_he_cap, sta.m_he_cap, strlen(sta.m_he_cap) + 1);
    strncpy(m_sec_assoc, sta.m_sec_assoc, strlen(sta.m_sec_assoc) + 1);
}

void de_sta_t::serialize(rbusObject_t& ob)
{

}

void de_sta_t::deserialize(rbusObject_t& ob)
{

}

void de_sta_t::serialize(cJSON *ob)
{

    cJSON_AddStringToObject(ob, "MACAddress", m_mac);
    cJSON_AddNumberToObject(ob, "SignalStrength", m_rssi);
    cJSON_AddNumberToObject(ob, "LastDataUplinkRate", m_ul_rate);
    cJSON_AddNumberToObject(ob, "LastDataDownlinkRate", m_dl_rate);
    cJSON_AddNumberToObject(ob, "RetransCount", m_retrans);
    cJSON_AddNumberToObject(ob, "PacketsReceived", m_pkts_rx);
    cJSON_AddNumberToObject(ob, "PacketsSent", m_pkts_tx);
    cJSON_AddNumberToObject(ob, "BytesReceived", m_bytes_rx);
    cJSON_AddNumberToObject(ob, "BytesSent", m_bytes_tx);
    cJSON_AddStringToObject(ob, "ClientCapabilities", m_cap);
    //cJSON_AddStringToObject(ob, "WiFi6Capabilities", m_wifi6_cap);
    cJSON_AddStringToObject(ob, "HTCapabilities", m_ht_cap);
    cJSON_AddStringToObject(ob, "VHTCapabilities", m_vht_cap);
    cJSON_AddStringToObject(ob, "HECapabilities", m_he_cap);
    cJSON_AddStringToObject(ob, "SecurityAssociation", m_sec_assoc);

}

void de_sta_t::deserialize(cJSON *ob)
{
    cJSON *elem;
    const char *str;

    elem = cJSON_GetObjectItem(ob, "MACAddress");
    str = cJSON_GetStringValue(elem);
    snprintf(m_mac, sizeof(m_mac), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(ob, "SignalStrength");
    m_rssi = static_cast<int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(ob, "LastDataUplinkRate");
    m_ul_rate = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(ob, "LastDataDownlinkRate");
    m_dl_rate = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(ob, "RetransCount");
    m_retrans = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(ob, "PacketsReceived");
    m_pkts_rx = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(ob, "PacketsSent");
    m_pkts_tx = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(ob, "BytesReceived");
    m_bytes_rx = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(ob, "BytesSent");
    m_bytes_tx = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(ob, "ClientCapabilities");
    str = cJSON_GetStringValue(elem);
    snprintf(m_cap, sizeof(m_cap), "%s", (str != NULL) ? str : "");

    //elem = cJSON_GetObjectItem(ob, "WiFi6Capabilities");
    //str = cJSON_GetStringValue(elem);
    //strncpy(m_wifi6_cap, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "HTCapabilities");
    str = cJSON_GetStringValue(elem);
    snprintf(m_ht_cap, sizeof(m_ht_cap), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(ob, "VHTCapabilities");
    str = cJSON_GetStringValue(elem);
    snprintf(m_vht_cap, sizeof(m_vht_cap), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(ob, "HECapabilities");
    str = cJSON_GetStringValue(elem);
    snprintf(m_he_cap, sizeof(m_he_cap), "%s", (str != NULL) ? str : "");

    elem = cJSON_GetObjectItem(ob, "SecurityAssociation");
    str = cJSON_GetStringValue(elem);
    snprintf(m_sec_assoc, sizeof(m_sec_assoc), "%s", (str != NULL) ? str : "");
}

int de_sta_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_sta_t::deinit()
{

}

de_sta_t::de_sta_t()
{
    memset(m_key, 0, sizeof(m_key));
    memset(m_mac, 0, sizeof(m_mac));
    m_rssi = 0;
    m_ul_rate = 0;
    m_dl_rate = 0;
    m_retrans = 0;
    m_pkts_rx = 0;
    m_pkts_tx = 0;
    m_bytes_rx = 0;
    m_bytes_tx = 0;
    memset(m_cap, 0, sizeof(m_cap));
    memset(m_ht_cap, 0, sizeof(m_ht_cap));
    memset(m_vht_cap, 0, sizeof(m_vht_cap));
    memset(m_he_cap, 0, sizeof(m_he_cap));
    memset(m_sec_assoc, 0, sizeof(m_sec_assoc));
}

de_sta_t::~de_sta_t()
{

}

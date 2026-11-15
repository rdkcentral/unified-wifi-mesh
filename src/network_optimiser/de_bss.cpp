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
#include "de_bss.h"

void de_bss_t::update(de_bss_t& bss)
{
    strncpy(m_bssid, bss.m_bssid, strlen(bss.m_bssid) + 1);
    strncpy(m_ssid, bss.m_ssid, strlen(bss.m_ssid) + 1);
    m_enabled = bss.m_enabled;
    m_broadcast = bss.m_broadcast;
    m_fronthaul = bss.m_fronthaul;
    m_backhaul = bss.m_backhaul;
}

void de_bss_t::serialize(rbusObject_t& ob)
{

}

void de_bss_t::deserialize(rbusObject_t& ob)
{

}

void de_bss_t::serialize(cJSON *ob)
{
    cJSON_AddStringToObject(ob, "BSSID", m_bssid);
    cJSON_AddStringToObject(ob, "SSID", m_ssid);
    cJSON_AddBoolToObject(ob, "Enabled", m_enabled);
    cJSON_AddBoolToObject(ob, "TransmittedBSSID", m_broadcast);
    cJSON_AddBoolToObject(ob, "FronthaulUse", m_fronthaul);
    cJSON_AddBoolToObject(ob, "BackhaulUse", m_backhaul);
}

void de_bss_t::deserialize(cJSON *ob)
{
    cJSON *elem;
    const char *str;

    elem = cJSON_GetObjectItem(ob, "BSSID");
    str = cJSON_GetStringValue(elem);
    strncpy(m_bssid, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "SSID");
    str = cJSON_GetStringValue(elem);
    strncpy(m_ssid, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "Enabled");
    m_enabled = cJSON_IsTrue(elem);

    elem = cJSON_GetObjectItem(ob, "TransmittedBSSID");
    m_broadcast = cJSON_IsTrue(elem);

    elem = cJSON_GetObjectItem(ob, "FronthaulUse");
    m_fronthaul = cJSON_IsTrue(elem);

    elem = cJSON_GetObjectItem(ob, "BackhaulUse");
    m_backhaul = cJSON_IsTrue(elem);

}


int de_bss_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_bss_t::deinit()
{

}

de_bss_t::de_bss_t()
{
    m_enabled = false;
    m_broadcast = true;
    m_fronthaul = true;
    m_backhaul = false;
}

de_bss_t::~de_bss_t()
{

}

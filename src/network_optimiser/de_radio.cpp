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
#include "de_radio.h"

void de_radio_t::update(de_radio_t& radio)
{
    strncpy(m_id, radio.m_id, strlen(radio.m_id) + 1);
    m_enabled = radio.m_enabled;
    m_util = radio.m_util;
    m_noise = radio.m_noise;
}

void de_radio_t::serialize(rbusObject_t& ob)
{
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_id);
    rbusObject_SetValue(ob, "ID", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, m_enabled);
    rbusObject_SetValue(ob, "Enabled", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_util);
    rbusObject_SetValue(ob, "Utilization", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetInt32(value, m_noise);
    rbusObject_SetValue(ob, "Noise", value);
    rbusValue_Release(value);
}

void de_radio_t::deserialize(rbusObject_t& ob)
{
    rbusValue_t value;
    const char *ptr;

    if ((value = rbusObject_GetValue(ob, "ID")) == NULL) {
        printf("%s:%d: Could not find Type value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_id, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "Enabled")) == NULL) {
        printf("%s:%d: Could not find Operator value\n", __func__, __LINE__);
    } else {
       m_enabled = rbusValue_GetBoolean(value);
    }

    if ((value = rbusObject_GetValue(ob, "Utilization")) == NULL) {
        printf("%s:%d: Could not find Utilization value\n", __func__, __LINE__);
    } else {
        m_util = rbusValue_GetUInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "Noise")) == NULL) {
       printf("%s:%d: Could not find Noise value\n", __func__, __LINE__);
    } else {
       m_noise = rbusValue_GetInt32(value);
    }

}

void de_radio_t::serialize(cJSON *ob)
{
    cJSON_AddStringToObject(ob, "ID", m_id);
    cJSON_AddBoolToObject(ob, "Enabled", m_enabled);
    cJSON_AddNumberToObject(ob, "Utilization", static_cast<double>(m_util));
    cJSON_AddNumberToObject(ob, "Noise", static_cast<double>(m_noise));
}

void de_radio_t::deserialize(cJSON *ob)
{   
    cJSON *elem;
    const char *str;

    elem = cJSON_GetObjectItem(ob, "ID");
    str = cJSON_GetStringValue(elem);
    strncpy(m_id, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "Enabled");
    m_enabled = cJSON_IsTrue(elem);

    elem = cJSON_GetObjectItem(ob, "Utilization");
    m_util = static_cast<unsigned int>(cJSON_GetNumberValue(elem));

    elem = cJSON_GetObjectItem(ob, "Noise");
    m_noise = static_cast<int>(cJSON_GetNumberValue(elem));

}


int de_radio_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_radio_t::deinit()
{

}

de_radio_t::de_radio_t()
{
    m_noise = 0;
    m_util = 0;
    m_enabled = false;
}

de_radio_t::~de_radio_t()
{

}

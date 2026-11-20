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
#include "de_op_class_scan.h"

void de_op_class_scan_t::update(de_op_class_scan_t& op_class)
{
    m_op_class = op_class.m_op_class;
}

void de_op_class_scan_t::serialize(rbusObject_t& ob)
{
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_op_class);
    rbusObject_SetValue(ob, "OperatingClass", value);
    rbusValue_Release(value);

}

void de_op_class_scan_t::deserialize(rbusObject_t& ob)
{
    rbusValue_t value;

    if ((value = rbusObject_GetValue(ob, "OperatingClass")) == NULL) {
        printf("%s:%d: Could not find OperatingClass  value\n", __func__, __LINE__);
    } else {
        m_op_class = rbusValue_GetUInt32(value);
    }
}

void de_op_class_scan_t::serialize(cJSON *ob)
{
    cJSON_AddNumberToObject(ob, "OperatingClass", m_op_class);
}

void de_op_class_scan_t::deserialize(cJSON *ob)
{
    cJSON *elem;

    elem = cJSON_GetObjectItem(ob, "Channel");
    m_op_class = cJSON_GetNumberValue(elem);
}

int de_op_class_scan_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_op_class_scan_t::deinit()
{

}

de_op_class_scan_t::de_op_class_scan_t()
{

}

de_op_class_scan_t::~de_op_class_scan_t()
{

}

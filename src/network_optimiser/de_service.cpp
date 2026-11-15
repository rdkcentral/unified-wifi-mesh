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
#include "de_service.h"

void de_service_t::update(de_service_t& svc)
{
    strncpy(m_type, svc.m_type, strlen(svc.m_type) + 1);
    strncpy(m_access, svc.m_access, strlen(svc.m_access) + 1);
    strncpy(m_url, svc.m_url, strlen(svc.m_url) + 1);
}

void de_service_t::serialize(rbusObject_t& ob)
{

}

void de_service_t::deserialize(rbusObject_t& ob)
{

}

void de_service_t::serialize(cJSON *ob)
{
    cJSON_AddStringToObject(ob, "Type", m_type);
    cJSON_AddStringToObject(ob, "Operator", m_access);
    cJSON_AddStringToObject(ob, "URL", m_url);
}

void de_service_t::deserialize(cJSON *ob)
{
    cJSON *elem;
    const char *str;

    elem = cJSON_GetObjectItem(ob, "Type");
    str = cJSON_GetStringValue(elem);
    strncpy(m_type, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "Access");
    str = cJSON_GetStringValue(elem);
    strncpy(m_access, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "URL");
    str = cJSON_GetStringValue(elem);
    strncpy(m_url, str, strlen(str) + 1);

}


int de_service_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_service_t::deinit()
{

}

de_service_t::de_service_t()
{
    memset(m_type, 0, sizeof(service_type_t));
    memset(m_access, 0, sizeof(access_type_t));
    memset(m_url, 0, sizeof(m_url));
    memset(m_key, 0, sizeof(m_key));
}

de_service_t::~de_service_t()
{

}

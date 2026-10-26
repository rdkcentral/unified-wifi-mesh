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
    m_type = svc.m_type;
    strncpy(m_operator_name, svc.m_operator_name, strlen(svc.m_operator_name) + 1);
    strncpy(m_url, svc.m_url, strlen(svc.m_url) + 1);
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
    m_type = service_type_unknown;
    memset(m_operator_name, 0, sizeof(m_operator_name));
    memset(m_url, 0, sizeof(m_url));
    memset(m_key, 0, sizeof(m_key));
}

de_service_t::~de_service_t()
{

}

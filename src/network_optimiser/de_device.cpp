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
#include "de_device.h"

void de_device_t::update(de_device_t& dev)
{
    strncpy(m_id, dev.m_id, strlen(dev.m_id) + 1);
    strncpy(m_manufacturer, dev.m_manufacturer, strlen(dev.m_manufacturer) + 1);
    strncpy(m_model, dev.m_model, strlen(dev.m_model) + 1);
    strncpy(m_serial, dev.m_serial, strlen(dev.m_serial) + 1);
    strncpy(m_version, dev.m_version, strlen(dev.m_version) + 1);
}

int de_device_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_device_t::deinit()
{

}

de_device_t::de_device_t()
{
    memset(m_key, 0, sizeof(m_key));
    memset(m_id, 0, sizeof(m_id));
    memset(m_manufacturer, 0, sizeof(m_manufacturer));
    memset(m_model, 0, sizeof(m_model));
    memset(m_serial, 0, sizeof(m_serial));
    memset(m_version, 0, sizeof(m_version));
}

de_device_t::~de_device_t()
{

}

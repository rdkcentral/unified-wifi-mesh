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

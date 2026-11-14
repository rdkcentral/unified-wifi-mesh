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

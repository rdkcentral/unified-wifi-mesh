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
#include "de_net_ssid.h"

void de_net_ssid_t::update(de_net_ssid_t& net_ssid)
{
    strncpy(m_ssid, net_ssid.m_ssid, strlen(net_ssid.m_ssid) + 1);
    m_enabled = net_ssid.m_enabled;
    strncpy(m_op, net_ssid.m_op, strlen(net_ssid.m_op) + 1);
    m_advertisement = net_ssid.m_advertisement;
    strncpy(m_mfp_config, net_ssid.m_mfp_config, strlen(net_ssid.m_mfp_config) + 1);
    strncpy(m_mob_domain, net_ssid.m_mob_domain, strlen(net_ssid.m_mob_domain) + 1);
}

int de_net_ssid_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_net_ssid_t::deinit()
{

}

de_net_ssid_t::de_net_ssid_t()
{
    memset(m_key, 0, sizeof(m_key));
    memset(m_ssid, 0, sizeof(m_ssid));
    memset(m_op, 0, sizeof(m_op));
    m_enabled = false;
    m_advertisement = false;
    memset(m_mfp_config, 0, sizeof(m_mfp_config));
    memset(m_mob_domain, 0, sizeof(m_mob_domain));
}

de_net_ssid_t::~de_net_ssid_t()
{

}

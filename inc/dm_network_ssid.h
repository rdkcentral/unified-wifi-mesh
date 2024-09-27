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

#ifndef DM_NETWORK_SSID_H
#define DM_NETWORK_SSID_H

#include "em_base.h"

class dm_network_ssid_t {
public:
    em_network_ssid_info_t    m_network_ssid_info;

public:
    int init() { memset(&m_network_ssid_info, 0, sizeof(em_network_ssid_info_t)); return 0; }
    em_network_ssid_info_t *get_network_ssid_info() { return &m_network_ssid_info; }
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj);

    bool operator == (const dm_network_ssid_t& obj);
    void operator = (const dm_network_ssid_t& obj);
    dm_network_ssid_t(em_network_ssid_info_t *net_ssid);
    dm_network_ssid_t(const dm_network_ssid_t& net_ssid);
    dm_network_ssid_t();
    ~dm_network_ssid_t();
};

#endif

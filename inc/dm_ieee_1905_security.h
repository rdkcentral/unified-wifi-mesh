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

#ifndef DM_IEEE_1905_SECURITY_H
#define DM_IEEE_1905_SECURITY_H

#include "em_base.h"
#include "db_easy_mesh.h"

class dm_ieee_1905_security_t {
public:
    em_ieee_1905_security_info_t    m_ieee_1905_security_info;

public:
    int init() { memset(&m_ieee_1905_security_info, 0, sizeof(em_ieee_1905_security_info_t)); return 0; }

    em_ieee_1905_security_info_t *get_ieee_1905_security_info() { return &m_ieee_1905_security_info; }
    em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() { return &m_ieee_1905_security_info.sec_cap; }

    bool operator == (const dm_ieee_1905_security_t& obj);
    void operator = (const dm_ieee_1905_security_t& obj);
    int decode(const cJSON *obj);
    void encode(cJSON *obj);

    dm_ieee_1905_security_t(em_ieee_1905_security_info_t *net_ssid);
    dm_ieee_1905_security_t(const dm_ieee_1905_security_t& net_ssid);
    dm_ieee_1905_security_t();
    ~dm_ieee_1905_security_t();
};

#endif

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

#ifndef DM_STA_H
#define DM_STA_H

#include "em_base.h"

class dm_sta_t {
public:
    em_sta_info_t    m_sta_info;

public:
    int init() { memset(&m_sta_info, 0, sizeof(em_sta_info_t)); return 0; }
    em_sta_info_t *get_sta_info() { return &m_sta_info; }
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj, bool summary = false);

    bool operator == (const dm_sta_t& obj);
    void operator = (const dm_sta_t& obj);

    static void parse_sta_bss_radio_from_key(const char *key, mac_address_t sta, bssid_t bssid, mac_address_t radio);
    static void decode_sta_capability(dm_sta_t *sta);

    dm_sta_t(em_sta_info_t *sta);
    dm_sta_t(const dm_sta_t& sta);
    dm_sta_t();
    ~dm_sta_t();
};

#endif

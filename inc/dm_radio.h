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

#ifndef DM_RADIO_H
#define DM_RADIO_H

#include "em_base.h"

class dm_radio_t {
public:
    em_radio_info_t    m_radio_info;

public:
    int init() { memset(&m_radio_info, 0, sizeof(em_radio_info_t)); return 0; }
    em_radio_info_t *get_radio_info() { return &m_radio_info; }
    
    em_interface_t  *get_radio_interface() { return &m_radio_info.id; }
    unsigned char   *get_radio_interface_mac() { return m_radio_info.id.mac; }
    char *get_radio_interface_name() { return m_radio_info.id.name; }
    unsigned char *get_radio_id() { return m_radio_info.id.mac; }
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj);

    bool operator == (const dm_radio_t& obj);
    void operator = (const dm_radio_t& obj);
    dm_orch_type_t get_dm_orch_type(const dm_radio_t& radio);

    dm_radio_t(em_radio_info_t *radio);
    dm_radio_t(const dm_radio_t& radio);
    dm_radio_t();
    ~dm_radio_t();
};

#endif

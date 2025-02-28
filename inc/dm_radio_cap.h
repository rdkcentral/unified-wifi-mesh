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

#ifndef DM_RADIO_CAP_H
#define DM_RADIO_CAP_H

#include "em_base.h"

class dm_radio_cap_t {
public:
    em_radio_cap_info_t    m_radio_cap_info;

public:
    int init() { memset(&m_radio_cap_info, 0, sizeof(em_radio_cap_info_t)); return 0; }
    em_radio_cap_info_t *get_radio_cap_info() { return &m_radio_cap_info; }
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj);

    bool operator == (const dm_radio_cap_t& obj);
    void operator = (const dm_radio_cap_t& obj);

    dm_radio_cap_t(em_radio_cap_info_t *radio_cap);
    dm_radio_cap_t(const dm_radio_cap_t& radio_cap);
    dm_radio_cap_t();
    virtual ~dm_radio_cap_t();
};

#endif

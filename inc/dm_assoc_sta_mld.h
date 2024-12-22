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

#ifndef DM_ASSOC_STA_MLD_H
#define DM_ASSOC_STA_MLD_H

#include "em_base.h"

class dm_assoc_sta_mld_t {
public:
    em_assoc_sta_mld_info_t    m_assoc_sta_mld_info;

public:
    int init() { memset(&m_assoc_sta_mld_info, 0, sizeof(em_assoc_sta_mld_info_t)); return 0; }
    em_assoc_sta_mld_info_t *get_ap_mld_info() { return &m_assoc_sta_mld_info; }
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj);

    bool operator == (const dm_assoc_sta_mld_t& obj);
    void operator = (const dm_assoc_sta_mld_t& obj);

    dm_assoc_sta_mld_t(em_assoc_sta_mld_info_t *ap_mld_info);
    dm_assoc_sta_mld_t(const dm_assoc_sta_mld_t& ap_mld);
    dm_assoc_sta_mld_t();
    ~dm_assoc_sta_mld_t();
};

#endif

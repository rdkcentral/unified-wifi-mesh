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

#ifndef DM_CAC_COMP_H
#define DM_CAC_COMP_H

#include "em_base.h"

class dm_cac_comp_t {
public:
    em_cac_comp_info_t    m_cac_comp_info;

public:
    int init() { memset(&m_cac_comp_info, 0, sizeof(em_cac_comp_info_t)); return 0; }
    em_cac_comp_info_t *get_cac_comp_info() { return &m_cac_comp_info; }
    
    unsigned char *get_cac_comp_id() { return m_cac_comp_info.ruid; }
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj);

    bool operator == (const dm_cac_comp_t& obj);
    void operator = (const dm_cac_comp_t& obj);
    dm_orch_type_t get_dm_orch_type(const dm_cac_comp_t& radio);

    dm_cac_comp_t(em_cac_comp_info_t *cac_comp);
    dm_cac_comp_t(const dm_cac_comp_t& cac_comp);
    dm_cac_comp_t();
    ~dm_cac_comp_t();
};

#endif

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

#ifndef DM_TID_TO_LINK_H
#define DM_TID_TO_LINK_H

#include "em_base.h"

class dm_tid_to_link_t {
public:
    em_tid_to_link_info_t    m_tid_to_link_info;

public:
    int init() { memset(&m_tid_to_link_info, 0, sizeof(em_tid_to_link_info_t)); return 0; }
    em_tid_to_link_info_t *get_tid_to_link_info() { return &m_tid_to_link_info; }
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj);

    bool operator == (const dm_tid_to_link_t& obj);
    void operator = (const dm_tid_to_link_t& obj);

    dm_tid_to_link_t(em_tid_to_link_info_t *tid_to_link_info);
    dm_tid_to_link_t(const dm_tid_to_link_t& tid_to_link);
    dm_tid_to_link_t();
    ~dm_tid_to_link_t();
};

#endif

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

#ifndef DM_BSS_H
#define DM_BSS_H

#include "em_base.h"

class dm_bss_t {
public:
    em_bss_info_t    m_bss_info;

public:
    int init() { memset(&m_bss_info, 0, sizeof(em_bss_info_t)); return 0; }
    em_bss_info_t *get_bss_info() { return &m_bss_info; }
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj, bool summary = false);

    bool operator == (const dm_bss_t& obj);
    void operator = (const dm_bss_t& obj);

	bool match_criteria(char *criteria);
	static int parse_bss_id_from_key(const char *key, em_bss_id_t *id);

    dm_bss_t(em_bss_info_t *bss);
    dm_bss_t(const dm_bss_t& bss);
    dm_bss_t();
    virtual ~dm_bss_t();
};

#endif

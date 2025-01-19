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

#ifndef DM_SCAN_RESULT_H
#define DM_SCAN_RESULT_H

#include "em_base.h"

class dm_scan_result_t {
public:
    em_scan_result_t    m_scan_result;

public:
    int init() { memset(&m_scan_result, 0, sizeof(em_scan_result_t)); return 0; }
    em_scan_result_t *get_scan_result() { return &m_scan_result; }
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj, em_scan_result_id_t id);

    bool operator == (const dm_scan_result_t& obj);
    void operator = (const dm_scan_result_t& obj);

	static int parse_scan_result_id_from_key(const char *key, em_scan_result_id_t *id);
	bool has_same_id(em_scan_result_id_t *);

    dm_scan_result_t(em_scan_result_t *scan_result);
    dm_scan_result_t(const dm_scan_result_t& scan_result);
    dm_scan_result_t(const em_scan_result_t& scan_result);
    dm_scan_result_t();
    ~dm_scan_result_t();
};

#endif

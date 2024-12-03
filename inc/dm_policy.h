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

#ifndef DM_POLICY_H
#define DM_POLICY_H

#include "em_base.h"

class dm_policy_t {
public:
    em_policy_t    m_policy;

public:
    int init() { memset(&m_policy, 0, sizeof(em_policy_t)); return 0; }
    em_policy_t *get_policy() { return &m_policy; }
    int decode(const cJSON *obj, void *parent_id, em_policy_id_type_t plicy = em_policy_id_type_unknown);
    void encode(cJSON *obj, em_policy_id_type_t id);

    bool operator == (const dm_policy_t& obj);
    void operator = (const dm_policy_t& obj);

	static int parse_dev_radio_mac_from_key(const char *key, em_policy_id_t *id);

    dm_policy_t(em_policy_t *policy);
    dm_policy_t(const dm_policy_t& policy);
    dm_policy_t(const em_policy_t& policy);
    dm_policy_t();
    ~dm_policy_t();
};

#endif

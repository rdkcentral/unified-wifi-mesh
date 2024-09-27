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

#ifndef DM_DPP_H
#define DM_DPP_H

#include "em_base.h"
#include "ec_base.h"

class em_cmd_t;

class dm_dpp_t {
public:
    em_dpp_info_t    m_dpp_info;

public:
    int init();
    em_dpp_info_t *get_dpp_info() { return &m_dpp_info; }
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj);

    bool operator == (const dm_dpp_t& obj);
    void operator = (const dm_dpp_t& obj);

    int analyze_config(const cJSON *obj, void *parent, em_cmd_t *cmd[], em_cmd_params_t *param);

    dm_dpp_t(em_dpp_info_t *net_ssid);
    dm_dpp_t(const dm_dpp_t& net_ssid);
    dm_dpp_t();
    ~dm_dpp_t();
};

#endif

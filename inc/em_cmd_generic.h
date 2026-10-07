/**
 * Copyright 2025 Comcast Cable Communications Management, LLC
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

#ifndef EM_CMD_GENERIC_H
#define EM_CMD_GENERIC_H

#include <vector>
#include <cstdint>
#include "em_cmd.h"

class em_cmd_generic_t : public em_cmd_t {

public:
    // Raw stats_arg_t[] payload copied from the rbus event.
    std::vector<uint8_t> m_raw_data;

    // Optional hook — private repo registers this (via __attribute__((constructor)))
    // to extract stats_arg_t fields into dm_sta_ext_t before the cmd is submitted.
    // using populate_fn_t = void(*)(em_cmd_generic_t &, dm_easy_mesh_t &);
    // static populate_fn_t s_populate;

    const std::vector<uint8_t> *get_raw_data() const override { return &m_raw_data; }

    em_cmd_generic_t(uint8_t *raw_buff, int len, dm_easy_mesh_t& dm);
};

#endif

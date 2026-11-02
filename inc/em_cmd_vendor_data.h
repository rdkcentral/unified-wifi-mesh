/**
 * Copyright 2026 Comcast Cable Communications Management, LLC
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

#ifndef EM_CMD_VENDOR_DATA_H
#define EM_CMD_VENDOR_DATA_H

#include <vector>
#include <cstdint>
#include "em_cmd.h"

class em_cmd_vendor_data_t : public em_cmd_t {

public:
    // Raw stats_arg_t[] payload copied from the rbus event.
    std::vector<uint8_t> m_raw_data;

    const std::vector<uint8_t> *get_raw_data() const override { return &m_raw_data; }

    em_cmd_vendor_data_t(uint8_t *raw_buff, int len, dm_easy_mesh_t& dm);
};

#endif

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

#ifndef EM_CMD_SET_BH_CFG_H
#define EM_CMD_SET_BH_CFG_H

#include "em_cmd.h"

class em_cmd_set_bh_cfg_t : public em_cmd_t {

public:
    /**!
     * @brief Constructs a backhaul config command.
     *
     * Creates a command with orch descriptors db_cfg + net_ssid_update.
     * Used for both the initial ioprocess call (with the analyzed dm) and
     * bus-event re-triggers (with the global m_data_model).
     *
     * @param[in] param Command parameters from the bus event.
     * @param[in] dm    Data model containing the backhaul SSID config.
     */
    em_cmd_set_bh_cfg_t(em_cmd_params_t param, dm_easy_mesh_t& dm);
};

#endif

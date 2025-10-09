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

#ifndef EM_CMD_DEV_INIT_H
#define EM_CMD_DEV_INIT_H

#include "em_cmd.h"

class em_cmd_dev_init_t : public em_cmd_t {

public:
    
	/**!
	 * @brief Initializes the device with the given parameters and mesh configuration.
	 *
	 * This function sets up the device using the specified command parameters and
	 * the provided easy mesh configuration.
	 *
	 * @param[in] param The command parameters required for device initialization.
	 * @param[in,out] dm The easy mesh configuration to be used for initialization.
	 *                   This parameter is modified during the initialization process.
	 * @param[in] do_connect_bsta Boolean flag indicating whether to connect the bSTA 
	 * 							  to the backhaul BSS on dev init
	 *
	 * @returns em_cmd_dev_init_t
	 * @retval SUCCESS if the device is initialized successfully.
	 * @retval FAILURE if the initialization fails due to invalid parameters or
	 *                 configuration issues.
	 *
	 * @note Ensure that the device is in a proper state before calling this function.
	 */
	em_cmd_dev_init_t(em_cmd_params_t param, dm_easy_mesh_t& dm, bool do_connect_bsta);
};

#endif

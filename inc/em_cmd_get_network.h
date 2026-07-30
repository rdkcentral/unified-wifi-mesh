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

#ifndef EM_CMD_GET_NETWORK_H
#define EM_CMD_GET_NETWORK_H

#include "em_cmd.h"

class em_cmd_get_network_t : public em_cmd_t {

public:
    
	/**!
	 * @brief Retrieves the network configuration based on the provided parameters.
	 *
	 * This function is responsible for obtaining the network settings using the
	 * specified command parameters and updating the easy mesh structure.
	 *
	 * @param[in] param The command parameters used to specify the network settings.
	 * @param[out] dm The easy mesh structure that will be updated with the network configuration.
	 *
	 * @returns em_cmd_get_network_t The result of the network retrieval operation.
	 *
	 * @note Ensure that the command parameters are correctly initialized before
	 * calling this function to avoid unexpected behavior.
	 */
	em_cmd_get_network_t(em_cmd_params_t param, dm_easy_mesh_t& dm);
};

#endif

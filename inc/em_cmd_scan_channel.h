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

#ifndef EM_CMD_SCAN_CHANNEL_H
#define EM_CMD_SCAN_CHANNEL_H

#include "em_cmd.h"

class em_cmd_scan_channel_t : public em_cmd_t {

public:
    
	/**!
	 * @brief Initiates a scan on the specified channel using the provided parameters.
	 *
	 * This function is responsible for scanning a channel based on the parameters
	 * provided in `em_cmd_params_t` and updates the `dm_easy_mesh_t` structure.
	 *
	 * @param[in] param The parameters for the scan operation.
	 * @param[out] dm The easy mesh structure to be updated with scan results.
	 *
	 * @returns em_cmd_scan_channel_t The result of the scan operation.
	 *
	 * @note Ensure that the `dm` structure is properly initialized before calling
	 * this function.
	 */
	em_cmd_scan_channel_t(em_cmd_params_t param, dm_easy_mesh_t& dm);
};

#endif

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

#ifndef EM_CMD_START_DPP_H
#define EM_CMD_START_DPP_H

#include "em_cmd.h"

class em_cmd_start_dpp_t : public em_cmd_t {

public:
    
	/**!
	 * @brief Starts the DPP command with the given parameters.
	 *
	 * This function initiates the DPP (Device Provisioning Protocol) command using the specified parameters.
	 *
	 * @param[in] param The parameters required to start the DPP command.
	 *
	 * @returns em_cmd_start_dpp_t The result of the DPP command initiation.
	 *
	 * @note Ensure that the parameters provided are valid and conform to the expected format for successful execution.
	 */
	em_cmd_start_dpp_t(em_cmd_params_t param);
};

#endif

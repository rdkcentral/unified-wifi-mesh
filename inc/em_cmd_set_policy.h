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

#ifndef EM_CMD_SET_POLICY_H
#define EM_CMD_SET_POLICY_H

#include "em_cmd.h"

class em_cmd_set_policy_t : public em_cmd_t {

public:
    
	/**!
	 * @brief Sets the policy for the EasyMesh device.
	 *
	 * This function configures the policy settings for the EasyMesh device using the provided parameters.
	 *
	 * @param[in] param The command parameters used to set the policy.
	 * @param[in,out] dm Reference to the EasyMesh device configuration.
	 *
	 * @returns em_cmd_set_policy_t The result of the policy setting operation.
	 * @retval SUCCESS if the policy was set successfully.
	 * @retval FAILURE if there was an error setting the policy.
	 *
	 * @note Ensure that the EasyMesh device is initialized before calling this function.
	 */
	em_cmd_set_policy_t(em_cmd_params_t param, dm_easy_mesh_t& dm);
};

#endif

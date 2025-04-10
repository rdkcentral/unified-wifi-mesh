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

#ifndef EM_CMD_SET_CHANNEL_H
#define EM_CMD_SET_CHANNEL_H

#include "em_cmd.h"

class em_cmd_set_channel_t : public em_cmd_t {

public:
    
	/**!
	 * @brief Sets the channel for the EasyMesh device.
	 *
	 * This function configures the channel settings for the specified EasyMesh device using the provided parameters.
	 *
	 * @param[in] param The command parameters required for setting the channel.
	 * @param[in,out] dm Reference to the EasyMesh device structure that will be updated with the new channel settings.
	 *
	 * @returns em_cmd_set_channel_t
	 * @retval Success or failure status of the channel setting operation.
	 *
	 * @note Ensure that the device is in a state that allows channel configuration before calling this function.
	 */
	em_cmd_set_channel_t(em_cmd_params_t param, dm_easy_mesh_t& dm);
};

#endif

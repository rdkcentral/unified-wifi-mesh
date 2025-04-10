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

#ifndef EM_CMD_REMOVE_DEVICE_H
#define EM_CMD_REMOVE_DEVICE_H

#include "em_cmd.h"

class em_cmd_remove_device_t : public em_cmd_t {

public:
	
	/**!
	 * @brief Removes a device from the EasyMesh network.
	 *
	 * This function is responsible for removing a specified device from the EasyMesh network using the provided parameters.
	 *
	 * @param[in] param The command parameters required for device removal.
	 * @param[in,out] dm The EasyMesh network context from which the device will be removed.
	 *
	 * @returns em_cmd_remove_device_t
	 * @retval true if the device was successfully removed.
	 * @retval false if the device removal failed.
	 *
	 * @note Ensure that the device is part of the network before attempting removal.
	 */
	em_cmd_remove_device_t(em_cmd_params_t param, dm_easy_mesh_t& dm);
};

#endif

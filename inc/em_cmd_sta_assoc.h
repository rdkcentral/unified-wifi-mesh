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

#ifndef EM_CMD_STA_ASSOC_H
#define EM_CMD_STA_ASSOC_H

#include "em_cmd.h"

class em_cmd_sta_assoc_t : public em_cmd_t {

public:
    
	/**!
	 * @brief Associates a station with the given parameters and mesh configuration.
	 *
	 * This function handles the association of a station using the specified command parameters and mesh configuration.
	 *
	 * @param[in] param The command parameters required for station association.
	 * @param[in,out] dm The easy mesh configuration to be used for association.
	 *
	 * @returns em_cmd_sta_assoc_t The result of the association command.
	 *
	 * @note Ensure that the mesh configuration is properly initialized before calling this function.
	 */
	em_cmd_sta_assoc_t(em_cmd_params_t param, dm_easy_mesh_t& dm);
};

#endif

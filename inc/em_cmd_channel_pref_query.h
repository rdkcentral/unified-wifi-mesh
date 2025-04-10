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

#ifndef EM_CMD_CHANNEL_PREF_QUERY_H
#define EM_CMD_CHANNEL_PREF_QUERY_H

#include "em_cmd.h"

class em_cmd_channel_pref_query_t : public em_cmd_t {

public:
    
	/**!
	 * @brief Queries the channel preference for a given service type and command parameters.
	 *
	 * This function interacts with the EasyMesh data model to retrieve channel preferences.
	 *
	 * @param[in] service The type of service for which the channel preference is queried.
	 * @param[in] param The command parameters associated with the query.
	 * @param[out] dm The EasyMesh data model reference where the channel preference will be stored.
	 *
	 * @returns em_cmd_channel_pref_query_t The result of the channel preference query.
	 *
	 * @note Ensure that the EasyMesh data model is properly initialized before calling this function.
	 */
	em_cmd_channel_pref_query_t(em_service_type_t service, em_cmd_params_t param, dm_easy_mesh_t& dm);
};

#endif

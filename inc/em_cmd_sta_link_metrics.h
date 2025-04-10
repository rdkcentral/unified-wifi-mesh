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

#ifndef EM_CMD_STA_LINK_METRICS_H
#define EM_CMD_STA_LINK_METRICS_H

#include "em_cmd.h"

class em_cmd_sta_link_metrics_t : public em_cmd_t {

public:
    
	/**!
	 * @brief Constructor for the em_cmd_sta_link_metrics_t class.
	 *
	 * This constructor initializes the em_cmd_sta_link_metrics_t object.
	 *
	 * @note This is a default constructor and does not take any parameters.
	 */
	em_cmd_sta_link_metrics_t(dm_easy_mesh_t& dm);
};

#endif

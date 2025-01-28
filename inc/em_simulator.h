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

#ifndef EM_SIMULATOR_H
#define EM_SIMULATOR_H

#include "em_base.h"
#include "dm_easy_mesh_agent.h"

class em_simulator_t {
	em_cmd_params_t	m_param;
	bool	m_can_run_scan_res;

	int find_matching_scan_result_index(dm_easy_mesh_agent_t& dm, unsigned char *mac, unsigned int op_class, unsigned int channel);

public:
	em_cmd_params_t *get_cmd_param() { return &m_param; }
	bool run(dm_easy_mesh_agent_t& dm);
	void configure(dm_easy_mesh_agent_t& dm, em_scan_params_t *params);

public:
    em_simulator_t();
    ~em_simulator_t();
};

#endif

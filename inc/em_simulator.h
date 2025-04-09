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

public:
	
	/**!
	 * @brief Retrieves the command parameters.
	 *
	 * This function returns a pointer to the command parameters structure.
	 *
	 * @returns A pointer to the em_cmd_params_t structure containing the command parameters.
	 *
	 * @note Ensure that the returned pointer is not modified directly.
	 */
	em_cmd_params_t *get_cmd_param() { return &m_param; }
	
	/**!
	 * @brief Runs the easy mesh agent.
	 *
	 * This function initiates the operation of the easy mesh agent using the provided
	 * `dm_easy_mesh_agent_t` structure.
	 *
	 * @param[in] dm Reference to a `dm_easy_mesh_agent_t` structure that contains
	 * the configuration and state information for the easy mesh agent.
	 *
	 * @returns True if the agent runs successfully, false otherwise.
	 *
	 * @note Ensure that the `dm` structure is properly initialized before calling
	 * this function.
	 */
	bool run(dm_easy_mesh_agent_t& dm);
	
	/**!
	 * @brief Configures the Easy Mesh agent with the given scan parameters.
	 *
	 * This function sets up the Easy Mesh agent using the provided scan parameters.
	 *
	 * @param[in] dm Reference to the Easy Mesh agent to be configured.
	 * @param[in] params Pointer to the scan parameters used for configuration.
	 *
	 * @note Ensure that the Easy Mesh agent and scan parameters are properly initialized before calling this function.
	 */
	void configure(dm_easy_mesh_agent_t& dm, em_scan_params_t *params);

public:
    
	/**!
	 * @brief Constructor for the em_simulator class.
	 *
	 * Initializes a new instance of the em_simulator class.
	 *
	 * @note This constructor does not take any parameters and does not return any values.
	 */
	em_simulator_t();
    
	/**!
	 * @brief Destructor for the em_simulator class.
	 *
	 * This function cleans up any resources used by the em_simulator instance.
	 *
	 * @note Ensure that all operations using the em_simulator instance are complete before destruction.
	 */
	~em_simulator_t();
};

#endif

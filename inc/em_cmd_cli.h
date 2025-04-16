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

#ifndef EM_CMD_CLI_H
#define EM_CMD_CLI_H

#include "em_cmd_exec.h"
#include "dm_easy_mesh.h"

class em_cli_t;
extern em_cli_t g_cli;

class em_cmd_cli_t : public em_cmd_exec_t {

    em_cli_t& m_cli = g_cli;
public:
    static em_cmd_t m_client_cmd_spec[];
public:
    
	/**!
	 * @brief Retrieves the edited network node.
	 *
	 * This function fetches the details of the edited network node based on the provided header.
	 *
	 * @param[in] header The header information used to identify the node.
	 * @param[out] node Pointer to the network node structure where the edited node details will be stored.
	 * @param[out] buff Buffer to store additional information or data related to the node.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the node and buff are properly initialized before calling this function.
	 */
   	static int     get_edited_node(em_network_node_t *node, const char *header, char *buff);
 
	/**!
	 * @brief Executes a command and stores the result.
	 *
	 * This function takes a command, executes it, and stores the output in the provided result buffer.
	 *
	 * @param[out] result A character pointer where the execution result will be stored.
	 *
	 * @returns int Status code of the execution.
	 * @retval 0 on success.
	 * @retval non-zero on failure.
	 *
	 * @note Ensure that the result buffer is adequately sized to hold the command output.
	 */
	int execute(char *result);

	/**!
	 * @brief Constructor for the em_cmd_cli_t class.
	 *
	 * This function initializes an instance of the em_cmd_cli_t class using the provided em_cmd_t object.
	 *
	 * @param[in] obj Reference to an em_cmd_t object used for initialization.
	 *
	 * @note Ensure that the em_cmd_t object is properly initialized before passing it to this constructor.
	 */
	em_cmd_cli_t(em_cmd_t& obj);
	
	/**!
	 * @brief Destructor for the em_cmd_cli_t class.
	 *
	 * This function cleans up any resources used by the em_cmd_cli_t instance.
	 *
	 * @note Ensure that all operations using the em_cmd_cli_t instance are complete before calling this destructor.
	 */
	~em_cmd_cli_t();
};

#endif

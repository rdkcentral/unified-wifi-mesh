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

#ifndef EM_CMD_AGENT_H
#define EM_CMD_AGENT_H

#include "em_cmd_exec.h"

class em_agent_t;
extern em_agent_t g_agent;

class em_cmd_agent_t : public em_cmd_exec_t {
    em_agent_t& m_agent = g_agent;
    int m_dsock;
public:
    static em_cmd_t m_client_cmd_spec[];
public:
    
	/**!
	 * @brief Executes a command and stores the result.
	 *
	 * This function executes a command and stores the output in the provided result parameter.
	 *
	 * @param[out] result A reference to a variable where the execution result will be stored.
	 *
	 * @returns int Status code of the execution.
	 * @retval 0 on success.
	 * @retval non-zero on failure.
	 *
	 * @note Ensure that the result variable is properly initialized before calling this function.
	 */
	int execute(em_long_string_t result);
    
	/**!
	 * @brief Sends the result status.
	 *
	 * This function is responsible for sending the result status of a command.
	 *
	 * @param[in] status The status of the command output to be sent.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure the status is valid before calling this function.
	 */
	int send_result(em_cmd_out_status_t status);

    
	/**!
	 * @brief Creates an event from the given buffer.
	 *
	 * This function takes a character buffer as input and creates an event of type `em_event_t`.
	 *
	 * @param[in] buff A character buffer containing the event data.
	 *
	 * @returns A pointer to the created `em_event_t` event.
	 * @retval NULL if the event creation fails.
	 *
	 * @note Ensure that the buffer is properly formatted to create a valid event.
	 */
	static em_event_t *create_event(char *buff);
    
    
	/**!
	 * @brief 
	 *
	 * Initializes a command agent with the specified command type.
	 *
	 * @param[in] type The type of command to initialize the agent with.
	 *
	 * @returns A new instance of em_cmd_agent_t initialized with the given command type.
	 *
	 * @note Ensure that the command type is valid and supported by the system.
	 */
	em_cmd_agent_t(em_cmd_type_t type);
    
	/**!
	 * @brief Constructor for em_cmd_agent_t class.
	 *
	 * This constructor initializes an instance of the em_cmd_agent_t class using the provided em_cmd_t object.
	 *
	 * @param[in] obj Reference to an em_cmd_t object used for initialization.
	 *
	 * @note Ensure that the em_cmd_t object is properly initialized before passing it to this constructor.
	 */
	em_cmd_agent_t(em_cmd_t& obj);
    
	/**!
	 * @brief Constructor for the em_cmd_agent_t class.
	 *
	 * This constructor initializes an instance of the em_cmd_agent_t class.
	 *
	 * @note This is a default constructor and does not take any parameters.
	 */
	em_cmd_agent_t();
};

#endif

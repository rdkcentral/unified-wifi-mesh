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

#ifndef EM_CMD_CTRL_H
#define EM_CMD_CTRL_H

#include "em_cmd_exec.h"

// extern em_ctrl_t g_ctrl;

class em_cmd_ctrl_t : public em_cmd_exec_t { 
    //em_ctrl_t& m_ctrl = g_ctrl;

public:
    
	/**!
	 * @brief Executes a command and stores the result.
	 *
	 * This function takes a command, executes it, and stores the output in the provided result buffer.
	 *
	 * @param[out] result A character buffer where the execution result will be stored.
	 *
	 * @returns int Status code of the execution.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the result buffer is large enough to hold the command output.
	 */
	int execute(char *result);
    
	/**!
	 * @brief Sends the result of a command execution.
	 *
	 * This function is responsible for sending the result status of a command
	 * execution to the appropriate handler or output interface.
	 *
	 * @param[in] status The status of the command execution to be sent.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the status is valid before calling this function.
	 */
	int send_result(em_cmd_out_status_t status);

    
	/**!
	 * @brief Constructor for em_cmd_ctrl_t class.
	 *
	 * Initializes the em_cmd_ctrl_t object.
	 *
	 * @note This constructor does not take any parameters.
	 */
	em_cmd_ctrl_t();
};

#endif

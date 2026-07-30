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

#ifndef EM_CMD_DEV_TEST_H
#define EM_CMD_DEV_TEST_H

#include "em_cmd.h"

class em_cmd_dev_test_t : public em_cmd_t {

public:
    
	/**!
	 * @brief Executes device test command
	 *
	 * This function is responsible for executing a device test command.
	 *
	 * @param[in] param The parameters required to execute the command.
	 * @param[in,out] dm A reference to the easy mesh data structure that will be modified.
	 *
	 * @returns em_cmd_dev_test_t The result of the device test command execution.
	 *
	 * @note Ensure that the dm structure is properly initialized before calling this function.
	 */
	em_cmd_dev_test_t(em_cmd_params_t param, dm_easy_mesh_t& dm);
};

#endif


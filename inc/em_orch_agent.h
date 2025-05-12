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

#ifndef EM_ORCH_AGENT_H
#define EM_ORCH_AGENT_H

#include "em_orch.h"

class em_orch_agent_t : public em_orch_t {

public:
    
	/**!
	 * @brief Builds candidate elements based on the provided command.
	 *
	 * This function processes the given command and generates a set of candidate elements
	 * that can be used for further operations.
	 *
	 * @param[in] cmd Pointer to the command structure containing necessary information
	 *                for building candidates.
	 *
	 * @returns The number of candidates successfully built.
	 *
	 * @note Ensure that the command structure is properly initialized before calling this function.
	 */
	unsigned int build_candidates(em_cmd_t *cmd);
    
	/**!
	 * @brief Pre-processes the orchestration operation.
	 *
	 * This function is responsible for handling the initial steps required
	 * to process an orchestration command.
	 *
	 * @param[in] pcmd Pointer to the orchestration command to be processed.
	 *
	 * @returns True if the pre-processing is successful, false otherwise.
	 *
	 * @note Ensure that the command is valid before calling this function.
	 */
	bool pre_process_orch_op(em_cmd_t *pcmd);
    
	/**!
	 * @brief Pre-processes the cancellation of a command.
	 *
	 * This function handles the necessary steps to cancel a given command
	 * within the em_t context.
	 *
	 * @param[in] pcmd Pointer to the command structure to be cancelled.
	 * @param[in] em Pointer to the em_t context in which the command is being processed.
	 *
	 * @note Ensure that the command is valid and the context is properly initialized
	 * before calling this function.
	 */
	void pre_process_cancel(em_cmd_t *pcmd, em_t *em);
    
	/**!
	 * @brief Checks if the EM is ready for orchestration execution.
	 *
	 * This function evaluates the readiness of the EM for executing orchestration commands.
	 *
	 * @param[in] pcmd Pointer to the command structure.
	 * @param[in] em Pointer to the EM structure.
	 *
	 * @returns True if the EM is ready for orchestration execution, false otherwise.
	 */
	bool is_em_ready_for_orch_exec(em_cmd_t *pcmd, em_t *em);
    
	/**!
	 * @brief Checks if the EM is ready for orchestration finalization.
	 *
	 * This function determines whether the EM (Execution Manager) is prepared to
	 * finalize the orchestration process based on the provided command.
	 *
	 * @param[in] pcmd Pointer to the command structure that contains the necessary
	 *                 information to check readiness.
	 * @param[in] em   Pointer to the EM structure representing the current state
	 *                 of the Execution Manager.
	 *
	 * @returns True if the EM is ready for orchestration finalization, false otherwise.
	 */
	bool is_em_ready_for_orch_fini(em_cmd_t *pcmd, em_t *em);
    
	/**!
	 * @brief Handles the transient orchestration command for the specified EM.
	 *
	 * This function processes the transient command provided in `pcmd` for the
	 * specified EM instance `em`. It ensures that the command is executed
	 * correctly and updates the state of the EM as necessary.
	 *
	 * @param[in] pcmd Pointer to the command structure containing the transient
	 * command to be processed.
	 * @param[in] em Pointer to the EM instance for which the command is to be
	 * executed.
	 *
	 * @note Ensure that both `pcmd` and `em` are valid pointers before calling
	 * this function to avoid undefined behavior.
	 */
	void orch_transient(em_cmd_t *pcmd, em_t *em);

public:
    
	/**!
	 * @brief Constructor for em_orch_agent_t.
	 *
	 * Initializes an orchestration agent with the given manager.
	 *
	 * @param[in] mgr Pointer to the em_mgr_t manager instance.
	 */
	em_orch_agent_t(em_mgr_t *mgr);
};

#endif

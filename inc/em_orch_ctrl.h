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

#ifndef EM_ORCH_CTRL_H
#define EM_ORCH_CTRL_H

#include "em_orch.h"

class em_orch_ctrl_t : public em_orch_t {

public:
    
	/**!
	 * @brief Builds a list of candidates based on the provided command.
	 *
	 * This function processes the given command and generates candidates
	 * that meet the specified criteria.
	 *
	 * @param[in] cmd Pointer to the command structure containing the criteria for
	 * candidate selection.
	 *
	 * @returns The number of candidates successfully built.
	 * @retval 0 if no candidates were built or an error occurred.
	 *
	 * @note Ensure that the command structure is properly initialized before
	 * calling this function.
	 */
	unsigned int build_candidates(em_cmd_t *cmd);
    
	/**!
	 * @brief Pre-processes the orchestration operation.
	 *
	 * This function is responsible for preparing the orchestration command before execution.
	 *
	 * @param[in] pcmd Pointer to the orchestration command structure that needs to be pre-processed.
	 *
	 * @returns bool
	 * @retval true if the pre-processing is successful.
	 * @retval false if the pre-processing fails.
	 *
	 * @note Ensure that the command structure is properly initialized before calling this function.
	 */
	bool pre_process_orch_op(em_cmd_t *pcmd);
    
	/**!
	 * @brief Cancels the pre-processing of a given command.
	 *
	 * This function is responsible for halting any ongoing pre-processing tasks associated with the provided command.
	 *
	 * @param[in] pcmd Pointer to the command structure that needs pre-processing cancellation.
	 * @param[in] em Pointer to the em structure associated with the command.
	 *
	 * @note Ensure that the command and em structures are properly initialized before calling this function.
	 */
	void pre_process_cancel(em_cmd_t *pcmd, em_t *em);
    
	/**!
	 * @brief Checks if the EM is ready for orchestration execution.
	 *
	 * This function evaluates the readiness of the EM for executing orchestration commands.
	 *
	 * @param[in] pcmd Pointer to the command structure containing orchestration details.
	 * @param[in] em Pointer to the EM structure to be checked.
	 *
	 * @returns True if the EM is ready for orchestration execution, false otherwise.
	 *
	 * @note Ensure that the EM structure is properly initialized before calling this function.
	 */
	bool is_em_ready_for_orch_exec(em_cmd_t *pcmd, em_t *em);
    
	/**!
	 * @brief Checks if the EM is ready for orchestration finalization.
	 *
	 * This function evaluates the current state of the EM and determines if it is prepared to proceed with the finalization of orchestration.
	 *
	 * @param[in] pcmd Pointer to the EM command structure.
	 * @param[in] em Pointer to the EM structure.
	 *
	 * @returns True if the EM is ready for orchestration finalization, false otherwise.
	 */
	bool is_em_ready_for_orch_fini(em_cmd_t *pcmd, em_t *em);
    
	/**!
	 * @brief Handles the orchestration of transient commands.
	 *
	 * This function processes transient commands within the orchestration module.
	 *
	 * @param[in] pcmd Pointer to the command structure containing the transient command details.
	 * @param[in] em Pointer to the em structure representing the current state of the orchestration.
	 *
	 * @note Ensure that the command structure and em state are properly initialized before calling this function.
	 */
	void orch_transient(em_cmd_t *pcmd, em_t *em);

public:
    
	/**!
	 * @brief Initializes the orchestration control structure.
	 *
	 * This function sets up the necessary parameters and state for the orchestration control.
	 *
	 * @param[in] mgr Pointer to the manager structure used for orchestration.
	 *
	 * @returns A newly initialized orchestration control structure.
	 *
	 * @note Ensure that the manager structure is properly initialized before calling this function.
	 */
	em_orch_ctrl_t(em_mgr_t *mgr);
};

#endif

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

#ifndef EM_ORCH_H
#define EM_ORCH_H

#include "em_base.h"
#include "em.h"

class em_cmd_t;
class em_mgr_t;

class em_orch_t {

public:
    em_mgr_t    *m_mgr;
    queue_t *m_pending;
    queue_t *m_active;
    hash_map_t  *m_cmd_map;

public:
    
	/**!
	 * @brief Retrieves the current state based on the provided command.
	 *
	 * @param[in] cmd Pointer to the command structure used to determine the state.
	 *
	 * @returns The current state of type em_orch_state_t associated with the given command.
	 */
	em_orch_state_t get_state(em_cmd_t *cmd);
    
	/**!
	 * @brief Handles the timeout event.
	 *
	 * This function is called when a timeout occurs.
	 * It performs necessary operations to handle the timeout.
	 *
	 * @note Ensure that the timeout duration is correctly set before calling this function.
	 */
	void handle_timeout();

    
	/**!
	 * @brief Submits a list of commands for execution.
	 *
	 * This function takes an array of command pointers and the number of commands,
	 * and submits them for processing.
	 *
	 * @param[in] pcmd Array of pointers to commands to be submitted.
	 * @param[in] num Number of commands in the array.
	 *
	 * @returns The number of commands successfully submitted.
	 *
	 * @note Ensure that the command pointers are valid and the number of commands
	 * does not exceed the maximum allowed.
	 */
	unsigned int submit_commands(em_cmd_t *pcmd[], unsigned int num);
    
	/**!
	 * @brief Builds candidates based on the provided command.
	 *
	 * This function processes the given command and constructs a set of candidates
	 * that can be used for further operations.
	 *
	 * @param[in] cmd Pointer to the command structure containing necessary information
	 *                for building candidates.
	 *
	 * @returns An unsigned integer representing the number of candidates built.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual unsigned int build_candidates(em_cmd_t *cmd) = 0;
    
	/**!
	 * @brief Checks if the given command is eligible for activation.
	 *
	 * This function evaluates the provided command and determines if it meets
	 * the criteria to be considered active.
	 *
	 * @param[in] pcmd Pointer to the command structure to be evaluated.
	 *
	 * @returns True if the command is eligible for activation, false otherwise.
	 *
	 * @note Ensure that the command structure is properly initialized before
	 * calling this function.
	 */
	bool eligible_for_active(em_cmd_t *pcmd);

    
	/**!
	 * @brief Pre-processes the orchestration operation.
	 *
	 * This function is responsible for performing any necessary pre-processing
	 * steps required before executing the main orchestration operation.
	 *
	 * @param[in] pcmd Pointer to the command structure containing the details
	 * of the orchestration operation to be pre-processed.
	 *
	 * @returns True if the pre-processing is successful, false otherwise.
	 */
	virtual bool pre_process_orch_op(em_cmd_t *pcmd) = 0;
    
	/**!
	 * @brief Pre-processes the cancellation of a command.
	 *
	 * This function is responsible for handling the initial steps required
	 * to cancel a given command within the em_t context.
	 *
	 * @param[in] pcmd Pointer to the command structure to be cancelled.
	 * @param[in] em Pointer to the em_t context in which the command is being processed.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void pre_process_cancel(em_cmd_t *pcmd, em_t *em) = 0;
    
	/**!
	 * @brief Checks if the EM is ready for orchestration execution.
	 *
	 * This function determines whether the EM (Execution Manager) is prepared to execute the given orchestration command.
	 *
	 * @param[in] pcmd Pointer to the em_cmd_t structure containing the command details.
	 * @param[in] em Pointer to the em_t structure representing the execution manager.
	 *
	 * @returns True if the EM is ready for orchestration execution, false otherwise.
	 */
	virtual bool is_em_ready_for_orch_exec(em_cmd_t *pcmd, em_t *em) = 0;
    
	/**!
	 * @brief Check if the EM is ready for orchestration finalization.
	 *
	 * This function determines whether the EM (Execution Manager) is prepared to
	 * complete the orchestration process based on the provided command.
	 *
	 * @param[in] pcmd Pointer to the command structure that contains the necessary
	 *                 information to assess readiness.
	 * @param[in] em   Pointer to the EM structure that is being checked for readiness.
	 *
	 * @returns True if the EM is ready for orchestration finalization, false otherwise.
	 */
	virtual bool is_em_ready_for_orch_fini(em_cmd_t *pcmd, em_t *em) = 0;
    
	/**!
	 * @brief Handles transient orchestration for the given command and em.
	 *
	 * This function is responsible for managing transient states in the orchestration
	 * process using the provided command and em parameters.
	 *
	 * @param[in] pcmd Pointer to the em_cmd_t structure containing command details.
	 * @param[in] em Pointer to the em_t structure representing the em context.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void orch_transient(em_cmd_t *pcmd, em_t *em) = 0;
    
	/**!
	 * @brief Submits a command for processing.
	 *
	 * This function takes a command structure and submits it for processing by the
	 * appropriate handler. The command structure should be properly initialized
	 * before calling this function.
	 *
	 * @param[in] pcmd Pointer to the command structure to be submitted.
	 *
	 * @returns True if the command was successfully submitted, false otherwise.
	 *
	 * @note Ensure that the command structure is valid and all required fields
	 * are set before submission.
	 */
	bool submit_command(em_cmd_t *pcmd);
    
	/**!
	 * @brief Destroys the given command object.
	 *
	 * This function is responsible for cleaning up and releasing any resources
	 * associated with the command object pointed to by `pcmd`.
	 *
	 * @param[in] pcmd Pointer to the command object to be destroyed.
	 *
	 * @note Ensure that `pcmd` is not NULL before calling this function.
	 */
	void destroy_command(em_cmd_t *pcmd);
    
	/**!
        * @brief Cancels a command of the specified type if misconfiguration for specific EMs.
        *
        * This function is used to cancel a command that is currently being processed when misconfigure happens.
        *
        * @param[in] type The type of command to cancel. This parameter specifies which command
        * should be canceled based on the em_cmd_type_t enumeration.
        *
        * @note Ensure that the command type provided is valid and currently active.
        */
       void cancel_command(em_cmd_type_t type, std::vector<em_t*> &em_radios);

	/**!
	 * @brief Cancels a command of the specified type.
	 *
	 * This function is used to cancel a command that is currently being processed or queued.
	 *
	 * @param[in] type The type of command to cancel. This parameter specifies which command
	 * should be canceled based on the em_cmd_type_t enumeration.
	 *
	 * @note Ensure that the command type provided is valid and currently active.
	 */
	void cancel_command(em_cmd_type_t type);
    
	/**!
	 * @brief Pushes statistics to the specified command structure.
	 *
	 * This function is responsible for updating the command structure with the
	 * latest statistics data.
	 *
	 * @param[in] pcmd Pointer to the command structure where statistics will be pushed.
	 *
	 * @note Ensure that the command structure is properly initialized before calling
	 * this function to avoid undefined behavior.
	 */
	void push_stats(em_cmd_t *pcmd);
    
	/**!
	 * @brief Populates statistics from the given command.
	 *
	 * This function extracts and processes statistics from the provided
	 * em_cmd_t command structure.
	 *
	 * @param[in] pcmd Pointer to the em_cmd_t command structure containing
	 *                 the statistics to be populated.
	 *
	 * @note Ensure that the command structure is properly initialized
	 *       before calling this function.
	 */
	void pop_stats(em_cmd_t *pcmd);
    
	/**!
	 * @brief Updates the statistics based on the provided command.
	 *
	 * This function processes the command pointed to by `pcmd` and updates
	 * the relevant statistics accordingly.
	 *
	 * @param[in] pcmd Pointer to the command structure containing the
	 * necessary information to update the statistics.
	 *
	 * @note Ensure that `pcmd` is not null and points to a valid command
	 * structure before calling this function.
	 */
	void update_stats(em_cmd_t *pcmd);
   
	/**!
	 * @brief Checks if a command type is currently in progress.
	 *
	 * This function determines whether a specific command type, identified by the
	 * parameter `type`, is currently being processed or is in progress.
	 *
	 * @param[in] evt bus event.
	 *
	 * @returns True if the command type is in progress, false otherwise.
	 */
	bool is_cmd_type_in_progress(em_bus_event_t *evt);

	/**!
	 * @brief Checks if a command type is currently in progress.
	 *
	 * This function determines whether a dev test commands types are identified by the
	 * parameter `type`, is currently being processed or is in progress.
	 *
	 *
	 * @returns True if the command type is in progress, false otherwise.
	 */
	bool get_dev_test_status();
 
	/**!
	 * @brief Checks if a command type is currently in progress.
	 *
	 * This function determines whether a specific command type, identified by the
	 * parameter `type`, is currently being processed or is in progress.
	 *
	 * @param[in] evt  event information .
	 *
	 * @returns True if the command type is in progress, false otherwise.
	 */
        bool is_cmd_type_renew_in_progress(em_bus_event_t *evt); 
	/**!
	 * @brief Orchestrates the execution of a command within the em context.
	 *
	 * This function takes a command and an em context, performing the necessary operations
	 * to execute the command within the given context.
	 *
	 * @param[in] pcmd Pointer to the command to be executed.
	 * @param[in] em Pointer to the em context in which the command is executed.
	 *
	 * @returns True if the orchestration is successful, false otherwise.
	 *
	 * @note Ensure that both pcmd and em are properly initialized before calling this function.
	 */
	bool orchestrate(em_cmd_t *pcmd, em_t *em);

    
	/**!
	 * @brief Constructor for the em_orch_t class.
	 *
	 * This constructor initializes the em_orch_t object.
	 *
	 * @note This is a default constructor.
	 */
	em_orch_t();
    
	/**!
	 * @brief Destructor for em_orch_t class.
	 *
	 * This function cleans up resources allocated by the em_orch_t instance.
	 *
	 * @note This is a virtual destructor.
	 */
	virtual ~em_orch_t();
};

#endif

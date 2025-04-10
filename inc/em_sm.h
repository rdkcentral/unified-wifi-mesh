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

#ifndef EM_SM_H
#define EM_SM_H

#include "em_base.h"

class em_sm_t {
	
	em_state_t	m_state;

public:
	
	/**!
	 * @brief Sets the state of the entity.
	 *
	 * This function updates the current state of the entity to the specified state.
	 *
	 * @param[in] state The new state to be set for the entity.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 Success.
	 * @retval -1 Failure due to invalid state.
	 *
	 * @note Ensure the state is valid before calling this function.
	 */
	int set_state(em_state_t state);
	
	/**!
	 * @brief Validates the state machine.
	 *
	 * This function checks if the given state is valid within the state machine.
	 *
	 * @param[in] state The state to be validated.
	 *
	 * @returns True if the state is valid, false otherwise.
	 *
	 * @note Ensure that the state is defined within the state machine before calling this function.
	 */
	bool validate_sm(em_state_t state);
	
	/**!
	 * @brief Retrieves the current state.
	 *
	 * @returns The current state of type em_state_t.
	 */
	em_state_t get_state() { return m_state; }

	
	/**!
	 * @brief Initializes the state machine for the specified service type.
	 *
	 * This function sets up the necessary configurations and prepares the state machine
	 * to handle events related to the given service type.
	 *
	 * @param[in] service The type of service for which the state machine is being initialized.
	 *
	 * @note Ensure that the service type is valid and supported before calling this function.
	 */
	void init_sm(em_service_type_t service);
	
    
	/**!
	 * @brief Constructor for the em_sm_t class.
	 *
	 * This constructor initializes an instance of the em_sm_t class.
	 *
	 * @note This is a default constructor.
	 */
	em_sm_t();
    
	/**!
	 * @brief Destructor for the em_sm_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the em_sm_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	~em_sm_t();
};

#endif

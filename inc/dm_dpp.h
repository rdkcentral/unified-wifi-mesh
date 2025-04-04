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

#ifndef DM_DPP_H
#define DM_DPP_H

#include "em_base.h"
#include "ec_base.h"

class em_cmd_t;

class dm_dpp_t {
public:
    ec_data_t    m_dpp_info;

public:
    
	/**!
	* @brief Initializes the system or component.
	*
	* This function sets up necessary configurations and prepares the system for operation.
	*
	* @returns int
	* @retval 0 on success
	* @retval -1 on failure
	*
	* @note Ensure that all prerequisites are met before calling this function.
	*/
	int init();
    
	/**!
	 * @brief Retrieves the DPP information.
	 *
	 * This function returns a pointer to the DPP information structure.
	 *
	 * @returns A pointer to the `ec_data_t` structure containing DPP information.
	 *
	 * @note Ensure that the returned pointer is not modified directly.
	 */
	ec_data_t *get_dpp_info() { return &m_dpp_info; }
    
	/**!
	 * @brief Decodes a JSON object into a specific format.
	 *
	 * This function takes a JSON object and decodes it, storing the result in the provided parent_id and user_info.
	 *
	 * @param[in] obj The JSON object to decode.
	 * @param[out] parent_id Pointer to store the decoded parent ID.
	 * @param[out] user_info Pointer to store user-specific information.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that obj is a valid cJSON object before calling this function.
	 */
	int decode(const cJSON *obj, void *parent_id, void* user_info);
    
	/**!
	 * @brief Encodes a cJSON object.
	 *
	 * This function takes a cJSON object and performs encoding operations on it.
	 *
	 * @param[in] obj Pointer to the cJSON object to be encoded.
	 *
	 * @note Ensure that the cJSON object is properly initialized before calling this function.
	 */
	void encode(cJSON *obj);

    bool operator == (const dm_dpp_t& obj);
    void operator = (const dm_dpp_t& obj);

    
	/**!
	 * @brief Analyzes the configuration from a JSON object.
	 *
	 * This function processes the given JSON object and extracts relevant
	 * configuration details, storing them in the provided command and parameter
	 * structures.
	 *
	 * @param[in] obj The JSON object containing configuration data.
	 * @param[out] parent A pointer to the parent structure where results are stored.
	 * @param[out] cmd An array of command structures to be populated.
	 * @param[out] param A pointer to the command parameters structure to be filled.
	 * @param[in] user_param A user-defined parameter for additional context.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object is properly formatted before calling this function.
	 */
	int analyze_config(const cJSON *obj, void *parent, em_cmd_t *cmd[], em_cmd_params_t *param, void* user_param);

    
	/**!
	 * @brief Constructor for dm_dpp_t class.
	 *
	 * This function initializes a dm_dpp_t object with the provided ec_data_t pointer.
	 *
	 * @param[in] dpp Pointer to an ec_data_t structure that contains the necessary data for initialization.
	 *
	 * @note Ensure that the ec_data_t pointer is valid and properly initialized before passing it to this constructor.
	 */
	dm_dpp_t(ec_data_t *dpp);
    
	/**!
	 * @brief Copy constructor for dm_dpp_t.
	 *
	 * This constructor creates a new instance of dm_dpp_t by copying the data from an existing instance.
	 *
	 * @param[in] dpp The dm_dpp_t instance to copy from.
	 *
	 * @note This is a deep copy constructor.
	 */
	dm_dpp_t(const dm_dpp_t& dpp);
    
	/**!
	 * @brief Constructor for dm_dpp_t class.
	 *
	 * Initializes a new instance of the dm_dpp_t class.
	 *
	 * @note This constructor does not take any parameters.
	 */
	dm_dpp_t();
    
	/**!
	 * @brief Destructor for the dm_dpp_t class.
	 *
	 * This function cleans up any resources allocated by the dm_dpp_t instance.
	 *
	 * @note Ensure that all operations using dm_dpp_t are completed before calling the destructor.
	 */
	~dm_dpp_t();
};

#endif

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

#ifndef DM_CAC_COMP_H
#define DM_CAC_COMP_H

#include "em_base.h"

class dm_cac_comp_t {
public:
    em_cac_comp_info_t    m_cac_comp_info;

public:
    
	/**!
	 * @brief Initializes the CAC component information structure.
	 *
	 * This function sets the CAC component information structure to zero.
	 *
	 * @returns int
	 * @retval 0 on successful initialization.
	 *
	 * @note This function does not take any parameters and always returns 0.
	 */
	int init() { memset(&m_cac_comp_info, 0, sizeof(em_cac_comp_info_t)); return 0; }
    
	/**!
	 * @brief Retrieves the CAC component information.
	 *
	 * @returns A pointer to the CAC component information structure.
	 */
	em_cac_comp_info_t *get_cac_comp_info() { return &m_cac_comp_info; }
    
    
	/**!
	 * @brief Retrieves the CAC component ID.
	 *
	 * This function returns the unique identifier for the CAC component.
	 *
	 * @returns A pointer to an unsigned char representing the CAC component ID.
	 *
	 * @note Ensure that the returned pointer is not null before using it.
	 */
	unsigned char *get_cac_comp_id() { return m_cac_comp_info.ruid; }
    
	/**!
	 * @brief Decodes a JSON object and associates it with a parent identifier.
	 *
	 * This function takes a JSON object and a parent identifier, performing the necessary decoding
	 * operations to associate the JSON data with the given parent.
	 *
	 * @param[in] obj The JSON object to be decoded.
	 * @param[out] parent_id The identifier of the parent to associate with the decoded data.
	 *
	 * @returns int Status code indicating success or failure of the decoding operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object and parent identifier are valid before calling this function.
	 */
	int decode(const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Encodes a cJSON object.
	 *
	 * This function takes a cJSON object and performs encoding operations on it.
	 *
	 * @param[in] obj Pointer to the cJSON object to be encoded.
	 *
	 * @note Ensure the cJSON object is properly initialized before calling this function.
	 */
	void encode(cJSON *obj);

    bool operator == (const dm_cac_comp_t& obj);
    void operator = (const dm_cac_comp_t& obj);
    
	/**!
	 * @brief Retrieves the DM orchestrator type for a given radio component.
	 *
	 * This function determines the orchestrator type associated with the specified
	 * radio component within the DM CAC (Dynamic Management Common Access Control)
	 * framework.
	 *
	 * @param[in] radio The radio component for which the orchestrator type is to be retrieved.
	 *
	 * @returns The orchestrator type associated with the provided radio component.
	 *
	 * @note Ensure that the radio component is properly initialized before calling this function.
	 */
	dm_orch_type_t get_dm_orch_type(const dm_cac_comp_t& radio);

    
	/**!
	 * @brief 
	 * This function initializes the CAC component with the provided information.
	 *
	 * @param[in] cac_comp A pointer to the structure containing CAC component information.
	 *
	 * @returns dm_cac_comp_t
	 * @retval Returns a handle to the initialized CAC component.
	 *
	 * @note Ensure that the `cac_comp` pointer is valid and properly initialized before calling this function.
	 */
	dm_cac_comp_t(em_cac_comp_info_t *cac_comp);
    
	/**!
	 * @brief Copy constructor for dm_cac_comp_t.
	 *
	 * This constructor initializes a new instance of dm_cac_comp_t
	 * by copying the contents of an existing instance.
	 *
	 * @param[in] cac_comp The dm_cac_comp_t instance to copy.
	 *
	 * @note Ensure that the source instance is valid and properly initialized.
	 */
	dm_cac_comp_t(const dm_cac_comp_t& cac_comp);
    
	/**!
	 * @brief Constructor for the dm_cac_comp_t class.
	 *
	 * This constructor initializes the dm_cac_comp_t object.
	 *
	 * @note This is a default constructor.
	 */
	dm_cac_comp_t();
    
	/**!
	 * @brief Destructor for the dm_cac_comp_t class.
	 *
	 * This function is responsible for cleaning up resources used by the dm_cac_comp_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	~dm_cac_comp_t();
};

#endif

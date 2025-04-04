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

#ifndef DM_BSTA_MLD_H
#define DM_BSTA_MLD_H

#include "em_base.h"

class dm_bsta_mld_t {
public:
    em_bsta_mld_info_t    m_bsta_mld_info;

public:
    
	/**!
	 * @brief Initializes the m_bsta_mld_info structure.
	 *
	 * This function sets all bytes of the m_bsta_mld_info structure to zero.
	 *
	 * @returns int
	 * @retval 0 on successful initialization.
	 *
	 * @note This function does not take any parameters and always returns 0.
	 */
	int init() { memset(&m_bsta_mld_info, 0, sizeof(em_bsta_mld_info_t)); return 0; }
    
	/**!
	 * @brief Retrieves the AP MLD information.
	 *
	 * This function returns a pointer to the AP MLD information structure.
	 *
	 * @returns A pointer to the `em_bsta_mld_info_t` structure containing the AP MLD information.
	 *
	 * @note Ensure that the returned pointer is not null before accessing its members.
	 */
	em_bsta_mld_info_t *get_ap_mld_info() { return &m_bsta_mld_info; }
    
	/**!
	 * @brief Decodes a JSON object and associates it with a parent ID.
	 *
	 * This function takes a JSON object and decodes it, associating the decoded data with a specified parent ID.
	 *
	 * @param[in] obj The JSON object to decode.
	 * @param[out] parent_id The ID of the parent to associate with the decoded data.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the JSON object is valid and the parent ID is correctly initialized before calling this function.
	 */
	int decode(const cJSON *obj, void *parent_id);
    
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

    bool operator == (const dm_bsta_mld_t& obj);
    void operator = (const dm_bsta_mld_t& obj);

    
	/**!
	 * @brief This function handles the MLD (Multi-Link Device) information processing.
	 *
	 * This function is responsible for processing the MLD information provided
	 * through the input parameter and performing necessary operations.
	 *
	 * @param[in] ap_mld_info Pointer to the MLD information structure that needs to be processed.
	 *
	 * @returns dm_bsta_mld_t
	 *
	 * @note Ensure that the input parameter is properly initialized before calling this function.
	 */
	dm_bsta_mld_t(em_bsta_mld_info_t *ap_mld_info);
    
	/**!
	 * @brief Copy constructor for dm_bsta_mld_t.
	 *
	 * This constructor initializes a new instance of the dm_bsta_mld_t class by copying the data from an existing instance.
	 *
	 * @param[in] ap_mld The instance of dm_bsta_mld_t to copy from.
	 */
	dm_bsta_mld_t(const dm_bsta_mld_t& ap_mld);
    
	/**!
	 * @brief Constructor for dm_bsta_mld_t class.
	 *
	 * Initializes the dm_bsta_mld_t object.
	 *
	 * @note This constructor does not take any parameters.
	 */
	dm_bsta_mld_t();
    
	/**!
	 * @brief Destructor for the dm_bsta_mld_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the dm_bsta_mld_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	~dm_bsta_mld_t();
};

#endif

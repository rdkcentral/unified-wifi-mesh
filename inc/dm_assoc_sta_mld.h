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

#ifndef DM_ASSOC_STA_MLD_H
#define DM_ASSOC_STA_MLD_H

#include "em_base.h"

class dm_assoc_sta_mld_t {
public:
    em_assoc_sta_mld_info_t    m_assoc_sta_mld_info;

public:
    
	/**!
	 * @brief Initializes the association station MLD information structure.
	 *
	 * This function sets the memory of the association station MLD information
	 * structure to zero, effectively initializing it.
	 *
	 * @returns int
	 * @retval 0 on successful initialization.
	 */
	int init() { memset(&m_assoc_sta_mld_info, 0, sizeof(em_assoc_sta_mld_info_t)); return 0; }
    
	/**!
	 * @brief Retrieves the AP MLD information.
	 *
	 * This function returns a pointer to the associated station MLD information.
	 *
	 * @returns A pointer to the `em_assoc_sta_mld_info_t` structure containing the AP MLD information.
	 */
	em_assoc_sta_mld_info_t *get_ap_mld_info() { return &m_assoc_sta_mld_info; }
    
	/**!
	 * @brief Decodes a JSON object and associates it with a parent identifier.
	 *
	 * This function takes a JSON object and a parent identifier, performing the necessary operations
	 * to decode the JSON data and associate it with the given parent.
	 *
	 * @param[in] obj The JSON object to be decoded.
	 * @param[out] parent_id The identifier of the parent to associate with the decoded data.
	 *
	 * @returns int Status code indicating success or failure of the decoding operation.
	 * @retval 0 Success.
	 * @retval -1 Failure due to invalid input or processing error.
	 *
	 * @note Ensure that the JSON object and parent identifier are valid before calling this function.
	 */
	int decode(const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Encodes the given cJSON object.
	 *
	 * This function takes a cJSON object and performs encoding operations.
	 *
	 * @param[in] obj Pointer to the cJSON object to be encoded.
	 *
	 * @note Ensure the cJSON object is properly initialized before calling this function.
	 */
	void encode(cJSON *obj);

    bool operator == (const dm_assoc_sta_mld_t& obj);
    void operator = (const dm_assoc_sta_mld_t& obj);

    
	/**!
	 * @brief Associates a station with the MLD (Multi-Link Device).
	 *
	 * This function is responsible for associating a station with the MLD using the provided
	 * access point MLD information.
	 *
	 * @param[in] ap_mld_info Pointer to the access point MLD information structure.
	 *
	 * @returns dm_assoc_sta_mld_t The result of the association process.
	 *
	 * @note Ensure that the ap_mld_info is properly initialized before calling this function.
	 */
	dm_assoc_sta_mld_t(em_assoc_sta_mld_info_t *ap_mld_info);
    
	/**!
	 * @brief Copy constructor for dm_assoc_sta_mld_t.
	 *
	 * This constructor initializes a new instance of dm_assoc_sta_mld_t by copying the data from the provided instance.
	 *
	 * @param[in] ap_mld The instance of dm_assoc_sta_mld_t to copy from.
	 */
	dm_assoc_sta_mld_t(const dm_assoc_sta_mld_t& ap_mld);
    
	/**!
	 * @brief Constructor for the dm_assoc_sta_mld class.
	 *
	 * Initializes a new instance of the dm_assoc_sta_mld class.
	 *
	 * @note This constructor does not take any parameters and does not return any values.
	 */
	dm_assoc_sta_mld_t();
    
	/**!
	 * @brief Destructor for the dm_assoc_sta_mld_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the dm_assoc_sta_mld_t instance.
	 *
	 * @note Ensure that all associated resources are properly released before the object is destroyed.
	 */
	~dm_assoc_sta_mld_t();
};

#endif

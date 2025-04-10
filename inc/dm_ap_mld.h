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

#ifndef DM_AP_MLD_H
#define DM_AP_MLD_H

#include "em_base.h"

class dm_ap_mld_t {
public:
    em_ap_mld_info_t    m_ap_mld_info;

public:
    
	/**!
	 * @brief Initializes the m_ap_mld_info structure.
	 *
	 * This function sets the m_ap_mld_info structure to zero.
	 *
	 * @returns 0 on successful initialization.
	 */
	int init() { memset(&m_ap_mld_info, 0, sizeof(em_ap_mld_info_t)); return 0; }
    
	/**!
	 * @brief Retrieves the AP MLD information.
	 *
	 * This function returns a pointer to the AP MLD information structure.
	 *
	 * @returns A pointer to the `em_ap_mld_info_t` structure containing the AP MLD information.
	 *
	 * @note Ensure that the returned pointer is not null before accessing the structure.
	 */
	em_ap_mld_info_t *get_ap_mld_info() { return &m_ap_mld_info; }
    
	/**!
	 * @brief Decodes a JSON object and associates it with a parent ID.
	 *
	 * This function takes a JSON object and decodes it, linking it to a specified parent ID.
	 *
	 * @param[in] obj The JSON object to be decoded.
	 * @param[out] parent_id The ID of the parent to which the decoded object will be linked.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the JSON object is valid before calling this function.
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

    bool operator == (const dm_ap_mld_t& obj);
    void operator = (const dm_ap_mld_t& obj);

    
	/**!
	 * @brief Initializes the AP MLD with the provided information.
	 *
	 * This function sets up the AP MLD using the details specified in the
	 * em_ap_mld_info_t structure. It is essential for configuring the MLD
	 * before it can be used for further operations.
	 *
	 * @param[in] ap_mld_info Pointer to a structure containing the MLD information.
	 *
	 * @returns dm_ap_mld_t A handle to the initialized AP MLD.
	 *
	 * @note Ensure that the ap_mld_info is properly populated before calling this function.
	 */
	dm_ap_mld_t(em_ap_mld_info_t *ap_mld_info);
    
	/**!
	 * @brief Copy constructor for dm_ap_mld_t.
	 *
	 * This constructor creates a new instance of dm_ap_mld_t by copying the data from an existing instance.
	 *
	 * @param[in] ap_mld The instance of dm_ap_mld_t to copy from.
	 *
	 * @note This is a deep copy constructor.
	 */
	dm_ap_mld_t(const dm_ap_mld_t& ap_mld);
    
	/**!
	 * @brief Constructor for dm_ap_mld_t class.
	 *
	 * This constructor initializes the dm_ap_mld_t object.
	 *
	 * @note Ensure that the object is properly initialized before use.
	 */
	dm_ap_mld_t();
    
	/**!
	 * @brief Destructor for the dm_ap_mld_t class.
	 *
	 * This function is responsible for cleaning up resources used by the dm_ap_mld_t instance.
	 *
	 * @note Ensure that all resources are properly released before the destructor is called.
	 */
	~dm_ap_mld_t();
};

#endif

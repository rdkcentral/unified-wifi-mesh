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

#ifndef DM_TID_TO_LINK_H
#define DM_TID_TO_LINK_H

#include "em_base.h"

class dm_tid_to_link_t {
public:
    em_tid_to_link_info_t    m_tid_to_link_info;

public:
    
	/**!
	 * @brief Initializes the TID to link information structure.
	 *
	 * This function sets the TID to link information structure to zero.
	 *
	 * @returns int
	 * @retval 0 on successful initialization.
	 *
	 * @note This function does not take any parameters and always returns 0.
	 */
	int init() { memset(&m_tid_to_link_info, 0, sizeof(em_tid_to_link_info_t)); return 0; }
    
	/**!
	 * @brief Retrieves the TID to link information.
	 *
	 * This function returns a pointer to the TID to link information structure.
	 *
	 * @returns A pointer to the `em_tid_to_link_info_t` structure containing the TID to link information.
	 *
	 * @note Ensure that the returned pointer is not null before dereferencing.
	 */
	em_tid_to_link_info_t *get_tid_to_link_info() { return &m_tid_to_link_info; }
    
	/**!
	 * @brief Decodes a JSON object to extract relevant information.
	 *
	 * This function takes a JSON object and decodes it to extract information
	 * that is then used to populate or modify the parent_id structure.
	 *
	 * @param[in] obj The JSON object to be decoded.
	 * @param[out] parent_id A pointer to the structure where the decoded information will be stored.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the JSON object is valid and the parent_id is properly initialized before calling this function.
	 */
	int decode(const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Encodes the given cJSON object.
	 *
	 * This function takes a cJSON object and performs encoding operations on it.
	 *
	 * @param[in] obj Pointer to the cJSON object to be encoded.
	 *
	 * @note Ensure that the cJSON object is properly initialized before calling this function.
	 */
	void encode(cJSON *obj);

    bool operator == (const dm_tid_to_link_t& obj);
    void operator = (const dm_tid_to_link_t& obj);

    
	/**!
	 * @brief Associates a TID with link information.
	 *
	 * This function takes a pointer to a `em_tid_to_link_info_t` structure and associates the TID with the corresponding link information.
	 *
	 * @param[in] tid_to_link_info Pointer to the structure containing TID to link information.
	 *
	 * @returns dm_tid_to_link_t The result of the association operation.
	 *
	 * @note Ensure that `tid_to_link_info` is properly initialized before calling this function.
	 */
	dm_tid_to_link_t(em_tid_to_link_info_t *tid_to_link_info);
    
	/**!
	 * @brief Copy constructor for dm_tid_to_link_t.
	 *
	 * This constructor creates a new instance of dm_tid_to_link_t by copying the data from an existing instance.
	 *
	 * @param[in] tid_to_link The instance of dm_tid_to_link_t to copy from.
	 *
	 * @note This is a deep copy constructor.
	 */
	dm_tid_to_link_t(const dm_tid_to_link_t& tid_to_link);
    
	/**!
	 * @brief Constructor for the dm_tid_to_link_t class.
	 *
	 * This constructor initializes a new instance of the dm_tid_to_link_t class.
	 *
	 * @note This is a default constructor and does not take any parameters.
	 */
	dm_tid_to_link_t();
    
	/**!
	 * @brief Destructor for the dm_tid_to_link_t class.
	 *
	 * This function is responsible for cleaning up resources used by the dm_tid_to_link_t instance.
	 *
	 * @note Ensure that all resources are properly released before the destructor is called.
	 */
	~dm_tid_to_link_t();
};

#endif

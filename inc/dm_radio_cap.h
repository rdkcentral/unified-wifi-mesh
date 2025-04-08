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

#ifndef DM_RADIO_CAP_H
#define DM_RADIO_CAP_H

#include "em_base.h"

class dm_radio_cap_t {
public:
    em_radio_cap_info_t    m_radio_cap_info;

public:
    
	/**!
	 * @brief Initializes the radio capabilities.
	 *
	 * This function sets the radio capabilities information to zero.
	 *
	 * @returns int
	 * @retval 0 on successful initialization.
	 *
	 * @note This function does not take any parameters.
	 */
	int init() { memset(&m_radio_cap_info, 0, sizeof(em_radio_cap_info_t)); return 0; }
    
	/**!
	 * @brief Retrieves the radio capability information.
	 *
	 * @returns A pointer to the radio capability information structure.
	 */
	em_radio_cap_info_t *get_radio_cap_info() { return &m_radio_cap_info; }
    
	/**!
	 * @brief Decodes a JSON object and associates it with a parent ID.
	 *
	 * This function takes a JSON object and a parent ID, performing the necessary
	 * operations to decode the JSON data and link it to the specified parent.
	 *
	 * @param[in] obj The JSON object to be decoded.
	 * @param[out] parent_id The ID of the parent to associate with the decoded data.
	 *
	 * @returns int Status code indicating success or failure of the decoding process.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object is properly formatted before calling this function.
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

    bool operator == (const dm_radio_cap_t& obj);
    void operator = (const dm_radio_cap_t& obj);

    
	/**!
	* @brief Retrieves the radio capabilities.
	*
	* This function is responsible for obtaining the radio capabilities and storing them in the provided structure.
	*
	* @param[out] radio_cap A pointer to an em_radio_cap_info_t structure where the radio capabilities will be stored.
	*
	* @returns A dm_radio_cap_t type indicating the status of the operation.
	* @retval DM_RADIO_CAP_SUCCESS if the operation was successful.
	* @retval DM_RADIO_CAP_FAILURE if the operation failed.
	*
	* @note Ensure that the radio_cap pointer is valid and points to a properly allocated structure.
	*/
	dm_radio_cap_t(em_radio_cap_info_t *radio_cap);
    
	/**!
	 * @brief Copy constructor for dm_radio_cap_t.
	 *
	 * This constructor initializes a new instance of the dm_radio_cap_t class
	 * by copying the data from an existing instance.
	 *
	 * @param[in] radio_cap The instance of dm_radio_cap_t to copy from.
	 *
	 * @note This is a deep copy constructor.
	 */
	dm_radio_cap_t(const dm_radio_cap_t& radio_cap);
    
	/**!
	 * @brief Constructor for the dm_radio_cap_t class.
	 *
	 * Initializes a new instance of the dm_radio_cap_t class.
	 *
	 * @note This constructor does not take any parameters.
	 */
	dm_radio_cap_t();
    
	/**!
	 * @brief Destructor for the dm_radio_cap_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the dm_radio_cap_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	virtual ~dm_radio_cap_t();
};

#endif

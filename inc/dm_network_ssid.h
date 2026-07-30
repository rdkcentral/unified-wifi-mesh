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

#ifndef DM_NETWORK_SSID_H
#define DM_NETWORK_SSID_H

#include "em_base.h"

class dm_network_ssid_t {
public:
    em_network_ssid_info_t    m_network_ssid_info;

public:
    
	/**!
	 * @brief Initializes the network SSID information structure.
	 *
	 * This function sets the network SSID information structure to zero.
	 *
	 * @returns 0 on successful initialization.
	 */
	int init() { memset(&m_network_ssid_info, 0, sizeof(em_network_ssid_info_t)); return 0; }
    
	/**!
	 * @brief Retrieves the network SSID information.
	 *
	 * This function returns a pointer to the structure containing the network SSID information.
	 *
	 * @returns Pointer to the network SSID information structure.
	 *
	 * @note Ensure that the returned pointer is not null before accessing the structure.
	 */
	em_network_ssid_info_t *get_network_ssid_info() { return &m_network_ssid_info; }
    
	/**!
	 * @brief Decodes a JSON object and associates it with a parent ID.
	 *
	 * This function takes a JSON object and decodes it, associating the decoded
	 * data with a specified parent ID. It is used to process JSON data within
	 * the network SSID context.
	 *
	 * @param[in] obj The JSON object to be decoded.
	 * @param[out] parent_id The ID of the parent to associate with the decoded data.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the JSON object is valid and the parent ID is correctly
	 * initialized before calling this function.
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

    
	/**!
	 * @brief Converts the haul type to a string representation.
	 *
	 * This function takes an em_haul_type_t and converts it to a human-readable string.
	 *
	 * @param[in] type The haul type to be converted.
	 * @param[out] str The string representation of the haul type.
	 *
	 * @returns A pointer to the string representation of the haul type.
	 *
	 * @note Ensure that the str buffer is large enough to hold the resulting string.
	 */
	static char *haul_type_to_string(em_haul_type_t type, em_string_t	str);
    
	/**!
	 * @brief Converts a string to a haul type.
	 *
	 * This function takes a string representation of a haul type and converts it
	 * to the corresponding em_haul_type_t enumeration value.
	 *
	 * @param[in] str The string representation of the haul type.
	 *
	 * @returns The corresponding em_haul_type_t value.
	 * @retval EM_HAUL_TYPE_INVALID if the string does not match any known haul type.
	 *
	 * @note Ensure that the input string is valid and corresponds to a known haul type.
	 */
	static em_haul_type_t haul_type_from_string(em_string_t	str);

    bool operator == (const dm_network_ssid_t& obj);
    void operator = (const dm_network_ssid_t& obj);
    
	/**!
	 * @brief Retrieves the network SSID information.
	 *
	 * This function is responsible for obtaining the SSID information
	 * from the provided network SSID structure.
	 *
	 * @param[in] net_ssid Pointer to the network SSID information structure.
	 *
	 * @returns dm_network_ssid_t The network SSID type.
	 *
	 * @note Ensure that the net_ssid pointer is valid and properly initialized
	 * before calling this function.
	 */
	dm_network_ssid_t(em_network_ssid_info_t *net_ssid);
    
	/**!
	 * @brief Copy constructor for dm_network_ssid_t.
	 *
	 * This constructor initializes a new instance of dm_network_ssid_t by copying the data from an existing instance.
	 *
	 * @param[in] net_ssid The existing dm_network_ssid_t instance to copy from.
	 *
	 * @note This is a deep copy operation.
	 */
	dm_network_ssid_t(const dm_network_ssid_t& net_ssid);
    
	/**!
	 * @brief Constructor for the dm_network_ssid_t class.
	 *
	 * This constructor initializes a new instance of the dm_network_ssid_t class.
	 *
	 * @note This is a default constructor and does not take any parameters.
	 */
	dm_network_ssid_t();
    
	/**!
	 * @brief Destructor for the dm_network_ssid_t class.
	 *
	 * This destructor cleans up any resources allocated by the dm_network_ssid_t instance.
	 *
	 * @note Ensure that all references to the instance are released before destruction.
	 */
	virtual ~dm_network_ssid_t();
};

#endif

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

#ifndef DM_RADIO_H
#define DM_RADIO_H

#include "em_base.h"

class dm_radio_t {
public:
    em_radio_info_t    m_radio_info;

public:
    
	/**!
	 * @brief Initializes the radio information structure.
	 *
	 * This function sets the radio information structure to zero.
	 *
	 * @returns int
	 * @retval 0 on successful initialization.
	 *
	 * @note This function does not take any parameters.
	 */
	int init() { memset(&m_radio_info, 0, sizeof(em_radio_info_t)); return 0; }
    
	/**!
	 * @brief Retrieves the radio information.
	 *
	 * This function returns a pointer to the radio information structure.
	 *
	 * @returns A pointer to the `em_radio_info_t` structure containing the radio information.
	 *
	 * @note Ensure that the returned pointer is not null before accessing its members.
	 */
	em_radio_info_t *get_radio_info() { return &m_radio_info; }
    
    
	/**!
	 * @brief Retrieves the radio interface.
	 *
	 * This function returns a pointer to the radio interface structure.
	 *
	 * @returns A pointer to the em_interface_t structure representing the radio interface.
	 *
	 * @note Ensure that the returned pointer is not null before using it.
	 */
	em_interface_t  *get_radio_interface() { return &m_radio_info.intf; }
    
	/**!
	 * @brief Retrieves the MAC address of the radio interface.
	 *
	 * This function returns the MAC address associated with the radio interface.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 *
	 * @note Ensure that the returned MAC address is valid and properly initialized before use.
	 */
	unsigned char   *get_radio_interface_mac() { return m_radio_info.intf.mac; }
    
	/**!
	 * @brief Retrieves the name of the radio interface.
	 *
	 * This function returns the name of the radio interface as a character pointer.
	 *
	 * @returns A pointer to a character string representing the radio interface name.
	 */
	char *get_radio_interface_name() { return m_radio_info.intf.name; }
    
	/**!
	 * @brief Retrieves the radio ID.
	 *
	 * This function returns the MAC address of the radio interface.
	 *
	 * @returns A pointer to an unsigned char representing the MAC address.
	 *
	 * @note Ensure that the returned pointer is handled appropriately to avoid memory issues.
	 */
	unsigned char *get_radio_id() { return m_radio_info.intf.mac; }
    
	/**!
	 * @brief Decodes a JSON object and associates it with a parent ID.
	 *
	 * This function takes a JSON object and a parent ID, performing the necessary decoding
	 * operations to associate the JSON data with the given parent ID.
	 *
	 * @param[in] obj The JSON object to be decoded.
	 * @param[out] parent_id The parent ID to associate with the decoded JSON object.
	 *
	 * @returns int Status code indicating success or failure of the decoding operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object and parent ID are valid before calling this function.
	 */
	int decode(const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Encodes the given JSON object with a specified reason.
	 *
	 * This function takes a cJSON object and encodes it based on the provided reason.
	 *
	 * @param[in] obj The JSON object to be encoded.
	 * @param[in] reason The reason for encoding, default is em_get_radio_list_reason_none.
	 *
	 * @note Ensure that the cJSON object is properly initialized before calling this function.
	 */
	void encode(cJSON *obj, em_get_radio_list_reason_t reason = em_get_radio_list_reason_none);

    bool operator == (const dm_radio_t& obj);
    void operator = (const dm_radio_t& obj);
    
	/**!
	 * @brief Retrieves the orchestrator type for a given radio.
	 *
	 * This function returns the orchestrator type associated with the specified radio object.
	 *
	 * @param[in] radio The radio object for which the orchestrator type is to be retrieved.
	 *
	 * @returns The orchestrator type of the specified radio.
	 *
	 * @note Ensure that the radio object is properly initialized before calling this function.
	 */
	dm_orch_type_t get_dm_orch_type(const dm_radio_t& radio);
	
	/**!
	 * @brief Parses the radio ID from a given key.
	 *
	 * This function extracts the radio ID from the provided key string and stores it in the specified radio ID variable.
	 *
	 * @param[in] key The key string from which the radio ID is to be parsed.
	 * @param[out] id Pointer to the radio ID variable where the parsed ID will be stored.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure, if the key is invalid or parsing fails.
	 *
	 * @note Ensure that the key is valid and the id pointer is not null before calling this function.
	 */
	int parse_radio_id_from_key(const char *key, em_radio_id_t *id);

	
	/**!
	 * @brief Dumps the current radio information.
	 *
	 * This function retrieves and displays the current state and settings of the radio.
	 *
	 * @note This function does not modify any radio settings.
	 */
	void dump_radio_info();

    
	/**!
	 * @brief Initializes the radio with the provided radio information.
	 *
	 * This function sets up the radio using the information provided in the
	 * em_radio_info_t structure. It prepares the radio for operation.
	 *
	 * @param[in] radio Pointer to an em_radio_info_t structure containing
	 * the radio information to be used for initialization.
	 *
	 * @returns A dm_radio_t object initialized with the provided radio
	 * information.
	 *
	 * @note Ensure that the radio information provided is valid and
	 * properly configured before calling this function.
	 */
	dm_radio_t(em_radio_info_t *radio);
    
	/**!
	 * @brief Copy constructor for dm_radio_t.
	 *
	 * This constructor initializes a new instance of dm_radio_t by copying the state of an existing instance.
	 *
	 * @param[in] radio The dm_radio_t instance to copy.
	 *
	 * @note This is a deep copy constructor.
	 */
	dm_radio_t(const dm_radio_t& radio);
    
	/**!
	 * @brief Constructor for dm_radio_t.
	 *
	 * This function initializes the dm_radio_t object.
	 *
	 * @note This is a default constructor.
	 */
	dm_radio_t();
    
	/**!
	 * @brief Destructor for the dm_radio_t class.
	 *
	 * This function cleans up any resources allocated by the dm_radio_t instance.
	 *
	 * @note This is a virtual destructor, ensuring proper cleanup in derived classes.
	 */
	virtual ~dm_radio_t();
};

#endif

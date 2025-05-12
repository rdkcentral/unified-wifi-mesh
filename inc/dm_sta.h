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

#ifndef DM_STA_H
#define DM_STA_H

#include "em_base.h"

class dm_sta_t {
public:
    em_sta_info_t    m_sta_info;

public:
    
	/**!
	 * @brief Initializes the STA information structure.
	 *
	 * This function sets the STA information structure to zero.
	 *
	 * @returns 0 on successful initialization.
	 */
	int init() { memset(&m_sta_info, 0, sizeof(em_sta_info_t)); return 0; }
    
	/**!
	 * @brief Retrieves the station information.
	 *
	 * This function returns a pointer to the station information structure.
	 *
	 * @returns A pointer to the `em_sta_info_t` structure containing the station information.
	 *
	 * @note Ensure that the returned pointer is not null before accessing its members.
	 */
	em_sta_info_t *get_sta_info() { return &m_sta_info; }
    
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
	 * @brief Encodes the given cJSON object with a specified reason.
	 *
	 * This function takes a cJSON object and encodes it based on the provided reason.
	 *
	 * @param[in] obj The cJSON object to be encoded.
	 * @param[in] reson The reason for encoding, default is em_get_sta_list_reason_none.
	 *
	 * @note Ensure that the cJSON object is properly initialized before calling this function.
	 */
	void encode(cJSON *obj, em_get_sta_list_reason_t reson = em_get_sta_list_reason_none);
	
	/**!
	 * @brief Encodes a beacon report into a JSON object.
	 *
	 * This function takes a cJSON object and encodes the beacon report data into it.
	 *
	 * @param[in] obj Pointer to the cJSON object where the beacon report will be encoded.
	 *
	 * @note Ensure that the cJSON object is properly initialized before calling this function.
	 */
	void encode_beacon_report(cJSON *obj);

    bool operator == (const dm_sta_t& obj);
    void operator = (const dm_sta_t& obj);

    
	/**!
	 * @brief Parses the STA BSS radio information from a given key.
	 *
	 * This function extracts the station (STA), BSSID, and radio MAC addresses
	 * from the provided key string.
	 *
	 * @param[in] key The key string containing the STA BSS radio information.
	 * @param[out] sta The extracted MAC address of the station.
	 * @param[out] bssid The extracted BSSID.
	 * @param[out] radio The extracted MAC address of the radio.
	 *
	 * @note Ensure that the key is correctly formatted to extract valid addresses.
	 */
	static void parse_sta_bss_radio_from_key(const char *key, mac_address_t sta, bssid_t bssid, mac_address_t radio);
    
	/**!
	 * @brief Decodes the capabilities of a station.
	 *
	 * This function processes the capability information of a given station
	 * and updates the relevant fields in the `dm_sta_t` structure.
	 *
	 * @param[in] sta Pointer to the `dm_sta_t` structure representing the station.
	 *
	 * @note Ensure that the `sta` pointer is valid and properly initialized before
	 * calling this function.
	 */
	static void decode_sta_capability(dm_sta_t *sta);
    
	/**!
	 * @brief Decodes the beacon report for the given station.
	 *
	 * This function processes the beacon report data associated with the specified
	 * station object, extracting relevant information for further use.
	 *
	 * @param[in] sta Pointer to the station object containing the beacon report.
	 *
	 * @note Ensure that the station object is properly initialized before calling
	 * this function.
	 */
	static void decode_beacon_report(dm_sta_t *sta);

    
	/**!
	 * @brief Creates a dm_sta_t object using the provided em_sta_info_t.
	 *
	 * This function initializes a dm_sta_t structure with the information
	 * contained in the em_sta_info_t parameter.
	 *
	 * @param[in] sta Pointer to an em_sta_info_t structure containing
	 * the station information.
	 *
	 * @returns A dm_sta_t object initialized with the provided station
	 * information.
	 *
	 * @note Ensure that the em_sta_info_t structure is properly initialized
	 * before calling this function.
	 */
	dm_sta_t(em_sta_info_t *sta);
    
	/**!
	 * @brief Copy constructor for dm_sta_t.
	 *
	 * This constructor initializes a new instance of the dm_sta_t class by copying the state of an existing instance.
	 *
	 * @param[in] sta The dm_sta_t instance to copy from.
	 *
	 * @note This is a deep copy constructor.
	 */
	dm_sta_t(const dm_sta_t& sta);
    
	/**!
	 * @brief Default constructor for the dm_sta_t class.
	 *
	 * This constructor initializes a new instance of the dm_sta_t class.
	 *
	 * @note This constructor does not take any parameters and does not return any values.
	 */
	dm_sta_t();
    
	/**!
	 * @brief Destructor for the dm_sta_t class.
	 *
	 * This destructor cleans up any resources allocated by the dm_sta_t instance.
	 *
	 * @note Ensure that all pointers and dynamic allocations are properly handled before destruction.
	 */
	virtual ~dm_sta_t();
};

#endif

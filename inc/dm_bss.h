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

#ifndef DM_BSS_H
#define DM_BSS_H

#include "em_base.h"
#include "ieee80211.h"

class dm_bss_t {
public:
    em_bss_info_t    m_bss_info;

public:
    
	/**!
	 * @brief Initializes the BSS information structure.
	 *
	 * This function sets the BSS information structure to zero.
	 *
	 * @returns int
	 * @retval 0 on successful initialization.
	 */
	int init() { memset(&m_bss_info, 0, sizeof(em_bss_info_t)); return 0; }
    
	/**!
	 * @brief Retrieves the BSS information.
	 *
	 * This function returns a pointer to the BSS information structure.
	 *
	 * @returns A pointer to the BSS information structure.
	 *
	 * @note Ensure that the returned pointer is not null before accessing its members.
	 */
	em_bss_info_t *get_bss_info() { return &m_bss_info; }
    
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
	 * @brief Encodes a JSON object.
	 *
	 * This function encodes a given JSON object, with an option to provide a summary.
	 *
	 * @param[in] obj The JSON object to be encoded.
	 * @param[in] summary A boolean flag indicating whether to encode in summary mode. Defaults to false.
	 *
	 * @note Ensure that the JSON object is properly initialized before encoding.
	 */
	void encode(cJSON *obj, bool summary = false);

    bool operator == (const dm_bss_t& obj);
    void operator = (const dm_bss_t& obj);

	
	/**!
	 * @brief Matches the given criteria.
	 *
	 * This function checks if the provided criteria string matches certain conditions.
	 *
	 * @param[in] criteria A pointer to a character array containing the criteria to match.
	 *
	 * @returns A boolean value indicating whether the criteria match (true) or not (false).
	 *
	 * @note Ensure that the criteria string is null-terminated.
	 */
	bool match_criteria(char *criteria);
   	
	/**!
	 * @brief Parses the BSS ID from the given key.
	 *
	 * This function extracts the BSS ID from a provided key string and stores it in the specified id structure.
	 *
	 * @param[in] key The key string from which the BSS ID is to be parsed.
	 * @param[out] id Pointer to the em_bss_id_t structure where the parsed BSS ID will be stored.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the key is valid and the id pointer is not null before calling this function.
	 */
	static int parse_bss_id_from_key(const char *key, em_bss_id_t *id);	

    
	/**!
	 * @brief Adds a vendor-specific information element.
	 *
	 * This function is responsible for adding a vendor-specific information element (IE) to the system.
	 *
	 * @param[in] vs_ie Pointer to the vendor-specific information element structure to be added.
	 *
	 * @returns bool
	 * @retval true if the vendor IE was added successfully.
	 * @retval false if there was an error adding the vendor IE.
	 *
	 * @note Ensure that the vs_ie pointer is valid and points to a properly initialized structure before calling this function.
	 */
	bool add_vendor_ie(struct ieee80211_vs_ie *vs_ie);

    
	/**!
	 * @brief Removes a vendor-specific information element.
	 *
	 * This function is responsible for removing a specified vendor-specific
	 * information element from the data structure.
	 *
	 * @param[in] vs_ie Pointer to the vendor-specific information element to be removed.
	 *
	 * @note Ensure that the pointer provided is valid and points to a properly
	 * initialized ieee80211_vs_ie structure.
	 */
	void remove_vendor_ie(struct ieee80211_vs_ie *vs_ie);

    
	/**!
	 * @brief Provides a description of the dm_bss_t function.
	 *
	 * This function is responsible for handling BSS information.
	 *
	 * @param[in] bss A pointer to an em_bss_info_t structure containing BSS information.
	 *
	 * @returns A dm_bss_t type value indicating the result of the operation.
	 *
	 * @note Ensure that the bss pointer is valid and properly initialized before calling this function.
	 */
	dm_bss_t(em_bss_info_t *bss);
    
	/**!
	 * @brief Copy constructor for dm_bss_t.
	 *
	 * This constructor creates a new instance of dm_bss_t by copying the data from an existing instance.
	 *
	 * @param[in] bss The dm_bss_t instance to copy from.
	 *
	 * @note This is a deep copy constructor.
	 */
	dm_bss_t(const dm_bss_t& bss);
    
	/**!
	 * @brief Constructor for dm_bss_t class.
	 *
	 * Initializes a new instance of the dm_bss_t class.
	 *
	 * @note This constructor does not take any parameters.
	 */
	dm_bss_t();
    
	/**!
	 * @brief Destructor for the dm_bss_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the dm_bss_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	virtual ~dm_bss_t();
};

#endif

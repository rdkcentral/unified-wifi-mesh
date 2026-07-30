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

#ifndef DM_SCAN_RESULT_H
#define DM_SCAN_RESULT_H

#include "em_base.h"

class dm_scan_result_t {
public:
    em_scan_result_t    m_scan_result;

public:
    
	/**!
	 * @brief Initializes the scan result structure.
	 *
	 * This function sets the memory of the scan result structure to zero.
	 *
	 * @returns int
	 * @retval 0 on successful initialization.
	 *
	 * @note This function does not take any parameters.
	 */
	int init() { memset(&m_scan_result, 0, sizeof(em_scan_result_t)); return 0; }
    
	/**!
	 * @brief Retrieves the current scan result.
	 *
	 * This function returns a pointer to the current scan result stored in the
	 * `m_scan_result` member.
	 *
	 * @returns A pointer to the `em_scan_result_t` structure containing the
	 * current scan result.
	 */
	em_scan_result_t *get_scan_result() { return &m_scan_result; }
    
	/**!
	 * @brief Decodes a JSON object and associates it with a parent ID.
	 *
	 * This function takes a JSON object and decodes it, associating the result
	 * with a given parent ID. It is used to process JSON data structures.
	 *
	 * @param[in] obj The JSON object to decode.
	 * @param[out] parent_id The ID of the parent to associate with the decoded data.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the JSON object is valid before calling this function.
	 */
	int decode(const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Encodes the given cJSON object.
	 *
	 * This function takes a cJSON object and performs encoding operations on it.
	 *
	 * @param[in] obj The cJSON object to be encoded.
	 *
	 * @note Ensure that the cJSON object is properly initialized before calling this function.
	 */
	void encode(cJSON *obj);

    bool operator == (const dm_scan_result_t& obj);
    void operator = (const dm_scan_result_t& obj);

	
	/**!
	 * @brief Parses the scan result ID from the given key.
	 *
	 * This function extracts the scan result ID from the provided key string.
	 *
	 * @param[in] key The key string from which the scan result ID is to be parsed.
	 * @param[out] id Pointer to the variable where the parsed scan result ID will be stored.
	 * @param[out] bssid Optional pointer to store the BSSID if provided.
	 *
	 * @returns int Returns 0 on success, or a negative error code on failure.
	 * @retval 0 Success.
	 * @retval <0 Error code indicating the type of failure.
	 *
	 * @note If the BSSID is not required, the default value of NULL can be used.
	 */
	static int parse_scan_result_id_from_key(const char *key, em_scan_result_id_t *id, unsigned char *bssid = NULL);
	
	/**!
	 * @brief Checks if the given scan result ID matches a predefined ID.
	 *
	 * This function compares the provided scan result ID with a predefined
	 * ID to determine if they are the same.
	 *
	 * @param[in] id Pointer to the scan result ID to be checked.
	 *
	 * @returns True if the IDs match, false otherwise.
	 *
	 * @note Ensure that the pointer provided is valid and points to a properly
	 * initialized scan result ID.
	 */
	bool has_same_id(em_scan_result_id_t *);

    
	/**!
	 * @brief Processes the scan result and returns a dm_scan_result_t object.
	 *
	 * This function takes an em_scan_result_t object as input and processes it to
	 * produce a dm_scan_result_t object. The processing involves extracting relevant
	 * data from the scan result and converting it into a format suitable for further
	 * use within the system.
	 *
	 * @param[in] scan_result Pointer to an em_scan_result_t object containing the scan data.
	 *
	 * @returns A dm_scan_result_t object containing the processed scan data.
	 *
	 * @note Ensure that the scan_result pointer is valid and points to a properly
	 * initialized em_scan_result_t object before calling this function.
	 */
	dm_scan_result_t(em_scan_result_t *scan_result);
    
	/**!
	 * @brief Copy constructor for dm_scan_result_t.
	 *
	 * This constructor initializes a new instance of the dm_scan_result_t class by copying an existing instance.
	 *
	 * @param[in] scan_result The dm_scan_result_t instance to copy from.
	 *
	 * @note This is a deep copy constructor.
	 */
	dm_scan_result_t(const dm_scan_result_t& scan_result);
    
	/**!
	 * @brief Constructor for dm_scan_result_t
	 *
	 * This constructor initializes a dm_scan_result_t object using an
	 * em_scan_result_t object.
	 *
	 * @param[in] scan_result The em_scan_result_t object to initialize from.
	 */
	dm_scan_result_t(const em_scan_result_t& scan_result);
    
	/**!
	* @brief Default constructor for the dm_scan_result_t class.
	*
	* This constructor initializes a new instance of the dm_scan_result_t class.
	*
	* @note This constructor does not take any parameters and does not perform any specific initialization.
	*/
	dm_scan_result_t();
    
	/**!
	 * @brief Destructor for the dm_scan_result_t class.
	 *
	 * This destructor cleans up any resources allocated by the dm_scan_result_t instance.
	 *
	 * @note Ensure that all pointers and dynamic allocations are properly managed before destruction.
	 */
	virtual ~dm_scan_result_t();
};

#endif

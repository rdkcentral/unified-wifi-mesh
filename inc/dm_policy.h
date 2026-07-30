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

#ifndef DM_POLICY_H
#define DM_POLICY_H

#include "em_base.h"

class dm_policy_t {
public:
    em_policy_t    m_policy;

public:
    
	/**!
	* @brief Initializes the policy structure.
	*
	* This function sets the policy structure to zero.
	*
	* @returns int
	* @retval 0 on success
	*
	* @note This function does not take any parameters and always returns 0.
	*/
	int init() { memset(&m_policy, 0, sizeof(em_policy_t)); return 0; }
    
	/**!
	 * @brief Retrieves the current policy.
	 *
	 * @returns A pointer to the current policy.
	 */
	em_policy_t *get_policy() { return &m_policy; }
    
	/**!
	 * @brief Decodes a JSON object to extract policy information.
	 *
	 * This function takes a JSON object and decodes it to retrieve the policy
	 * information, storing it in the provided parent ID. The policy type can
	 * be specified, defaulting to unknown if not provided.
	 *
	 * @param[in] obj The JSON object to decode.
	 * @param[out] parent_id The ID where the decoded policy information will be stored.
	 * @param[in] plicy The type of policy to decode, defaults to em_policy_id_type_unknown.
	 *
	 * @returns int Status code indicating success or failure of the decode operation.
	 *
	 * @note Ensure that the JSON object is properly formatted to contain policy information.
	 */
	int decode(const cJSON *obj, void *parent_id, em_policy_id_type_t plicy = em_policy_id_type_unknown);
    
	/**!
	 * @brief Encodes the given JSON object with the specified policy ID.
	 *
	 * This function takes a JSON object and a policy ID, and encodes the object
	 * according to the rules defined by the policy.
	 *
	 * @param[in] obj The JSON object to be encoded.
	 * @param[in] id The policy ID used for encoding.
	 *
	 * @note Ensure that the JSON object is properly initialized before calling this function.
	 */
	void encode(cJSON *obj, em_policy_id_type_t id);

    bool operator == (const dm_policy_t& obj);
    void operator = (const dm_policy_t& obj);

	
	/**!
	 * @brief Parses the device radio MAC address from the given key.
	 *
	 * This function extracts the MAC address associated with a device radio from
	 * the provided key and stores it in the specified policy ID structure.
	 *
	 * @param[in] key The key from which the MAC address is to be parsed.
	 * @param[out] id Pointer to the policy ID structure where the parsed MAC address will be stored.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the key is valid and the id pointer is not null before calling this function.
	 */
	static int parse_dev_radio_mac_from_key(const char *key, em_policy_id_t *id);

    
	/**!
	 * @brief 
	 *
	 * This function initializes a dm_policy_t object using the provided em_policy_t object.
	 *
	 * @param[in] policy A pointer to an em_policy_t object that will be used to initialize the dm_policy_t.
	 *
	 * @returns A dm_policy_t object initialized with the given em_policy_t.
	 *
	 * @note Ensure that the policy pointer is valid and properly initialized before calling this function.
	 */
	dm_policy_t(em_policy_t *policy);
    
	/**!
	 * @brief Copy constructor for dm_policy_t.
	 *
	 * This constructor initializes a new instance of dm_policy_t by copying the values from an existing policy.
	 *
	 * @param[in] policy The dm_policy_t instance to copy from.
	 */
	dm_policy_t(const dm_policy_t& policy);
    
	/**!
	 * @brief Constructor for dm_policy_t
	 *
	 * This constructor initializes a dm_policy_t object using an existing em_policy_t object.
	 *
	 * @param[in] policy The em_policy_t object to initialize from.
	 */
	dm_policy_t(const em_policy_t& policy);
    
	/**!
	 * @brief Constructor for the dm_policy_t class.
	 *
	 * This constructor initializes a new instance of the dm_policy_t class.
	 *
	 * @note This is a default constructor and does not take any parameters.
	 */
	dm_policy_t();
    
	/**!
	 * @brief Destructor for dm_policy_t class.
	 *
	 * This function cleans up any resources allocated by the dm_policy_t instance.
	 *
	 * @note This is a virtual destructor.
	 */
	virtual ~dm_policy_t();
};

#endif

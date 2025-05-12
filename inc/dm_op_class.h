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

#ifndef DM_OP_CLASS_H
#define DM_OP_CLASS_H

#include "em_base.h"

class dm_op_class_t {
public:
    em_op_class_info_t    m_op_class_info;

public:
    
	/**!
	 * @brief Initializes the operation class information structure.
	 *
	 * This function sets the memory of the operation class information structure to zero.
	 *
	 * @returns int
	 * @retval 0 on successful initialization.
	 *
	 * @note This function does not take any parameters.
	 */
	int init() { memset(&m_op_class_info, 0, sizeof(em_op_class_info_t)); return 0; }
    
	/**!
	 * @brief Retrieves the operation class information.
	 *
	 * This function returns a pointer to the operation class information structure.
	 *
	 * @returns A pointer to the `em_op_class_info_t` structure containing the operation class information.
	 *
	 * @note Ensure that the returned pointer is not null before accessing the structure members.
	 */
	em_op_class_info_t *get_op_class_info() { return &m_op_class_info; }
    
	/**!
	* @brief Decodes a JSON object and associates it with a parent identifier.
	*
	* This function takes a JSON object and decodes it, linking it to a specified parent identifier.
	*
	* @param[in] obj A pointer to the cJSON object to be decoded.
	* @param[out] parent_id A pointer to the parent identifier where the decoded data will be stored.
	*
	* @returns int
	* @retval 0 on success
	* @retval -1 on failure
	*
	* @note Ensure that the cJSON object is properly initialized before calling this function.
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

    bool operator == (const dm_op_class_t& obj);
    void operator = (const dm_op_class_t& obj);

    
	/**!
	 * @brief Parses the operation class ID from a given key.
	 *
	 * This function extracts the operation class ID from the provided key string
	 * and stores it in the specified output parameter.
	 *
	 * @param[in] key The key string from which the operation class ID is to be parsed.
	 * @param[out] id Pointer to the variable where the parsed operation class ID will be stored.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval non-zero error code on failure.
	 *
	 * @note Ensure that the key is valid and the id pointer is not null before calling this function.
	 */
	static int parse_op_class_id_from_key(const char *key, em_op_class_id_t *id);

    
	/**!
	* @brief Constructor for the dm_op_class_t class.
	*
	* This function initializes a dm_op_class_t object using the provided op_class information.
	*
	* @param[in] op_class Pointer to an em_op_class_info_t structure containing the operation class information.
	*/
	dm_op_class_t(em_op_class_info_t *op_class);
    
	/**!
	 * @brief Copy constructor for dm_op_class_t.
	 *
	 * This constructor creates a new instance of dm_op_class_t by copying the contents
	 * of another dm_op_class_t object.
	 *
	 * @param[in] op_class The dm_op_class_t object to be copied.
	 *
	 * @note This is a deep copy constructor.
	 */
	dm_op_class_t(const dm_op_class_t& op_class);
    
	/**!
	 * @brief Constructor for dm_op_class_t.
	 *
	 * Initializes a dm_op_class_t object using the provided op_class_info.
	 *
	 * @param[in] op_class_info The operation class information used for initialization.
	 */
	dm_op_class_t(const em_op_class_info_t& op_class_info);
    
	/**!
	 * @brief Constructor for dm_op_class_t.
	 *
	 * Initializes a new instance of the dm_op_class_t class.
	 *
	 * @note This constructor does not take any parameters.
	 */
	dm_op_class_t();
    
	/**!
	 * @brief Destructor for the dm_op_class_t class.
	 *
	 * This function is responsible for cleaning up resources used by the dm_op_class_t instance.
	 *
	 * @note Ensure that all dynamically allocated resources are properly released.
	 */
	~dm_op_class_t();
};

#endif

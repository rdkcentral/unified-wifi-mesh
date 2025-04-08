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

#ifndef DM_SSID_2_VID_MAP_H
#define DM_SSID_2_VID_MAP_H

#include "em_base.h"
#include "db_easy_mesh.h"

class dm_ssid_2_vid_map_t : public db_easy_mesh_t {
    em_ssid_2_vid_map_info_t    m_ssid_2_vid_map_info;
    hash_map_t  *m_list;

public:
    
	/**!
	 * @brief Initializes the system or component.
	 *
	 * This function is responsible for setting up the necessary environment
	 * or state required for the system or component to function correctly.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note Ensure that this function is called before any other operations
	 * are performed on the system or component.
	 */
	int init();

    
	/**!
	 * @brief Retrieves the SSID to VID map information.
	 *
	 * This function returns a pointer to the internal data structure
	 * that holds the mapping information between SSID and VID.
	 *
	 * @returns A pointer to the `em_ssid_2_vid_map_info_t` structure.
	 *
	 * @note Ensure that the returned pointer is not modified directly.
	 */
	em_ssid_2_vid_map_info_t *get_ssid_2_vid_map_info() { return &m_ssid_2_vid_map_info; }
    
	/**!
	 * @brief Retrieves the first element from the hash map.
	 *
	 * This function returns the first element in the hash map, which is of type `dm_ssid_2_vid_map_t`.
	 *
	 * @returns A pointer to the first `dm_ssid_2_vid_map_t` element in the hash map.
	 * @retval NULL if the hash map is empty.
	 *
	 * @note Ensure that the hash map is not empty before calling this function to avoid null pointer dereference.
	 */
	dm_ssid_2_vid_map_t *get_first() { return (dm_ssid_2_vid_map_t *)hash_map_get_first(m_list); }
    
	/**!
	 * @brief Retrieves the next element in the SSID to VID map.
	 *
	 * This function returns the next element in the SSID to VID map, allowing iteration over the map.
	 *
	 * @param[in] ssid_2_vid Pointer to the current element in the SSID to VID map.
	 *
	 * @returns Pointer to the next element in the SSID to VID map.
	 * @retval NULL if there are no more elements in the map.
	 *
	 * @note Ensure that the map is not modified during iteration.
	 */
	dm_ssid_2_vid_map_t *get_next(dm_ssid_2_vid_map_t *ssid_2_vid) { return (dm_ssid_2_vid_map_t *)hash_map_get_next(m_list, ssid_2_vid); }
    
	/**!
	 * @brief Updates the list with the given SSID to VID mapping.
	 *
	 * This function takes a mapping of SSID to VID and updates the internal list
	 * accordingly.
	 *
	 * @param[in] ssid_2_vid The SSID to VID mapping to be updated in the list.
	 *
	 * @returns dm_orch_type_t The type indicating the result of the update operation.
	 *
	 * @note Ensure that the mapping provided is valid and conforms to expected formats.
	 */
	dm_orch_type_t update_list(const dm_ssid_2_vid_map_t& ssid_2_vid);

    
	/**!
	 * @brief Initializes the SSID to VID mapping table.
	 *
	 * This function sets up the necessary data structures and state for the
	 * SSID to VID mapping table to be used.
	 *
	 * @note This function must be called before any other operations on the
	 * mapping table are performed.
	 */
	void init_table();
    
	/**!
	 * @brief Initializes the columns for the SSID to VID mapping.
	 *
	 * This function sets up the necessary data structures or state required
	 * for managing the mapping between SSIDs and VIDs.
	 *
	 * @note This function should be called before any operations that
	 * require SSID to VID mapping.
	 */
	void init_columns();
    
	/**!
	 * @brief Synchronizes the database using the provided database client and context.
	 *
	 * This function attempts to synchronize the database by utilizing the given
	 * database client and context. It ensures that the database state is consistent
	 * with the expected values.
	 *
	 * @param[in] db_client Reference to the database client used for synchronization.
	 * @param[in] ctx Pointer to the context information required for synchronization.
	 *
	 * @returns int Status code indicating the success or failure of the synchronization.
	 * @retval 0 Indicates successful synchronization.
	 * @retval -1 Indicates failure during synchronization.
	 *
	 * @note Ensure that the database client is properly initialized before calling
	 * this function.
	 */
	int sync_db(db_client_t& db_client, void *ctx);
    
	/**!
	 * @brief Updates the database with the given operation and data.
	 *
	 * This function performs the specified operation on the database using the provided data.
	 *
	 * @param[in] db_client Reference to the database client used for the operation.
	 * @param[in] op The operation type to be performed on the database.
	 * @param[in] data Pointer to the data used for the operation.
	 *
	 * @returns int Status code indicating the success or failure of the operation.
	 * @retval 0 Operation was successful.
	 * @retval -1 Operation failed due to invalid parameters.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int update_db(db_client_t& db_client, dm_orch_type_t op, void *data);
    
	/**!
	 * @brief Searches the database using the provided key.
	 *
	 * This function attempts to find an entry in the database using the specified key.
	 *
	 * @param[in] db_client Reference to the database client used for the search operation.
	 * @param[in] ctx Contextual information required for the search.
	 * @param[in] key Pointer to the key used for searching the database.
	 *
	 * @returns True if the key is found in the database, false otherwise.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	bool search_db(db_client_t& db_client, void *ctx, void *key);
    bool operator == (const db_easy_mesh_t& obj);
    
	/**!
	 * @brief Sets the configuration using the provided JSON object.
	 *
	 * This function updates the configuration in the database client using the JSON object provided.
	 *
	 * @param[in] db_client Reference to the database client object.
	 * @param[in] obj Pointer to the cJSON object containing configuration data.
	 * @param[out] parent_id Pointer to the parent ID where the configuration is applied.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object is properly formatted before calling this function.
	 */
	int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Retrieves the configuration details from a JSON object.
	 *
	 * This function extracts configuration information from the provided JSON object and associates it with a parent identifier. It can optionally provide a summary of the configuration.
	 *
	 * @param[in] obj The JSON object containing configuration data.
	 * @param[in] parent_id A pointer to the parent identifier to associate with the configuration.
	 * @param[in] summary A boolean flag indicating whether to return a summary of the configuration. Defaults to false.
	 *
	 * @returns An integer status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the JSON object and parent identifier are valid before calling this function.
	 */
	int get_config(cJSON *obj, void *parent_id, bool summary = false);

    
	/**!
	 * @brief Maps SSID to VID.
	 *
	 * This function takes a pointer to an SSID to VID mapping information structure
	 * and performs the mapping operation.
	 *
	 * @param[in] ssid_2_vid Pointer to the SSID to VID mapping information structure.
	 *
	 * @returns dm_ssid_2_vid_map_t The result of the mapping operation.
	 *
	 * @note Ensure that the input structure is properly initialized before calling this function.
	 */
	dm_ssid_2_vid_map_t(em_ssid_2_vid_map_info_t *ssid_2_vid);
    
	/**!
	 * @brief Copy constructor for dm_ssid_2_vid_map_t.
	 *
	 * This constructor initializes a new instance of the dm_ssid_2_vid_map_t class
	 * by copying the data from an existing instance.
	 *
	 * @param[in] ssid_2_vid The instance of dm_ssid_2_vid_map_t to copy from.
	 *
	 * @note This is a deep copy constructor.
	 */
	dm_ssid_2_vid_map_t(const dm_ssid_2_vid_map_t& ssid_2_vid);
    
	/**!
	 * @brief Constructor for dm_ssid_2_vid_map_t class.
	 *
	 * This constructor initializes the dm_ssid_2_vid_map_t object.
	 *
	 * @note This is a default constructor.
	 */
	dm_ssid_2_vid_map_t();
    
	/**!
	 * @brief Destructor for the dm_ssid_2_vid_map_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the dm_ssid_2_vid_map_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	~dm_ssid_2_vid_map_t();
};

#endif

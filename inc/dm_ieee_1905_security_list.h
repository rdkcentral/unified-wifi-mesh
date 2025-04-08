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

#ifndef DM_IEEE_1905_SECURITY_LIST_H
#define DM_IEEE_1905_SECURITY_LIST_H

#include "em_base.h"
#include "dm_ieee_1905_security.h"
#include "db_easy_mesh.h"

class dm_easy_mesh_t;
class dm_ieee_1905_security_list_t : public dm_ieee_1905_security_t, public db_easy_mesh_t {
    hash_map_t  *m_list;

public:
    
	/**!
	 * @brief Initializes the IEEE 1905 security list.
	 *
	 * This function sets up the necessary structures and configurations
	 * required for the IEEE 1905 security list to operate.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that all prerequisites are met before calling this function.
	 */
	int init();

    
	/**!
	 * @brief Retrieves the IEEE 1905 security information.
	 *
	 * @returns A pointer to the `em_ieee_1905_security_info_t` structure containing the security information.
	 *
	 * @note This function returns a pointer to an internal structure, ensure that the data is not modified externally.
	 */
	em_ieee_1905_security_info_t *get_ieee_1905_security_info() { return &m_ieee_1905_security_info; }
    
	/**!
	 * @brief Retrieves the first security element from the list.
	 *
	 * This function returns the first element in the security list, casting it to the appropriate type.
	 *
	 * @returns A pointer to the first `dm_ieee_1905_security_t` element in the list.
	 * @retval nullptr if the list is empty.
	 *
	 * @note Ensure the list is not empty before calling this function to avoid null pointer dereference.
	 */
	dm_ieee_1905_security_t *get_first() { return static_cast<dm_ieee_1905_security_t *>(hash_map_get_first(m_list)); }
    
	/**!
	 * @brief Retrieves the next security entry in the list.
	 *
	 * This function returns the next security entry in the IEEE 1905 security list
	 * based on the provided current entry.
	 *
	 * @param[in] net_ssid Pointer to the current security entry in the list.
	 *
	 * @returns Pointer to the next security entry in the list.
	 * @retval nullptr if there are no more entries.
	 *
	 * @note Ensure that the provided net_ssid is a valid entry in the list.
	 */
	dm_ieee_1905_security_t *get_next(dm_ieee_1905_security_t *net_ssid) { return static_cast<dm_ieee_1905_security_t *>(hash_map_get_next(m_list, net_ssid)); }
    
	/**!
	 * @brief Retrieves the DM orchestration type based on the provided database client and security settings.
	 *
	 * This function determines the appropriate DM orchestration type by analyzing the given database client and
	 * security configuration.
	 *
	 * @param[in] db_client Reference to the database client used for retrieving orchestration information.
	 * @param[in] security Reference to the IEEE 1905 security settings used in the determination process.
	 *
	 * @returns The determined DM orchestration type.
	 */
	dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_ieee_1905_security_t& security);
    
	/**!
	 * @brief Updates the security list with the given security object and operation type.
	 *
	 * This function modifies the security list based on the provided security object
	 * and the specified operation type.
	 *
	 * @param[in] security The security object to be used for updating the list.
	 * @param[in] op The operation type indicating how the list should be updated.
	 *
	 * @note Ensure that the security object and operation type are valid before calling this function.
	 */
	void update_list(const dm_ieee_1905_security_t& security, dm_orch_type_t op);
    
	/**!
	 * @brief Deletes the security list.
	 *
	 * This function removes all entries from the security list, effectively clearing it.
	 *
	 * @note Ensure that no operations are pending on the list before calling this function.
	 */
	void delete_list();

    
	/**!
	 * @brief Initializes the security table.
	 *
	 * This function sets up the necessary data structures and initializes the security table for use.
	 *
	 * @note Ensure that the table is properly configured before calling this function.
	 */
	void init_table();
    
	/**!
	 * @brief Initializes the columns for the IEEE 1905 security list.
	 *
	 * This function sets up the necessary columns required for managing
	 * the security list in the IEEE 1905 protocol.
	 *
	 * @note Ensure that the security list is properly configured before
	 * calling this function.
	 */
	void init_columns();
    
	/**!
	 * @brief Synchronize the database with the given client and context.
	 *
	 * This function synchronizes the database using the provided database client and context.
	 *
	 * @param[in] db_client Reference to the database client used for synchronization.
	 * @param[in] ctx Pointer to the context used during synchronization.
	 *
	 * @returns int Status code indicating success or failure of the synchronization.
	 * @retval 0 Synchronization was successful.
	 * @retval -1 Synchronization failed due to an error.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int sync_db(db_client_t& db_client, void *ctx);
    
	/**!
	 * @brief Updates the database with the given operation type and data.
	 *
	 * This function performs an update on the database using the specified operation type and data.
	 *
	 * @param[in,out] db_client Reference to the database client used for the update operation.
	 * @param[in] op The operation type to be performed on the database.
	 * @param[in] data Pointer to the data to be used in the update operation.
	 *
	 * @returns int Status code of the update operation.
	 * @retval 0 on success.
	 * @retval non-zero on failure.
	 *
	 * @note Ensure that the db_client is properly initialized before calling this function.
	 */
	int update_db(db_client_t& db_client, dm_orch_type_t op, void *data);
    
	/**!
	 * @brief Searches the database using the provided key.
	 *
	 * This function attempts to find an entry in the database that matches the given key.
	 *
	 * @param[in] db_client Reference to the database client used for the search operation.
	 * @param[in] ctx Contextual information required for the search.
	 * @param[in] key Pointer to the key used for searching the database.
	 *
	 * @returns True if the entry is found, false otherwise.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	bool search_db(db_client_t& db_client, void *ctx, void *key);
    bool operator == (const db_easy_mesh_t& obj);
    
	/**!
	 * @brief Sets the configuration using the provided JSON object.
	 *
	 * This function updates the configuration in the database client using the
	 * JSON object provided. The parent ID is used to associate the configuration
	 * with a specific parent entity.
	 *
	 * @param[in] db_client Reference to the database client where the configuration
	 * will be set.
	 * @param[in] obj Pointer to a cJSON object containing the configuration data.
	 * @param[in] parent_id Pointer to the parent ID associated with the configuration.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Success
	 * @retval -1 Failure
	 *
	 * @note Ensure that the JSON object is properly formatted and the database client
	 * is initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Retrieves the configuration details.
	 *
	 * This function fetches the configuration details and populates the provided JSON object.
	 *
	 * @param[out] obj A pointer to a cJSON object where the configuration details will be stored.
	 * @param[in] parent_id A pointer to the parent identifier used for fetching specific configuration details.
	 * @param[in] summary A boolean flag indicating whether to fetch a summary of the configuration.
	 *
	 * @returns An integer status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the cJSON object is properly initialized before calling this function.
	 */
	int get_config(cJSON *obj, void *parent_id, bool summary = false);

};

#endif

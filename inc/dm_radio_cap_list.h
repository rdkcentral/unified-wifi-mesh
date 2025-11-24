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

#ifndef DM_RADIO_CAP_LIST_H
#define DM_RADIO_CAP_LIST_H

#include "em_base.h"
#include "dm_radio_cap.h"
#include "db_easy_mesh.h"
#include "tr_181.h"

class dm_easy_mesh_t;
class dm_radio_cap_list_t : public dm_radio_cap_t, public db_easy_mesh_t, virtual public tr_181_t {
    hash_map_t  *m_list;

public:
    
	/**!
	 * @brief Initializes the radio capability list.
	 *
	 * This function sets up the necessary structures and state for managing
	 * the radio capability list.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the system is in the correct state before calling this function.
	 */
	int init();

    
	/**!
	 * @brief Retrieves the first radio capability from the list.
	 *
	 * This function returns the first element in the radio capability list.
	 *
	 * @returns A pointer to the first `dm_radio_cap_t` element in the list.
	 * @retval nullptr if the list is empty.
	 *
	 * @note Ensure the list is not empty before calling this function to avoid null pointer dereference.
	 */
	dm_radio_cap_t *get_first() { return static_cast<dm_radio_cap_t *>(hash_map_get_first(m_list)); }
    
	/**!
	 * @brief Retrieves the next radio capability from the list.
	 *
	 * This function returns the next radio capability in the list after the given radio capability.
	 *
	 * @param[in] radio_cap A pointer to the current radio capability.
	 *
	 * @returns A pointer to the next radio capability in the list.
	 * @retval nullptr If there are no more radio capabilities in the list.
	 *
	 * @note Ensure that the provided radio_cap is valid and part of the list.
	 */
	dm_radio_cap_t  *get_next(dm_radio_cap_t *radio_cap) { return static_cast<dm_radio_cap_t *>(hash_map_get_next(m_list, radio_cap)); }

    
	/**!
	 * @brief Retrieves the DM orchestration type based on the provided database client and radio capabilities.
	 *
	 * @param[in] db_client Reference to the database client used for querying.
	 * @param[in] radio_cap Reference to the radio capabilities structure.
	 *
	 * @returns The DM orchestration type.
	 */
	dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_radio_cap_t& radio_cap);
    
	/**!
	 * @brief Updates the radio capability list with the given operation type.
	 *
	 * This function modifies the list of radio capabilities based on the specified operation type.
	 *
	 * @param[in] radio_cap The radio capability to be updated in the list.
	 * @param[in] op The operation type to be applied to the radio capability list.
	 *
	 * @note Ensure that the radio capability and operation type are valid before calling this function.
	 */
	void update_list(const dm_radio_cap_t& radio_cap, dm_orch_type_t op);
    
	/**!
	 * @brief Deletes the radio capability list.
	 *
	 * This function removes all entries from the radio capability list.
	 *
	 * @note Ensure that the list is initialized before calling this function.
	 */
	void delete_list();

    
	/**!
	 * @brief Initializes the radio capability list table.
	 *
	 * This function sets up the necessary data structures and state for managing
	 * the radio capability list.
	 *
	 * @note This function should be called before any operations on the radio
	 * capability list are performed.
	 */
	void init_table();
    
	/**!
	 * @brief Initializes the columns for the radio capability list.
	 *
	 * This function sets up the necessary columns required for managing
	 * the radio capabilities within the list.
	 *
	 * @note Ensure that the list is properly initialized before calling
	 * this function.
	 */
	void init_columns();
    
	/**!
	 * @brief Synchronizes the database with the given client and context.
	 *
	 * This function is responsible for ensuring that the database state is
	 * consistent with the provided client and context information.
	 *
	 * @param[in] db_client Reference to the database client to be synchronized.
	 * @param[in] ctx Pointer to the context information required for synchronization.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval non-zero error code on failure.
	 *
	 * @note Ensure that the database client is properly initialized before calling
	 * this function.
	 */
	int sync_db(db_client_t& db_client, void *ctx);
    
	/**!
	 * @brief Updates the database with the specified operation and data.
	 *
	 * This function performs a database update operation using the provided database client, operation type, and data.
	 *
	 * @param[in,out] db_client Reference to the database client used for the update operation.
	 * @param[in] op The operation type to be performed on the database.
	 * @param[in] data Pointer to the data to be used in the update operation.
	 *
	 * @returns int Status code indicating the success or failure of the update operation.
	 * @retval 0 Operation was successful.
	 * @retval non-zero An error occurred during the update operation.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int update_db(db_client_t& db_client, dm_orch_type_t op, void *data);
    
	/**!
	 * @brief Searches the database using the provided key.
	 *
	 * This function attempts to locate an entry in the database using the specified key.
	 *
	 * @param[in] db_client Reference to the database client used for the search operation.
	 * @param[in] ctx Context information for the search operation.
	 * @param[in] key Key used to search the database.
	 *
	 * @returns True if the search is successful, false otherwise.
	 */
	bool search_db(db_client_t& db_client, void *ctx, void *key);
    bool operator == (const db_easy_mesh_t& obj);
    
	/**!
	 * @brief Sets the configuration using the provided JSON object.
	 *
	 * This function updates the configuration settings in the database client
	 * using the JSON object provided. The parent ID is used to specify the
	 * hierarchical context within the configuration.
	 *
	 * @param[in] db_client Reference to the database client where the configuration
	 * will be set.
	 * @param[in] obj Pointer to a cJSON object containing the configuration data.
	 * @param[in] parent_id Pointer to the parent ID used for hierarchical context.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note Ensure that the JSON object is properly formatted and that the database
	 * client is initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Retrieves the configuration settings from a JSON object.
	 *
	 * This function extracts configuration details from the provided JSON object and associates them with a parent identifier. Optionally, a summary can be requested.
	 *
	 * @param[in] obj The JSON object containing configuration data.
	 * @param[in] parent_id A pointer to the parent identifier to associate with the configuration.
	 * @param[in] summary A boolean flag indicating whether to retrieve a summary of the configuration.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 *
	 * @note Ensure that the JSON object is properly formatted and contains the expected configuration fields.
	 */
	int get_config(cJSON *obj, void *parent_id, bool summary = false);

};

#endif

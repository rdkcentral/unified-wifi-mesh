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

#ifndef DM_RADIO_LIST_H
#define DM_RADIO_LIST_H

#include "em_base.h"
#include "dm_radio.h"
#include "db_easy_mesh.h"
#include "tr_181.h"

class dm_easy_mesh_t;
class dm_radio_list_t : public dm_radio_t, public db_easy_mesh_t, virtual public tr_181_t {

public:
    
	/**!
	 * @brief Initializes the radio list module.
	 *
	 * This function sets up the necessary resources and configurations
	 * required for the radio list module to operate.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that this function is called before any other
	 * radio list operations.
	 */
	int init();


    
	/**!
	 * @brief Retrieves the DM orchestration type for a given radio.
	 *
	 * This function queries the database client to determine the orchestration type
	 * associated with the specified radio.
	 *
	 * @param[in] db_client Reference to the database client used for querying.
	 * @param[in] radio The radio for which the orchestration type is to be retrieved.
	 *
	 * @returns The DM orchestration type associated with the specified radio.
	 */
	dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_radio_t& radio);
    
	/**!
	 * @brief Updates the radio list with the specified operation type.
	 *
	 * This function modifies the radio list based on the operation type provided.
	 *
	 * @param[in] radio The radio object to be updated in the list.
	 * @param[in] op The operation type to be performed on the radio list.
	 *
	 * @note Ensure that the radio object and operation type are valid before calling this function.
	 */
	void update_list(const dm_radio_t& radio, dm_orch_type_t op);
    
	/**!
	* @brief Deletes the radio list.
	*
	* This function is responsible for removing all entries from the radio list.
	*
	* @note Ensure that the list is not in use before calling this function to avoid undefined behavior.
	*/
	void delete_list();

    
	/**!
	* @brief Initializes the radio list table.
	*
	* This function sets up the necessary data structures and state for the radio list table.
	*
	* @note This function should be called before any operations on the radio list table.
	*/
	void init_table();
    
	/**!
	 * @brief Initializes the columns for the radio list.
	 *
	 * This function sets up the necessary columns required for displaying
	 * the radio list in the user interface.
	 *
	 * @note Ensure that the radio list is properly initialized before
	 * calling this function.
	 */
	void init_columns();
    
	/**!
	 * @brief Synchronizes the database with the given client and context.
	 *
	 * This function is responsible for ensuring that the database is in sync
	 * with the provided client and context. It performs necessary operations
	 * to achieve synchronization.
	 *
	 * @param[in] db_client Reference to the database client to be synchronized.
	 * @param[in] ctx Pointer to the context used during synchronization.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the database client is properly initialized before
	 * calling this function.
	 */
	int sync_db(db_client_t& db_client, void *ctx);
    
	/**!
	 * @brief Updates the database with the specified operation and data.
	 *
	 * This function performs a database update operation using the provided database client,
	 * operation type, and data. It modifies the database state based on the operation type.
	 *
	 * @param[in] db_client Reference to the database client used for the update operation.
	 * @param[in] op The type of operation to be performed on the database.
	 * @param[in] data Pointer to the data required for the update operation.
	 *
	 * @returns int Status code indicating the success or failure of the operation.
	 * @retval 0 Operation was successful.
	 * @retval -1 Operation failed due to invalid parameters or database errors.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int update_db(db_client_t& db_client, dm_orch_type_t op, void *data);
    
	/**!
	 * @brief Searches the database using the provided key.
	 *
	 * This function performs a search operation on the database using the given key and context.
	 *
	 * @param[in] db_client Reference to the database client used for the search operation.
	 * @param[in] ctx Pointer to the context information required for the search.
	 * @param[in] key Pointer to the key used for searching in the database.
	 *
	 * @returns bool
	 * @retval true if the search is successful and the key is found.
	 * @retval false if the search fails or the key is not found.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	bool search_db(db_client_t& db_client, void *ctx, void *key);
    bool operator == (const db_easy_mesh_t& obj);
    
	/**!
	 * @brief Sets the configuration using the provided JSON object.
	 *
	 * This function updates the configuration settings in the database client
	 * using the JSON object provided. The parent ID is used to specify the
	 * hierarchy or context within which the configuration is applied.
	 *
	 * @param[in] db_client Reference to the database client where the configuration
	 * is to be set.
	 * @param[in] obj Pointer to a cJSON object containing the configuration data.
	 * @param[in] parent_id Pointer to the parent ID used for hierarchical context.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Success
	 * @retval -1 Failure
	 *
	 * @note Ensure that the JSON object is properly formatted and that the database
	 * client is initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Sets the configuration for the specified radio.
	 *
	 * This function configures the radio settings using the provided database client and radio object.
	 *
	 * @param[in] db_client Reference to the database client used for configuration.
	 * @param[in] radio Reference to the radio object to be configured.
	 * @param[in] parent_id Pointer to the parent identifier, if applicable.
	 *
	 * @returns int Status code indicating success or failure of the configuration.
	 * @retval 0 Configuration was successful.
	 * @retval -1 Configuration failed due to invalid parameters.
	 *
	 * @note Ensure that the database client and radio objects are properly initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, dm_radio_t& radio, void *parent_id);   
    
	/**!
	 * @brief Retrieves the configuration for the specified radio list.
	 *
	 * This function fetches the configuration details based on the provided JSON object and parent identifier.
	 *
	 * @param[in] obj The JSON object containing configuration details.
	 * @param[in] parent_id The identifier for the parent configuration.
	 * @param[in] reason The reason for fetching the radio list configuration. Defaults to `em_get_radio_list_reason_none`.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object and parent identifier are valid before calling this function.
	 */
	int get_config(cJSON *obj, void *parent_id, em_get_radio_list_reason_t reason = em_get_radio_list_reason_none);
    
	/**!
	 * @brief Retrieves the configuration settings.
	 *
	 * This function extracts configuration details from a JSON object and processes them based on the provided parent ID and summary flag.
	 *
	 * @param[in] obj The JSON object containing configuration data.
	 * @param[in] parent_id A pointer to the parent identifier used for processing.
	 * @param[in] summary A boolean flag indicating whether to retrieve a summary of the configuration.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object is properly formatted before calling this function.
	 */
	int get_config(cJSON *obj, void *parent_id, bool summary);

    
	/**!
	 * @brief Retrieves the first radio from the list.
	 *
	 * This function returns a pointer to the first radio object in the list.
	 *
	 * @returns A pointer to the first dm_radio_t object.
	 * @retval nullptr If the list is empty or an error occurs.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual dm_radio_t *get_first_radio() = 0;
    
	/**!
	 * @brief Retrieves the next radio in the list.
	 *
	 * This function takes a pointer to a radio and returns a pointer to the next radio in the list.
	 *
	 * @param[in] radio A pointer to the current radio.
	 *
	 * @returns A pointer to the next radio in the list.
	 * @retval nullptr If there is no next radio.
	 *
	 * @note This function is pure virtual and must be implemented by derived classes.
	 */
	virtual dm_radio_t *get_next_radio(dm_radio_t *radio) = 0;
    
	/**!
	 * @brief Retrieves a radio object associated with the given key.
	 *
	 * This function searches for a radio object using the specified key and returns a pointer to the radio object if found.
	 *
	 * @param[in] key A constant character pointer representing the key used to search for the radio object.
	 *
	 * @returns A pointer to the dm_radio_t object associated with the given key.
	 * @retval nullptr If no radio object is found for the specified key.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_radio_t *get_radio(const char *key) = 0;
    
	/**!
	 * @brief Removes a radio entry identified by the given key.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @param[in] key A pointer to a character string that uniquely identifies the radio entry to be removed.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing radio entry.
	 */
	virtual void remove_radio(const char *key) = 0;
    
	/**!
	 * @brief Puts a radio into the list.
	 *
	 * This function adds a radio to the list using the specified key.
	 *
	 * @param[in] key The key associated with the radio.
	 * @param[in] radio The radio object to be added.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void put_radio(const char *key, const dm_radio_t *radio) = 0;

};

#endif

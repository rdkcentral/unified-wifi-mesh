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

#ifndef DM_STA_LIST_H
#define DM_STA_LIST_H

#include "em_base.h"
#include "dm_sta.h"
#include "db_easy_mesh.h"
#include "tr_181.h"

class dm_easy_mesh_t;
class em_cmd_t;

class dm_sta_list_t : public dm_sta_t, public db_easy_mesh_t, virtual public tr_181_t {

public:
    
	/**!
	 * @brief Initializes the system or component.
	 *
	 * This function is responsible for setting up the necessary environment
	 * or state required for the system or component to function correctly.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that all preconditions are met before calling this function.
	 */
	int init();


    
	/**!
	 * @brief Retrieves the DM orchestration type for a given station.
	 *
	 * This function queries the database client to determine the DM orchestration type
	 * associated with the specified station.
	 *
	 * @param[in] db_client Reference to the database client used for querying.
	 * @param[in] sta Reference to the station for which the DM orchestration type is retrieved.
	 *
	 * @returns The DM orchestration type associated with the specified station.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_sta_t& sta);
    
	/**!
	 * @brief Updates the list with the given station information and operation type.
	 *
	 * This function modifies the list based on the operation type specified.
	 *
	 * @param[in] sta The station information to be updated in the list.
	 * @param[in] op The operation type that determines how the list should be updated.
	 *
	 * @note Ensure that the station information and operation type are valid before calling this function.
	 */
	void update_list(const dm_sta_t& sta, dm_orch_type_t op);   
    
	/**!
	 * @brief Deletes the list.
	 *
	 * This function removes all elements from the list and deallocates any associated memory.
	 *
	 * @note Ensure that the list is initialized before calling this function to avoid undefined behavior.
	 */
	void delete_list();

    
	/**!
	 * @brief Analyzes the configuration from a JSON object array.
	 *
	 * This function processes the given JSON object array and extracts relevant
	 * configuration details, associating them with the provided parent ID and
	 * command structures.
	 *
	 * @param[in] obj_arr A pointer to the cJSON object array containing configuration data.
	 * @param[in] parent_id A pointer to the parent ID used for associating the configuration.
	 * @param[out] cmd An array of pointers to em_cmd_t structures where the extracted commands will be stored.
	 * @param[out] param A pointer to em_cmd_params_t where the extracted command parameters will be stored.
	 *
	 * @returns int Status code indicating success or failure of the configuration analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the JSON object array and command structures are properly initialized before calling this function.
	 */
	int analyze_config(const cJSON *obj_arr, void *parent_id, em_cmd_t *cmd[], em_cmd_params_t *param);

    
	/**!
	 * @brief Initializes the table.
	 *
	 * This function sets up the necessary data structures and state for the table.
	 *
	 * @note Ensure that the table is properly configured before calling this function.
	 */
	void init_table();
    
	/**!
	 * @brief Initializes the columns for the data management system.
	 *
	 * This function sets up the necessary columns required for the data management
	 * system to function correctly. It should be called before any data operations
	 * are performed.
	 *
	 * @note Ensure that the system is properly configured before calling this function.
	 */
	void init_columns();
    
	/**!
	 * @brief Synchronizes the database using the provided database client and context.
	 *
	 * This function is responsible for ensuring that the database is synchronized
	 * with the current state as defined by the context.
	 *
	 * @param[in] db_client Reference to the database client used for synchronization.
	 * @param[in] ctx Pointer to the context used for synchronization.
	 *
	 * @returns int Status code indicating success or failure of the synchronization.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int sync_db(db_client_t& db_client, void *ctx);
    
	/**!
	 * @brief Updates the database with the given operation and data.
	 *
	 * This function performs the specified operation on the database using the provided data.
	 *
	 * @param[in] db_client Reference to the database client.
	 * @param[in] op The operation type to be performed on the database.
	 * @param[in] data Pointer to the data to be used in the operation.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Operation was successful.
	 * @retval -1 Operation failed.
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
	 * @returns True if the entry is found, false otherwise.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	bool search_db(db_client_t& db_client, void *ctx, void *key);
    
	/**!
	 * @brief Compares a database client with a station.
	 *
	 * This function checks if the given database client matches the specified station.
	 *
	 * @param[in] db_client Reference to the database client object to be compared.
	 * @param[in] sta Reference to the station object to compare against.
	 *
	 * @returns True if the database client matches the station, false otherwise.
	 */
	bool compare_db(db_client_t& db_client, const dm_sta_t& sta);
    bool operator == (const db_easy_mesh_t& obj);

	/**!
	 * @brief Updates a row in the database using the provided database client.
	 *
	 * This function modifies a specific row in the database as specified by the
	 * additional parameters (not fully listed here).
	 *
	 * @param[in] db_client Reference to the database client used for the operation.
	 *
	 * @returns int Status code of the operation.
	 * @retval 0 on success.
	 * @retval non-zero on failure.
	 *
	 * @note Ensure that the database client is properly initialized before calling
	 * this function.
	 */
	int update_row(db_client_t& db_client, ...);
    
	/**!
	 * @brief Sets the configuration using the provided JSON object.
	 *
	 * This function updates the configuration in the database client using the JSON object provided.
	 *
	 * @param[in] db_client Reference to the database client where the configuration will be set.
	 * @param[in] obj Pointer to a cJSON object containing the configuration data.
	 * @param[out] parent_id Pointer to a location where the parent ID will be stored.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object is properly formatted before calling this function.
	 */
	int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Sets the configuration for a given station.
	 *
	 * This function configures the specified station using the provided database client and parent identifier.
	 *
	 * @param[in] db_client Reference to the database client used for configuration.
	 * @param[in] sta Reference to the station configuration structure.
	 * @param[in] parent_id Pointer to the parent identifier.
	 *
	 * @returns int Status code indicating success or failure of the configuration.
	 * @retval 0 Configuration was successful.
	 * @retval -1 Configuration failed due to invalid parameters.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, dm_sta_t& sta, void *parent_id);
    
	/**!
	 * @brief Retrieves the configuration settings.
	 *
	 * This function extracts configuration details from the provided JSON object.
	 *
	 * @param[in] obj The JSON object containing configuration data.
	 * @param[in] parent_id A pointer to the parent identifier.
	 * @param[in] summary A boolean flag indicating whether to retrieve a summary.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the JSON object is properly formatted before calling this function.
	 */
	int get_config(cJSON *obj, void *parent_id, bool summary = false);
    
	/**!
	 * @brief Retrieves the configuration for a given station list.
	 *
	 * This function fetches the configuration details based on the provided JSON object and parent identifier.
	 *
	 * @param[in] obj The JSON object containing configuration details.
	 * @param[in] parent_id The identifier for the parent object.
	 * @param[in] reason The reason for retrieving the station list configuration.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object is properly formatted before calling this function.
	 */
	int get_config(cJSON *obj, void *parent_id, em_get_sta_list_reason_t reason);

    
	/**!
	 * @brief Retrieves the first station.
	 *
	 * This function returns a pointer to the first station in the list.
	 *
	 * @returns A pointer to the first station.
	 * @retval nullptr If there are no stations in the list.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual dm_sta_t *get_first_sta() = 0;
    
	/**!
	 * @brief Retrieves the next station in the list.
	 *
	 * This function returns the next station object following the provided station in the list.
	 *
	 * @param[in] sta Pointer to the current station object.
	 *
	 * @returns Pointer to the next station object in the list.
	 * @retval nullptr If there is no next station.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_sta_t *get_next_sta(dm_sta_t *sta) = 0;
    
	/**!
	 * @brief Retrieves a station object based on the provided key.
	 *
	 * This function searches for a station object using the specified key and returns a pointer to the station object if found.
	 *
	 * @param[in] key A constant character pointer representing the key used to search for the station.
	 *
	 * @returns A pointer to a dm_sta_t object if the station is found, otherwise returns nullptr.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_sta_t *get_sta(const char *key) = 0;
    
	/**!
	 * @brief Removes a station identified by the given key.
	 *
	 * This function is responsible for removing a station from the list
	 * using the specified key.
	 *
	 * @param[in] key A constant character pointer representing the key
	 *                 of the station to be removed.
	 *
	 * @note This is a pure virtual function and must be implemented by
	 *       derived classes.
	 */
	virtual void remove_sta(const char *key) = 0;
    
	/**!
	 * @brief Adds a station entry to the data manager.
	 *
	 * This function inserts a station entry identified by a key into the data manager.
	 *
	 * @param[in] key A constant character pointer representing the unique key for the station.
	 * @param[in] sta A pointer to a `dm_sta_t` structure containing the station data to be added.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void put_sta(const char *key, const dm_sta_t *sta) = 0;

};

#endif

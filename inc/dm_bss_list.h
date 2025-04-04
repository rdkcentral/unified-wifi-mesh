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

#ifndef DM_BSS_LIST_H
#define DM_BSS_LIST_H

#include "em_base.h"
#include "dm_bss.h"
#include "db_easy_mesh.h"

class dm_easy_mesh_t;

class dm_bss_list_t : public dm_bss_t, public db_easy_mesh_t {

public:
    
	/**!
	 * @brief Initializes the system or component.
	 *
	 * This function is responsible for setting up necessary configurations
	 * and preparing the system for operation.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that all prerequisites are met before calling this function.
	 */
	int init();


    
	/**!
	 * @brief Retrieves the DM orchestration type for a given BSS.
	 *
	 * This function determines the DM orchestration type based on the provided
	 * database client and BSS information.
	 *
	 * @param[in] db_client Reference to the database client used for querying.
	 * @param[in] bss Constant reference to the BSS structure containing necessary information.
	 *
	 * @returns The DM orchestration type associated with the specified BSS.
	 * @retval dm_orch_type_t The type of orchestration determined.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_bss_t& bss);
    
	/**!
	 * @brief Updates the list with the given BSS information and operation type.
	 *
	 * This function modifies the current list based on the provided BSS structure
	 * and operation type. It ensures that the list is updated according to the
	 * specified operation.
	 *
	 * @param[in] bss The BSS information to be used for updating the list.
	 * @param[in] op The operation type that dictates how the list should be updated.
	 *
	 * @note Ensure that the BSS information and operation type are valid before
	 * calling this function to avoid unexpected behavior.
	 */
	void update_list(const dm_bss_t& bss, dm_orch_type_t op);	
    
	/**!
	 * @brief Deletes the list.
	 *
	 * This function is responsible for deleting the list and freeing any associated resources.
	 *
	 * @note Ensure that the list is not accessed after calling this function.
	 */
	void delete_list();

    
	/**!
	 * @brief Initializes the table.
	 *
	 * This function sets up the necessary data structures and state for the table to be used.
	 *
	 * @note Ensure that the table is not already initialized before calling this function.
	 */
	void init_table();
    
	/**!
	 * @brief Initializes the columns for the BSS list.
	 *
	 * This function sets up the necessary columns required for displaying or processing the BSS list.
	 *
	 * @note Ensure that the BSS list is properly initialized before calling this function.
	 */
	void init_columns();
    
	/**!
	 * @brief Synchronizes the database using the provided client and context.
	 *
	 * This function is responsible for ensuring that the database is synchronized
	 * with the current state as defined by the context.
	 *
	 * @param[in] db_client Reference to the database client used for synchronization.
	 * @param[in] ctx Pointer to the context used for synchronization.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval non-zero on failure.
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
	 * @returns True if the entry is found, false otherwise.
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
	 * hierarchical context within the configuration.
	 *
	 * @param[in] db_client Reference to the database client where the configuration
	 * will be set.
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
	 * @brief Sets the configuration for a BSS.
	 *
	 * This function configures the BSS using the provided database client and parent ID.
	 *
	 * @param[in] db_client Reference to the database client used for configuration.
	 * @param[in] bss Reference to the BSS structure to be configured.
	 * @param[in] parent_id Pointer to the parent ID used in the configuration.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the db_client and bss are properly initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, dm_bss_t& bss, void *parent_id);
    
	/**!
	 * @brief Retrieves the configuration details from a JSON object.
	 *
	 * This function extracts configuration settings from the provided JSON object and associates them with a parent identifier. It can optionally provide a summary of the configuration.
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
	 * @brief Retrieves the first BSS (Base Station Subsystem) entry.
	 *
	 * This function returns a pointer to the first BSS entry available.
	 *
	 * @returns A pointer to the first dm_bss_t object.
	 * @retval nullptr if no BSS entries are available.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_bss_t *get_first_bss() = 0;
    
	/**!
	 * @brief Retrieves the next BSS (Basic Service Set) in the list.
	 *
	 * This function is used to iterate over the BSS list, returning the next BSS
	 * following the provided one.
	 *
	 * @param[in] bss Pointer to the current BSS from which the next BSS is to be retrieved.
	 *
	 * @returns Pointer to the next BSS in the list.
	 * @retval nullptr if there are no more BSSs in the list.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_bss_t *get_next_bss(dm_bss_t *bss) = 0;
    
	/**!
	 * @brief Retrieves the BSS entry associated with the specified key.
	 *
	 * This function searches for the BSS entry that matches the given key and returns it.
	 *
	 * @param[in] key The key used to identify the BSS entry.
	 *
	 * @returns A pointer to the `dm_bss_t` structure if found, otherwise `nullptr`.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_bss_t *get_bss(const char *key) = 0;
    
	/**!
	 * @brief Removes a BSS entry identified by the given key.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @param[in] key A pointer to a character string that uniquely identifies the BSS entry to be removed.
	 *
	 * @note The key must be a valid, null-terminated string.
	 */
	virtual void remove_bss(const char *key) = 0;
    
	/**!
	 * @brief Puts a BSS entry into the data structure.
	 *
	 * This function inserts a BSS (Basic Service Set) entry into the data structure
	 * using the provided key.
	 *
	 * @param[in] key A constant character pointer representing the key associated with the BSS entry.
	 * @param[in] bss A pointer to a dm_bss_t structure containing the BSS data to be inserted.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void put_bss(const char *key, const dm_bss_t *bss) = 0;

};

#endif

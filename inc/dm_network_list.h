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

#ifndef DM_NETWORK_LIST_H
#define DM_NETWORK_LIST_H

#include "em_base.h"
#include "dm_network.h"
#include "db_easy_mesh.h"

class dm_easy_mesh_t;
class dm_network_list_t : public dm_network_t, public db_easy_mesh_t {

public:
    
	/**!
	 * @brief Initializes the network list.
	 *
	 * @returns Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note This function must be called before using other network list functions.
	 */
	int init();

    
	/**!
	 * @brief Decodes a JSON object array into a specified parent structure.
	 *
	 * This function takes a JSON object array and decodes it into a structure
	 * pointed to by `parent_id`. The decoding process involves parsing the JSON
	 * data and populating the corresponding fields in the parent structure.
	 *
	 * @param[in] obj_arr A pointer to the cJSON object array to be decoded.
	 * @param[out] parent_id A pointer to the parent structure where the decoded
	 * data will be stored.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that `parent_id` is properly initialized before calling this
	 * function. The function does not allocate memory for the parent structure.
	 */
	int decode(const cJSON *obj_arr, void *parent_id);
    
	/**!
	 * @brief Encodes the given JSON object array.
	 *
	 * This function takes a JSON object array and performs encoding operations on it.
	 *
	 * @param[in] obj_arr Pointer to the cJSON object array to be encoded.
	 *
	 * @note Ensure that the cJSON object array is properly initialized before passing it to this function.
	 */
	void encode(cJSON *obj_arr);


    
	/**!
	 * @brief Retrieves the DM orchestration type for a given network.
	 *
	 * This function determines the orchestration type based on the provided
	 * database client and network information.
	 *
	 * @param[in] db_client Reference to the database client used for querying.
	 * @param[in] net Reference to the network for which the orchestration type is determined.
	 *
	 * @returns The orchestration type of the specified network.
	 * @retval dm_orch_type_t The type of orchestration for the network.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_network_t& net);
    
	/**!
	 * @brief Updates the network list based on the operation type.
	 *
	 * This function modifies the network list by applying the specified operation
	 * type to the given network object.
	 *
	 * @param[in] net The network object to be updated in the list.
	 * @param[in] op The operation type to be applied to the network list.
	 *
	 * @note Ensure that the network object and operation type are valid before
	 * calling this function.
	 */
	void update_list(const dm_network_t& net, dm_orch_type_t op);
    
	/**!
	 * @brief Deletes the network list.
	 *
	 * This function removes all entries from the network list, effectively clearing it.
	 *
	 * @note Ensure that the list is not in use before calling this function to avoid undefined behavior.
	 */
	void delete_list();

    
	/**!
	 * @brief Retrieves the control interface for a given network identifier.
	 *
	 * This function searches for and returns the control interface associated with the specified network identifier.
	 *
	 * @param[in] net_id The network identifier for which the control interface is requested.
	 *
	 * @returns A pointer to the control interface associated with the given network identifier.
	 * @retval NULL if the network identifier is not found or an error occurs.
	 *
	 * @note Ensure that the network identifier provided is valid and corresponds to an existing network.
	 */
	em_interface_t *get_ctrl_al_interface(em_long_string_t net_id);

    
	/**!
	 * @brief Initializes the network table.
	 *
	 * This function sets up the necessary data structures and state for the network table.
	 *
	 * @note This function should be called before any other operations on the network table.
	 */
	void init_table();
    
	/**!
	 * @brief Initializes the columns for the network list.
	 *
	 * This function sets up the necessary columns required for displaying
	 * the network list. It should be called before any operations that
	 * depend on the column setup.
	 *
	 * @note Ensure that the network list is properly initialized before
	 * calling this function.
	 */
	void init_columns();
    
	/**!
	 * @brief Synchronizes the database using the provided database client and context.
	 *
	 * This function establishes a connection to the database and performs synchronization
	 * operations using the given client and context.
	 *
	 * @param[in] db_client Reference to the database client used for synchronization.
	 * @param[in] ctx Pointer to the context information required for synchronization.
	 *
	 * @returns int Status code indicating the success or failure of the synchronization.
	 * @retval 0 Synchronization was successful.
	 * @retval -1 Synchronization failed due to an error.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
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
	 * This function performs a search operation on the database using the given key and context.
	 *
	 * @param[in] db_client Reference to the database client used for the search operation.
	 * @param[in] ctx Pointer to the context for the search operation.
	 * @param[in] key Pointer to the key used for searching in the database.
	 *
	 * @returns True if the search is successful, false otherwise.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	bool search_db(db_client_t& db_client, void *ctx, void *key);
    bool operator == (const db_easy_mesh_t& obj);
    
	/**!
	 * @brief Sets the configuration for a network.
	 *
	 * This function configures the network settings using the provided database client and network information.
	 *
	 * @param[in] db_client Reference to the database client used for configuration.
	 * @param[in] net Reference to the network configuration to be set.
	 * @param[in] parent_id Pointer to the parent identifier, if applicable.
	 *
	 * @returns int Status code indicating success or failure of the configuration.
	 * @retval 0 Configuration was successful.
	 * @retval -1 Configuration failed due to invalid parameters.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, dm_network_t& net, void *parent_id);
    
	/**!
	 * @brief Sets the configuration using the provided JSON object.
	 *
	 * This function updates the configuration in the database client using the
	 * JSON object provided. The parent ID is used to specify the hierarchy
	 * within the configuration.
	 *
	 * @param[in] db_client Reference to the database client where the configuration
	 * will be set.
	 * @param[in] obj Pointer to a cJSON object containing the configuration data.
	 * @param[in] parent_id Pointer to the parent ID used for hierarchical configuration.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the db_client is properly initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Retrieves the configuration details from a JSON object.
	 *
	 * This function extracts configuration information from the provided JSON object and associates it with a parent identifier. Optionally, a summary of the configuration can be retrieved.
	 *
	 * @param[in] obj The JSON object containing configuration data.
	 * @param[in] parent_id A pointer to the parent identifier to associate with the configuration.
	 * @param[in] summary A boolean flag indicating whether to retrieve a summary of the configuration. Defaults to false.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Success
	 * @retval -1 Failure
	 *
	 * @note Ensure that the JSON object is properly formatted and the parent identifier is valid before calling this function.
	 */
	int get_config(cJSON *obj, void *parent_id, bool summary = false);

    
	/**!
	 * @brief Retrieves the first network from the list.
	 *
	 * @returns A pointer to the first network object.
	 * @retval nullptr if no networks are available.
	 */
	virtual dm_network_t *get_first_network() = 0;
    
	/**!
	 * @brief Retrieves the next network in the list.
	 *
	 * This function returns the next network object following the provided network object in the list.
	 *
	 * @param[in] net A pointer to the current network object from which the next network is to be retrieved.
	 *
	 * @returns A pointer to the next network object in the list.
	 * @retval nullptr If there are no more networks in the list.
	 *
	 * @note The caller must ensure that the provided network object is valid and part of the list.
	 */
	virtual dm_network_t *get_next_network(dm_network_t *net) = 0;
    
	/**!
	 * @brief Retrieves the network associated with the given key.
	 *
	 * This function searches for the network corresponding to the specified key and returns a pointer to the network object.
	 *
	 * @param[in] key A constant character pointer representing the key used to identify the network.
	 *
	 * @returns A pointer to the dm_network_t object associated with the given key.
	 * @retval nullptr If no network is found for the specified key.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_network_t *get_network(const char *key) = 0;
    
	/**!
	 * @brief Removes a network identified by the given key.
	 *
	 * This function is responsible for removing a network from the list
	 * using the specified key.
	 *
	 * @param[in] key A pointer to a character string that uniquely identifies
	 *                the network to be removed.
	 *
	 * @note This is a pure virtual function and must be implemented by
	 *       derived classes.
	 */
	virtual void remove_network(const char *key) = 0;
    
	/**!
	 * @brief Puts a network into the data manager.
	 *
	 * This function stores the network information associated with the given key.
	 *
	 * @param[in] key A pointer to a character string representing the key.
	 * @param[in] net A pointer to a dm_network_t structure containing the network information.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void put_network(const char *key, const dm_network_t *net) = 0;

};

#endif

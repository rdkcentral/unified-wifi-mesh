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

#ifndef DM_NETWORK_SSID_LIST_H
#define DM_NETWORK_SSID_LIST_H

#include "em_base.h"
#include "dm_network_ssid.h"
#include "db_easy_mesh.h"

class dm_easy_mesh_t;
class em_cmd_t;

class dm_network_ssid_list_t : public dm_network_ssid_t, public db_easy_mesh_t {

public:
    
	/**!
	 * @brief Initializes the network SSID list.
	 *
	 * This function sets up necessary configurations and prepares the system to handle network SSID operations.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that all prerequisites are met before calling this function.
	 */
	int init();


    
	/**!
	 * @brief Retrieves the DM orchestration type for a given network SSID.
	 *
	 * This function takes a network SSID as input and returns the corresponding
	 * DM orchestration type.
	 *
	 * @param[in] net_ssid The network SSID for which the DM orchestration type is required.
	 *
	 * @returns The DM orchestration type associated with the provided network SSID.
	 */
	dm_orch_type_t get_dm_orch_type(const dm_network_ssid_t& net_ssid);
    
	/**!
	 * @brief Updates the network SSID list with the specified operation.
	 *
	 * This function modifies the list of network SSIDs based on the operation type provided.
	 *
	 * @param[in] net_ssid The network SSID to be updated in the list.
	 * @param[in] op The operation type to be performed on the network SSID list.
	 *
	 * @note Ensure that the operation type is valid and supported.
	 */
	void update_list(const dm_network_ssid_t& net_ssid, dm_orch_type_t op);
    
	/**!
	 * @brief Deletes the network SSID list.
	 *
	 * This function removes all entries from the network SSID list, effectively clearing it.
	 *
	 * @note Ensure that no operations are pending on the list before calling this function.
	 */
	void delete_list();

    
	/**!
	 * @brief Analyzes the configuration from a JSON object array.
	 *
	 * This function processes the given JSON object array to extract and analyze
	 * configuration data, associating it with a parent identifier and populating
	 * command structures.
	 *
	 * @param[in] obj_arr Pointer to the cJSON object array containing configuration data.
	 * @param[in] parent_id Pointer to the parent identifier used for associating the configuration.
	 * @param[out] pcmd Array of pointers to em_cmd_t structures where the parsed commands will be stored.
	 * @param[in] param Pointer to em_cmd_params_t structure containing additional parameters for command processing.
	 *
	 * @returns int Status code indicating success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the JSON object array and command structures are properly initialized before calling this function.
	 */
	int analyze_config(const cJSON *obj_arr, void *parent_id, em_cmd_t *pcmd[], em_cmd_params_t *param);

    
	/**!
	 * @brief Initializes the network SSID table.
	 *
	 * This function sets up the necessary data structures for managing
	 * the list of network SSIDs.
	 *
	 * @note This function must be called before any operations on the
	 *       SSID list are performed.
	 */
	void init_table();
    
	/**!
	 * @brief Initializes the columns for the network SSID list.
	 *
	 * This function sets up the necessary columns required for displaying or processing
	 * the network SSID list.
	 *
	 * @note Ensure that the necessary resources are allocated before calling this function.
	 */
	void init_columns();
    
	/**!
	 * @brief Synchronizes the database using the provided client and context.
	 *
	 * This function attempts to synchronize the database by utilizing the given
	 * database client and context. It ensures that the database state is
	 * consistent and up-to-date.
	 *
	 * @param[in] db_client Reference to the database client used for synchronization.
	 * @param[in] ctx Pointer to the context information required for synchronization.
	 *
	 * @returns int Status code indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the database client is properly initialized before calling
	 * this function.
	 */
	int sync_db(db_client_t& db_client, void *ctx);
    
	/**!
	 * @brief Updates the database with the given operation type and data.
	 *
	 * This function performs an update on the database using the specified operation type and data.
	 *
	 * @param[in] db_client Reference to the database client used for the update.
	 * @param[in] op The operation type to be performed on the database.
	 * @param[in] data Pointer to the data to be used in the update operation.
	 *
	 * @returns int Status code indicating the success or failure of the update operation.
	 * @retval 0 Indicates successful update.
	 * @retval -1 Indicates failure in updating the database.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int update_db(db_client_t& db_client, dm_orch_type_t op, void *data);
    
	/**!
	 * @brief Searches the database for a specific key.
	 *
	 * This function searches the database using the provided client and context to find the specified key.
	 *
	 * @param[in] db_client Reference to the database client used for the search.
	 * @param[in] ctx Context information for the search operation.
	 * @param[in] key The key to search for in the database.
	 *
	 * @returns True if the key is found, false otherwise.
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
	 * @param[in] db_client Reference to the database client where the configuration will be set.
	 * @param[in] obj Pointer to a cJSON object containing the configuration data.
	 * @param[out] parent_id Pointer to a location where the parent ID will be stored.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object is properly formatted before calling this function.
	 */
	int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Sets the configuration for a network SSID.
	 *
	 * This function configures the network SSID using the provided database client and parent ID.
	 *
	 * @param[in] db_client Reference to the database client used for configuration.
	 * @param[in] net_ssid Reference to the network SSID to be configured.
	 * @param[in] parent_id Pointer to the parent ID associated with the configuration.
	 *
	 * @returns int Status code indicating success or failure of the configuration.
	 * @retval 0 Configuration was successful.
	 * @retval -1 Configuration failed due to invalid parameters.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, dm_network_ssid_t& net_ssid, void *parent_id);
    
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
	 * @brief Retrieves the first network SSID.
	 *
	 * This function returns a pointer to the first network SSID available.
	 *
	 * @returns A pointer to the first network SSID.
	 * @retval nullptr if no SSID is available.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual dm_network_ssid_t *get_first_network_ssid() = 0;
    
	/**!
	 * @brief Retrieves the next network SSID in the list.
	 *
	 * This function provides a mechanism to iterate over network SSIDs.
	 *
	 * @param[in] net_ssid A pointer to the current network SSID.
	 *
	 * @returns A pointer to the next network SSID in the list.
	 * @retval nullptr If there are no more SSIDs in the list.
	 *
	 * @note This function must be implemented by derived classes.
	 */
	virtual dm_network_ssid_t *get_next_network_ssid(dm_network_ssid_t *net_ssid) = 0;
    
	/**!
	 * @brief Retrieves the network SSID associated with the given key.
	 *
	 * This function searches for the network SSID that corresponds to the specified key.
	 *
	 * @param[in] key A constant character pointer representing the key used to find the network SSID.
	 *
	 * @returns A pointer to a dm_network_ssid_t structure that contains the network SSID.
	 * @retval nullptr If the key does not correspond to any network SSID.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual dm_network_ssid_t *get_network_ssid(const char *key) = 0;
    
	/**!
	 * @brief Removes a network SSID from the list.
	 *
	 * This function removes the specified network SSID identified by the key.
	 *
	 * @param[in] key A pointer to a character string representing the key of the network SSID to be removed.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual void remove_network_ssid(const char *key) = 0;
    
	/**!
	 * @brief Puts a network SSID into the system.
	 *
	 * This function stores the provided network SSID associated with the given key.
	 *
	 * @param[in] key A pointer to a character string representing the key associated with the network SSID.
	 * @param[in] net_ssid A pointer to a dm_network_ssid_t structure containing the network SSID information.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void put_network_ssid(const char *key, const dm_network_ssid_t *net_ssid) = 0;

};

#endif

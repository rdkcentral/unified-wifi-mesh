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

#ifndef DM_POLICY_LIST_H
#define DM_POLICY_LIST_H

#include "em_base.h"
#include "dm_policy.h"
#include "db_easy_mesh.h"

class dm_easy_mesh_t;
class dm_policy_list_t : public dm_policy_t, public db_easy_mesh_t {

public:
    
	/**!
	 * @brief Initializes the policy list.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note This function must be called before using any other functions in the policy list module.
	 */
	int init();

    
	/**!
	 * @brief Retrieves the DM orchestration type based on the provided policy.
	 *
	 * This function determines the appropriate DM orchestration type by evaluating
	 * the given policy in conjunction with the database client.
	 *
	 * @param[in] db_client Reference to the database client used for policy evaluation.
	 * @param[in] policy The policy for which the DM orchestration type is to be determined.
	 *
	 * @returns The DM orchestration type corresponding to the provided policy.
	 */
	dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_policy_t& policy);
    
	/**!
	 * @brief Updates the policy list based on the specified operation type.
	 *
	 * This function modifies the policy list according to the operation type provided.
	 *
	 * @param[in] policy The policy to be updated in the list.
	 * @param[in] op The operation type to be applied to the policy list.
	 *
	 * @note Ensure that the policy and operation type are valid before calling this function.
	 */
	void update_list(const dm_policy_t& policy, dm_orch_type_t op);
    
	/**!
	* @brief Deletes the list.
	*
	* This function is responsible for deleting the list and freeing any associated resources.
	*
	* @note Ensure that the list is not accessed after calling this function.
	*/
	void delete_list();

    
	/**!
	 * @brief Initializes the policy table.
	 *
	 * This function sets up the initial state of the policy table.
	 *
	 * @note Ensure that the table is not already initialized before calling this function.
	 */
	void init_table();
    
	/**!
	 * @brief Initializes the columns for the policy list.
	 *
	 * This function sets up the necessary columns required for displaying or processing the policy list.
	 *
	 * @note Ensure that the environment is properly set up before calling this function.
	 */
	void init_columns();
    
	/**!
	 * @brief Synchronizes the database using the provided database client and context.
	 *
	 * This function is responsible for ensuring that the database is synchronized
	 * with the current state as defined by the context.
	 *
	 * @param[in] db_client Reference to the database client used for synchronization.
	 * @param[in] ctx Pointer to the context used during the synchronization process.
	 *
	 * @returns int Status code indicating success or failure of the synchronization.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int sync_db(db_client_t& db_client, void *ctx);
    
	/**!
	 * @brief Updates the database with the specified operation and data.
	 *
	 * This function performs an update on the database using the provided database client, operation type, and data.
	 *
	 * @param[in,out] db_client Reference to the database client used for the update.
	 * @param[in] op The operation type to be performed on the database.
	 * @param[in] data Pointer to the data to be used in the update operation.
	 *
	 * @returns int Status code of the update operation.
	 * @retval 0 on success.
	 * @retval non-zero on failure.
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
	 * @param[in] key Pointer to the key used for searching the database.
	 *
	 * @returns True if the search is successful, false otherwise.
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
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the JSON object is properly formatted and that the database
	 * client is initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Sets the configuration for the given policy.
	 *
	 * This function applies the specified policy to the database client.
	 *
	 * @param[in] db_client Reference to the database client.
	 * @param[in] policy Reference to the policy to be set.
	 * @param[in] parent_id Pointer to the parent identifier.
	 *
	 * @returns int Status code indicating success or failure.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, dm_policy_t& policy, void *parent_id);
    
	/**!
	 * @brief Retrieves the configuration details from a JSON object.
	 *
	 * This function extracts configuration information from the provided JSON object and associates it with a parent identifier. Optionally, it can return a summary of the configuration.
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
	 * @brief Retrieves the first policy from the list.
	 *
	 * @returns A pointer to the first policy in the list.
	 * @retval nullptr if the list is empty.
	 *
	 * @note This function must be implemented by derived classes.
	 */
	virtual dm_policy_t *get_first_policy() = 0;
    
	/**!
	 * @brief Retrieves the next policy in the list.
	 *
	 * This function returns the next policy object following the given policy.
	 *
	 * @param[in] policy The current policy object from which the next policy is retrieved.
	 *
	 * @returns A pointer to the next dm_policy_t object.
	 * @retval nullptr if there is no next policy available.
	 *
	 * @note This function must be implemented by derived classes.
	 */
	virtual dm_policy_t *get_next_policy(dm_policy_t *policy) = 0;
    
	/**!
	 * @brief Retrieves the policy associated with the specified key.
	 *
	 * This function searches for and returns the policy that corresponds to the given key.
	 *
	 * @param[in] key The key for which the policy is to be retrieved.
	 *
	 * @returns A pointer to the policy associated with the specified key.
	 * @retval nullptr If no policy is found for the given key.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_policy_t *get_policy(const char *key) = 0;
    
	/**!
	 * @brief Removes a policy identified by the given key.
	 *
	 * This function removes a policy from the list using the specified key.
	 *
	 * @param[in] key The key identifying the policy to be removed.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void remove_policy(const char *key) = 0;
    
	/**!
	 * @brief Puts a policy into the policy list.
	 *
	 * This function inserts or updates a policy associated with the given key.
	 *
	 * @param[in] key The key associated with the policy.
	 * @param[in] policy The policy to be inserted or updated.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void put_policy(const char *key, const dm_policy_t *policy) = 0;
};

#endif

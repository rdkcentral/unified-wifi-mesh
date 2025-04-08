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

#ifndef DM_SCAN_RESULT_LIST_H
#define DM_SCAN_RESULT_LIST_H

#include "em_base.h"
#include "dm_scan_result.h"
#include "db_easy_mesh.h"

#define scan_result_self_index 0xFFF

typedef struct {
	em_scan_result_t	*result;
	unsigned int	index;
} db_update_scan_result_t;

class dm_easy_mesh_t;
class dm_scan_result_list_t : public dm_scan_result_t, public db_easy_mesh_t {

public:
    
	/**!
	 * @brief Initializes the scan result list.
	 *
	 * This function sets up necessary resources and prepares the scan result list for use.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that this function is called before any other operations on the scan result list.
	 */
	int init();

    
	/**!
	 * @brief Retrieves the DM orchestration type based on the provided scan result and index.
	 *
	 * This function evaluates the scan result and returns the corresponding DM orchestration type.
	 *
	 * @param[in] db_client Reference to the database client used for accessing necessary data.
	 * @param[in] scan_result Constant reference to the scan result from which the orchestration type is determined.
	 * @param[in] index Unsigned integer representing the index of the scan result to be evaluated.
	 *
	 * @returns The DM orchestration type corresponding to the given scan result and index.
	 * @retval dm_orch_type_t The type of orchestration determined from the scan result.
	 *
	 * @note Ensure that the index is within the valid range of the scan result list to avoid undefined behavior.
	 */
	dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_scan_result_t& scan_result, unsigned int index);
    
	/**!
	 * @brief Updates the scan result list with the provided scan result at the specified index.
	 *
	 * This function modifies the list of scan results by updating the entry at the given index
	 * with the new scan result provided. The operation type is specified by the op parameter.
	 *
	 * @param[in] scan_result The scan result to update in the list.
	 * @param[in] index The index at which the scan result should be updated.
	 * @param[in] op The operation type to be performed on the scan result list.
	 *
	 * @note Ensure that the index is within the bounds of the list to avoid undefined behavior.
	 */
	void update_list(const dm_scan_result_t& scan_result, unsigned int index, dm_orch_type_t op);
    
	/**!
	* @brief Deletes the entire list of scan results.
	*
	* This function is responsible for clearing all entries in the scan result list,
	* freeing any allocated memory, and resetting the list to its initial state.
	*
	* @note Ensure that no other operations are performed on the list after calling
	* this function, as it will be empty.
	*/
	void delete_list();

    
	/**!
	 * @brief Initializes the table for storing scan results.
	 *
	 * This function sets up the necessary data structures and resources
	 * required to manage and store scan results efficiently.
	 *
	 * @note Ensure that this function is called before any operations
	 * related to scan results are performed.
	 */
	void init_table();
    
	/**!
	 * @brief Initializes the columns for the scan result list.
	 *
	 * This function sets up the necessary columns required to display
	 * the scan results in a structured format.
	 *
	 * @note Ensure that the scan result list is properly initialized
	 * before calling this function.
	 */
	void init_columns();
    
	/**!
	* @brief Synchronizes the database using the provided database client and context.
	*
	* This function is responsible for ensuring that the database is synchronized
	* with the latest data available. It uses the provided database client to
	* perform the necessary operations.
	*
	* @param[in] db_client Reference to the database client used for synchronization.
	* @param[in] ctx Pointer to the context information required for synchronization.
	*
	* @returns int Status code indicating the success or failure of the operation.
	* @retval 0 Indicates successful synchronization.
	* @retval non-zero Error code indicating the type of failure.
	*
	* @note Ensure that the database client is properly initialized before calling
	* this function. The context should contain all necessary information for
	* the synchronization process.
	*/
	int sync_db(db_client_t& db_client, void *ctx);
    
	/**!
	 * @brief Updates the database with the given operation type and data.
	 *
	 * This function modifies the database using the provided client, operation type, and data.
	 *
	 * @param[in] db_client Reference to the database client used for the update.
	 * @param[in] op The operation type to be performed on the database.
	 * @param[in] data Pointer to the data used for the update operation.
	 *
	 * @returns int Status code indicating the success or failure of the update operation.
	 * @retval 0 Indicates success.
	 * @retval -1 Indicates failure.
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
	 * @retval true if the search operation is successful.
	 * @retval false if the search operation fails.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	bool search_db(db_client_t& db_client, void *ctx, void *key);
    bool operator == (const db_easy_mesh_t& obj);
    
	/**!
	 * @brief Sets the configuration using the provided JSON object.
	 *
	 * This function updates the configuration settings in the database client
	 * using the JSON object provided. It may also associate the configuration
	 * with a parent identifier if applicable.
	 *
	 * @param[in] db_client Reference to the database client where the configuration
	 * will be set.
	 * @param[in] obj Pointer to a cJSON object containing the configuration data.
	 * @param[in] parent_id Pointer to a parent identifier, if applicable.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 *
	 * @note Ensure that the JSON object is properly formatted and the database
	 * client is initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Sets the configuration for a scan result.
	 *
	 * This function configures the scan result using the provided database client and parent ID.
	 *
	 * @param[in] db_client Reference to the database client used for configuration.
	 * @param[in] scan_result Reference to the scan result to be configured.
	 * @param[in] parent_id Pointer to the parent ID associated with the scan result.
	 *
	 * @returns int Status code indicating success or failure of the configuration.
	 * @retval 0 Configuration was successful.
	 * @retval -1 Configuration failed due to invalid parameters.
	 *
	 * @note Ensure that the database client and scan result are properly initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, dm_scan_result_t& scan_result, void *parent_id);
    
	/**!
	 * @brief Retrieves the configuration from the given JSON object.
	 *
	 * This function extracts configuration details from the provided JSON object and associates it with the specified parent ID. Optionally, a summary can be generated.
	 *
	 * @param[in] obj The JSON object containing configuration data.
	 * @param[in] parent_id The identifier for the parent to associate the configuration with.
	 * @param[in] summary Flag indicating whether to generate a summary.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Success.
	 * @retval -1 Failure.
	 *
	 * @note Ensure that the JSON object is properly formatted before calling this function.
	 */
	int get_config(cJSON *obj, void *parent_id, bool summary = false);

    
	/**!
	 * @brief Retrieves the first scan result from the list.
	 *
	 * This function returns a pointer to the first scan result available in the list.
	 *
	 * @returns A pointer to the first scan result of type dm_scan_result_t.
	 * @retval nullptr if the list is empty or no scan results are available.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual dm_scan_result_t *get_first_scan_result() = 0;
    
	/**!
	 * @brief Retrieves the next scan result from the list.
	 *
	 * This function is used to iterate over the scan results stored in the list.
	 *
	 * @param[in] scan_result A pointer to the current scan result from which the next result is to be retrieved.
	 *
	 * @returns A pointer to the next scan result in the list.
	 * @retval nullptr If there are no more scan results available.
	 *
	 * @note This function must be implemented by the derived class.
	 */
	virtual dm_scan_result_t *get_next_scan_result(dm_scan_result_t *scan_result) = 0;
    
	/**!
	 * @brief Retrieves the scan result associated with the specified key.
	 *
	 * This function searches for the scan result that matches the given key and returns a pointer to it.
	 *
	 * @param[in] key The key used to identify the scan result.
	 *
	 * @returns A pointer to the dm_scan_result_t associated with the key.
	 * @retval nullptr If no scan result is found for the given key.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_scan_result_t *get_scan_result(const char *key) = 0;
    
	/**!
	 * @brief Removes a scan result identified by the given key.
	 *
	 * This function removes a scan result from the list using the specified key.
	 *
	 * @param[in] key A pointer to a character string that uniquely identifies the scan result to be removed.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void remove_scan_result(const char *key) = 0;
    
	/**!
	 * @brief Puts a scan result into the list at the specified index.
	 *
	 * This function inserts a scan result associated with a given key into the
	 * scan result list at the specified index. If the index is out of bounds,
	 * the behavior is undefined.
	 *
	 * @param[in] key The key associated with the scan result.
	 * @param[in] scan_result Pointer to the scan result to be inserted.
	 * @param[in] index The position in the list where the scan result should be inserted.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void put_scan_result(const char *key, const dm_scan_result_t *scan_result, unsigned int index) = 0;
};

#endif

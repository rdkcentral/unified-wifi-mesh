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

#ifndef DM_OP_CLASS_LIST_H
#define DM_OP_CLASS_LIST_H

#include "em_base.h"
#include "dm_op_class.h"
#include "db_easy_mesh.h"
#include "tr_181.h"

class dm_easy_mesh_t;
class dm_op_class_list_t : public dm_op_class_t, public db_easy_mesh_t, virtual public tr_181_t {

public:
    
	/**!
	 * @brief Initializes the operation class list.
	 *
	 * This function sets up the necessary structures and resources for the operation class list.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note Ensure that this function is called before any other operations on the class list.
	 */
	int init();

    
	/**!
	 * @brief Retrieves the DM orchestration type based on the provided database client and operation class.
	 *
	 * This function determines the type of DM orchestration required by analyzing the given database client and operation class.
	 *
	 * @param[in] db_client Reference to the database client object used for the operation.
	 * @param[in] op_class Reference to the operation class object that specifies the operation type.
	 *
	 * @returns The DM orchestration type as a value of type dm_orch_type_t.
	 *
	 * @note Ensure that the database client and operation class are properly initialized before calling this function.
	 */
	dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_op_class_t& op_class);
    
	/**!
	 * @brief Updates the list with the given operation class and type.
	 *
	 * This function modifies the internal list based on the provided operation class and orchestration type.
	 *
	 * @param[in] op_class The operation class to be updated in the list.
	 * @param[in] op The orchestration type associated with the operation class.
	 *
	 * @note Ensure that the operation class and type are valid before calling this function.
	 */
	void update_list(const dm_op_class_t& op_class, dm_orch_type_t op);
    
	/**!
	 * @brief Deletes the list.
	 *
	 * This function is responsible for deleting the list and freeing up any resources associated with it.
	 *
	 * @note Ensure that the list is properly initialized before calling this function.
	 */
	void delete_list();

    
	/**!
	 * @brief Initializes the table.
	 *
	 * This function sets up the necessary data structures and state for the table.
	 *
	 * @note Ensure that the table is properly configured before calling this function.
	 */
	void init_table();
    
	/**!
	 * @brief Initializes the columns for the operation class list.
	 *
	 * This function sets up the necessary columns required for the operation class list.
	 * It should be called before any operations are performed on the list.
	 *
	 * @note Ensure that the operation class list is properly initialized before calling this function.
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
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval non-zero on failure.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int sync_db(db_client_t& db_client, void *ctx);
    
	/**!
	 * @brief Updates the database with the specified operation and data.
	 *
	 * This function performs an update on the database using the provided database client,
	 * operation type, and data. It modifies the database state based on the operation.
	 *
	 * @param[in,out] db_client Reference to the database client used for the update.
	 * @param[in] op The operation type to be performed on the database.
	 * @param[in] data Pointer to the data required for the operation.
	 *
	 * @returns int Status code indicating success or failure of the update operation.
	 * @retval 0 Operation was successful.
	 * @retval -1 Operation failed due to invalid parameters or database error.
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
	 * @param[in] ctx Contextual information for the search operation.
	 * @param[in] key Pointer to the key used for searching in the database.
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
	 * @brief Sets the configuration for the operation class.
	 *
	 * This function configures the operation class using the provided database client and parent ID.
	 *
	 * @param[in] db_client Reference to the database client used for configuration.
	 * @param[in] op_class Reference to the operation class to be configured.
	 * @param[in] parent_id Pointer to the parent ID associated with the configuration.
	 *
	 * @returns int Status code indicating success or failure of the configuration.
	 * @retval 0 Configuration was successful.
	 * @retval -1 Configuration failed due to invalid parameters.
	 *
	 * @note Ensure that the database client and operation class are properly initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, dm_op_class_t& op_class, void *parent_id);
    
	/**!
	 * @brief Retrieves the configuration from a JSON object.
	 *
	 * This function extracts configuration details from the provided JSON object and associates it with a parent identifier. Optionally, it can return a summary of the configuration.
	 *
	 * @param[in] obj The JSON object containing configuration data.
	 * @param[in] parent_id The identifier for the parent to associate the configuration with.
	 * @param[in] summary Flag indicating whether to return a summary of the configuration.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 *
	 * @note Ensure that the JSON object is properly formatted before calling this function.
	 */
	int get_config(cJSON *obj, void *parent_id, bool summary = false);
    
	/**!
	 * @brief Retrieves the configuration for a specified operation class type.
	 *
	 * This function extracts the configuration details from the provided JSON object
	 * based on the specified operation class type.
	 *
	 * @param[in] obj Pointer to a cJSON object containing configuration data.
	 * @param[in] type The operation class type for which the configuration is required.
	 *
	 * @note Ensure that the cJSON object is properly initialized and contains valid data
	 * before calling this function.
	 */
	void get_config(cJSON *obj, em_op_class_type_t type);

    
	/**!
	 * @brief Retrieves the first operation class.
	 *
	 * This function returns a pointer to the first operation class available.
	 *
	 * @returns A pointer to the first operation class.
	 * @retval nullptr If no operation class is available.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_op_class_t *get_first_op_class() = 0;
    
	/**!
	 * @brief Retrieves the next operation class.
	 *
	 * This function is used to iterate over operation classes.
	 *
	 * @param[in] op_class The current operation class from which the next is to be retrieved.
	 *
	 * @returns A pointer to the next operation class.
	 *
	 * @note This function must be implemented by derived classes.
	 */
	virtual dm_op_class_t *get_next_op_class(dm_op_class_t *op_class) = 0;
    
	/**!
	 * @brief Retrieves the operation class associated with the given key.
	 *
	 * This function searches for the operation class using the provided key and returns a pointer to the corresponding dm_op_class_t object.
	 *
	 * @param[in] key A constant character pointer representing the key used to find the operation class.
	 *
	 * @returns A pointer to the dm_op_class_t object associated with the key.
	 * @retval nullptr If no operation class is found for the given key.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_op_class_t *get_op_class(const char *key) = 0;
    
	/**!
	 * @brief Removes an operation class identified by the given key.
	 *
	 * This function is a pure virtual function that must be implemented by
	 * derived classes. It is responsible for removing an operation class
	 * associated with the specified key.
	 *
	 * @param[in] key A pointer to a character string representing the key
	 *                of the operation class to be removed.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an
	 *       existing operation class.
	 */
	virtual void remove_op_class(const char *key) = 0;
    
	/**!
	 * @brief Puts an operation class associated with a key.
	 *
	 * This function associates the given operation class with the specified key.
	 *
	 * @param[in] key The key to associate with the operation class.
	 * @param[in] op_class The operation class to be associated with the key.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void put_op_class(const char *key, const dm_op_class_t *op_class) = 0;

	
	/**!
	 * @brief Retrieves the first pre-set operation class by type.
	 *
	 * This function searches for and returns the first operation class that matches the specified type.
	 *
	 * @param[in] type The type of the operation class to retrieve.
	 *
	 * @returns A pointer to the first pre-set operation class of the specified type.
	 * @retval nullptr If no matching operation class is found.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_op_class_t *get_first_pre_set_op_class_by_type(em_op_class_type_t type) = 0;
	
	/**!
	 * @brief Retrieves the next pre-set operation class by type.
	 *
	 * This function searches for the next operation class of the specified type
	 * starting from the given operation class.
	 *
	 * @param[in] type The type of the operation class to search for.
	 * @param[in] op_class The current operation class from which the search begins.
	 *
	 * @returns A pointer to the next operation class of the specified type.
	 * @retval nullptr If no further operation class of the specified type is found.
	 *
	 * @note This function is pure virtual and must be implemented by derived classes.
	 */
	virtual dm_op_class_t *get_next_pre_set_op_class_by_type(em_op_class_type_t type, dm_op_class_t *op_class) = 0;

};

#endif

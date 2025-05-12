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

#ifndef DB_EASY_MESH_H
#define DB_EASY_MESH_H

#include "em_base.h"
#include "db_column.h"
#include "db_client.h"
#include <cjson/cJSON.h>

class db_easy_mesh_t {

public: 
    db_table_name_t m_table_name;
    unsigned int    m_num_cols;
    db_column_t     m_columns[EM_MAX_COLS];  

public:
    
	/**!
	 * @brief Initializes the table.
	 *
	 * This function is responsible for setting up the initial state of the table.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void init_table() = 0;
    
	/**!
	 * @brief Initializes the columns for the database.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 * It sets up the necessary columns for the database operations.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	virtual void init_columns() = 0;
    
	/**!
	 * @brief Synchronizes the database with the provided client context.
	 *
	 * This function is responsible for ensuring that the database state is
	 * consistent with the client context provided. It is a pure virtual
	 * function and must be implemented by derived classes.
	 *
	 * @param[in] db_client Reference to the database client object.
	 * @param[in] ctx Pointer to the context for synchronization.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval non-zero error code on failure.
	 *
	 * @note This function must be overridden in derived classes.
	 */
	virtual int sync_db(db_client_t& db_client, void *ctx) = 0;
    
	/**!
	 * @brief Updates the database with the given operation type and data.
	 *
	 * This function is responsible for updating the database using the provided client, operation type, and data.
	 *
	 * @param[in] db_client Reference to the database client used for the update.
	 * @param[in] op The type of operation to perform on the database.
	 * @param[in] data Pointer to the data used for the update operation.
	 *
	 * @returns int Status code indicating the success or failure of the update operation.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual int update_db(db_client_t& db_client, dm_orch_type_t op, void *data) = 0;
    
	/**!
	 * @brief Searches the database using the provided key.
	 *
	 * This function attempts to find an entry in the database that matches the given key.
	 *
	 * @param[out] db_client A reference to the database client that will be used for the search.
	 * @param[in] ctx A pointer to the context information required for the search operation.
	 * @param[in] key A pointer to the key used to search the database.
	 *
	 * @returns True if the search is successful, false otherwise.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual bool search_db(db_client_t& db_client, void *ctx, void *key) = 0;
    virtual bool operator == (const db_easy_mesh_t& obj) = 0;

    
	/**!
	 * @brief Set the configuration for the database client.
	 *
	 * This function sets the configuration for the provided database client using the JSON object.
	 *
	 * @param[in] db_client Reference to the database client object to be configured.
	 * @param[in] obj Pointer to a cJSON object containing the configuration settings.
	 * @param[in] parent_id Pointer to the parent identifier, if applicable.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval non-zero error code on failure.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id) = 0;
    
	/**!
	 * @brief Retrieves the configuration settings.
	 *
	 * This function is responsible for obtaining the configuration settings and populating the provided JSON object.
	 *
	 * @param[out] obj A pointer to a cJSON object where the configuration will be stored.
	 * @param[in] parent_id A pointer to the parent identifier used for retrieving specific configuration settings.
	 * @param[in] summary A boolean flag indicating whether to retrieve a summary of the configuration.
	 *
	 * @returns An integer status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual int get_config(cJSON *obj, void *parent_id, bool summary = false) = 0;

    
	/**!
	 * @brief Retrieves the column format based on the specified format and position.
	 *
	 * This function returns a string representation of the column format for a given
	 * database format type and position.
	 *
	 * @param[in] fmt The database format type.
	 * @param[in] pos The position within the format.
	 *
	 * @returns A pointer to a character string representing the column format.
	 *
	 * @note Ensure that the position is within the valid range for the specified format.
	 */
	char *get_column_format(db_fmt_t fmt, unsigned int pos);
    
	/**!
	 * @brief Retrieves strings based on a specified token.
	 *
	 * This function processes the given parent string and extracts substrings
	 * based on the provided token. The extracted strings are stored in the argv array.
	 *
	 * @param[in] parent The parent string to be processed.
	 * @param[in] token The token used to identify substrings within the parent.
	 * @param[in] argc The number of arguments expected in the argv array.
	 * @param[out] argv Array to store the extracted strings.
	 *
	 * @returns int The number of strings successfully extracted.
	 * @retval 0 if no strings are extracted.
	 * @retval -1 if an error occurs during processing.
	 *
	 * @note Ensure that the argv array has sufficient space to store the extracted strings.
	 */
	int get_strings_by_token(char *parent, int token, unsigned int argc, char *argv[]);

    
	/**!
	 * @brief Creates a table using the provided database client.
	 *
	 * This function initializes a new table in the database using the given
	 * database client object. It ensures that the table is set up correctly
	 * and ready for data operations.
	 *
	 * @param[in] db_client Reference to the database client object used to
	 *                      create the table.
	 *
	 * @returns int Status code indicating the success or failure of the
	 *              table creation operation.
	 * @retval 0 Table created successfully.
	 * @retval -1 Failed to create table due to an error.
	 *
	 * @note Ensure that the db_client is properly initialized before calling
	 *       this function.
	 */
	int create_table(db_client_t& db_client);
    
	/**!
	 * @brief Loads a table using the provided database client.
	 *
	 * This function initializes and loads a table from the database using the given
	 * database client reference. It ensures that the table is ready for operations.
	 *
	 * @param[in] db_client Reference to the database client used for loading the table.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Success
	 * @retval non-zero Failure
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int load_table(db_client_t& db_client);
    
	/**!
	 * @brief Synchronizes the table with the database client.
	 *
	 * This function ensures that the table is in sync with the provided database client.
	 *
	 * @param[in] db_client Reference to the database client to sync with.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval non-zero on failure.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int sync_table(db_client_t& db_client);
    
	/**!
	 * @brief Deletes a table from the database using the provided database client.
	 *
	 * This function interfaces with the database client to remove a specified table.
	 *
	 * @param[in] db_client Reference to the database client used to perform the deletion.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	void delete_table(db_client_t& db_client);

    
	/**!
	 * @brief Checks if the table is empty.
	 *
	 * This function determines whether the specified table in the database is empty.
	 *
	 * @param[in] db_client Reference to the database client object.
	 *
	 * @returns True if the table is empty, false otherwise.
	 */
	bool is_table_empty(db_client_t& db_client);
    
	/**!
	 * @brief Checks if an entry exists in the database table.
	 *
	 * This function determines whether a specific entry, identified by the given key,
	 * exists within the database table managed by the provided database client.
	 *
	 * @param[in] db_client Reference to the database client managing the table.
	 * @param[in] key Pointer to the key used to identify the entry in the table.
	 *
	 * @returns True if the entry exists, false otherwise.
	 *
	 * @note Ensure that the key is valid and corresponds to the expected format
	 * for the database table.
	 */
	bool entry_exists_in_table(db_client_t& db_client, void *key);

    
	/**!
	 * @brief Inserts a row into the database using the provided database client.
	 *
	 * This function is responsible for adding a new row to the database. The specific details of the row
	 * to be inserted are provided through the variadic arguments.
	 *
	 * @param[in] db_client Reference to the database client used for the operation.
	 * @param[in] ... Variadic arguments representing the data to be inserted into the row.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval non-zero on failure.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int insert_row(db_client_t& db_client, ...);
    
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
	 * @brief Compares a row in the database.
	 *
	 * This function compares a row in the database using the provided database client.
	 *
	 * @param[in] db_client Reference to the database client used for comparison.
	 * @param[in] ... Additional parameters for row comparison.
	 *
	 * @returns int Result of the comparison.
	 * @retval 0 if the rows are equal.
	 * @retval Non-zero if the rows are not equal.
	 *
	 * @note Ensure the database client is properly initialized before calling this function.
	 */
	int compare_row(db_client_t& db_client, ...);
    
	/**!
	 * @brief Deletes a row from the database using the specified client.
	 *
	 * This function interacts with the database to remove a specific row based on the provided parameters.
	 *
	 * @param[in] db_client Reference to the database client used for the operation.
	 * @param[in] ... Additional parameters specifying the row to be deleted.
	 *
	 * @returns int Status code of the operation.
	 * @retval 0 Success.
	 * @retval non-zero Failure, with specific error codes indicating the type of error.
	 *
	 * @note Ensure that the db_client is properly initialized before calling this function.
	 */
	int delete_row(db_client_t& db_client, ...);
    
    
	/**!
	 * @brief Constructor for the db_easy_mesh_t class.
	 *
	 * This constructor initializes a new instance of the db_easy_mesh_t class.
	 *
	 * @note This is a default constructor and does not take any parameters.
	 */
	db_easy_mesh_t();
    
	/**!
	 * @brief Destructor for the db_easy_mesh_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the db_easy_mesh_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	virtual ~db_easy_mesh_t();
};

#endif

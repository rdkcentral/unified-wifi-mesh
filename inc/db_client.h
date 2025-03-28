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


#ifndef DB_CLIENT_H
#define DB_CLIENT_H

/**!
 * @brief Database client class to manage database connections and queries.
 *
 * This class provides methods for initializing, executing queries,
 * and retrieving results from a database.
 *
 * @note This class is not thread-safe.
 */
class db_client_t {
    void *m_driver; ///< Database driver instance
    void *m_con; ///< Database connection instance

    /**!
     * @brief Establish a connection to the database.
     *
     * @param[in] path Path to the database.
     *
     * @returns 0 on success, non-zero on failure.
     * @retval 0 Connection successful.
     * @retval -1 Connection failed.
     *
     * @note This function must be called before executing queries.
     */
    int connect(const char *path);

public:
    /**!
     * @brief Initialize the database connection.
     *
     * @param[in] path Path to the database.
     *
     * @returns 0 on success, non-zero on failure.
     * @retval 0 Initialization successful.
     * @retval -1 Initialization failed.
     *
     * @note This function should be called before performing any database operations.
     */
    int init(const char *path);

    /**!
     * @brief Execute a SQL query on the database.
     *
     * @param[in] query SQL query to execute.
     *
     * @returns Pointer to result context on success, NULL on failure.
     *
     * @note Caller is responsible for handling the returned result context.
     */
    void *execute(const char *query);

    /**!
     * @brief Retrieve the next result from the query execution.
     *
     * @param[in] ctx Result context.
     *
     * @returns True if there is another result, false otherwise.
     *
     * @note The result context must be valid and obtained from execute().
     */
    bool next_result(void *ctx);

    /**!
     * @brief Retrieve a string value from the result context.
     *
     * @param[in] ctx Result context.
     * @param[out] res Buffer to store the retrieved string.
     * @param[in] col Column index from which to retrieve the string.
     *
     * @returns Pointer to the result buffer containing the string.
     *
     * @note Ensure the buffer size is sufficient to store the retrieved string.
     */
    char *get_string(void *ctx, char *res, unsigned int col);

    /**!
     * @brief Retrieve an integer value from the result context.
     *
     * @param[in] ctx Result context.
     * @param[in] col Column index from which to retrieve the number.
     *
     * @returns Retrieved integer value.
     *
     * @note Ensure the result context is valid before calling this function.
     */
    int get_number(void *ctx, unsigned int col);

    /**!
     * @brief Recreate the database, deleting existing data and creating a fresh structure.
     *
     * @returns 0 on success, non-zero on failure.
     *
     * @note Use with caution as this will erase all existing data.
     */
    int recreate_db();

    /**!
     * @brief Constructor that initializes the database client.
     *
     * Initializes internal members to NULL.
     *
     * @note The database connection is not established in the constructor.
     */
    db_client_t();

    /**!
     * @brief Destructor that cleans up database resources.
     *
     * Ensures the connection and driver are properly released.
     */
    ~db_client_t();	
};

#endif

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

#include <sqlite3.h>
#include <mutex>

 /**!
  * @brief Database client class to manage database connections and queries.
  *
  * This class provides methods for initializing, executing queries,
  * and retrieving results from a database using the MariaDB C client library.
  *
  * @note This class is not thread-safe.
  */
 class db_client_t {
sqlite3 *m_con;
char m_path[512];
std::mutex m_mutex;


	 /**!
	  * @brief Establish a connection to the database.
	  *
	  * This function attempts to establish a connection to the specified database
	  * using the provided path. It is essential to call this function before
	  * executing any database queries to ensure a valid connection is established.
	  *
	  * @param[in] path A constant character pointer representing the path to the
	  * database in the format "username@password".
	  *
	  * @returns An integer indicating the success or failure of the connection
	  * attempt.
	  * @retval 0 Connection successful.
	  * @retval -1 Connection failed due to invalid path or other errors.
	  *
	  * @note Ensure that the database server is running and accessible before
	  * calling this function. Failure to do so may result in a connection error.
	  */
	 int connect(const char *path);

 public:

	 /**!
	  * @brief Initialize the database connection.
	  *
	  * This function sets up the necessary environment to interact with the database
	  * specified by the given path. It must be called before any other database
	  * operations are performed.
	  *
	  * @param[in] path Path to the SQLite database file. When null or empty, the default deployment path is used.
	  *
	  * @returns 0 on success, non-zero on failure.
	  * @retval 0 Initialization successful.
	  * @retval -1 Initialization failed due to an invalid path or other errors.
	  *
	  * @note Ensure that the path is correct and accessible by the application.
	  */
	 int init(const char *path);


	 /**!
	  * @brief Execute a SQL query on the database.
	  *
	  * This function takes a SQL query as input and executes it on the connected database.
	  *
	  * @param[in] query SQL query to execute. This should be a valid SQL statement.
	  * @param[out] succeeded Optional. Receives the status of this execution:
	  *             true when the statement completed (with or without rows),
	  *             false on preparation or execution errors. The status is
	  *             specific to this call and is not affected by concurrent queries.
	  *
	  * @returns Pointer to result context when the query returned rows, NULL otherwise.
	  *
	  * @note Caller is responsible for handling the returned result context.
	  *       The context will be automatically freed when next_result() returns false.
	  */
	 void *execute(const char *query, bool *succeeded = NULL);

	 /**
	  * @brief Escapes a string for use as a quoted SQL value.
	  *
	  * SQLite escaping contract: the only character with special meaning inside a single-quoted
	  * SQLite string literal is the single quote, which is escaped by doubling it (' -> '').
	  * Nothing else is altered (no backslash escapes). The result must be placed between single
	  * quotes by the caller; it is not safe for identifiers or unquoted contexts. The source is
	  * treated as a C string, so embedded NUL bytes end it.
	  *
	  * @param[in] src Null-terminated source string.
	  * @param[out] dst Buffer receiving the escaped string.
	  * @param[in] dst_size Destination buffer size, including the null terminator.
	  * @returns true on success. false if the connection or buffer is invalid, or the escaped
	  *          string (plus terminator) does not fit; dst is then set to an empty string and
	  *          must not be used in a query.
	  */
	 bool escape_string(const char *src, char *dst, unsigned int dst_size) const;


	 /**!
	  * @brief Retrieve the next result from the query execution.
	  *
	  * This function checks if there is another result available in the
	  * result context provided. It is typically used in a loop to
	  * iterate over all results of a query.
	  *
	  * @param[in] ctx Result context. This should be a valid context
	  * obtained from a previous call to execute().
	  *
	  * @returns True if there is another result available, false otherwise.
	  *
	  * @note When this function returns false, it automatically frees the result context,
	  *       so you don't need to call free_result() manually.
	  *       If you need to release the result context before fully iterating, use free_result().
	  */
	 bool next_result(void *ctx);


	 /**!
	  * @brief Release a result context before it has been drained by next_result().
	  *
	  * Callers that stop iterating early (e.g. after finding a match) must use
	  * this instead of leaving the context to leak.
 	  * @note The context is freed automatically when next_result() returns false.
 	  *       Do not call free_result() after fully draining results, and do not
 	  *       use ctx after next_result() returns false or free_result() is called.
	  *
	  * @param[in] ctx Result context obtained from execute(). Safe to call with NULL.
	  */
	 void free_result(void *ctx);


	 /**!
	  * @brief Retrieve a string value from the result context.
	  *
	  * This function extracts a string from a specified column in the result context and stores it in the provided buffer.
	  *
	  * @param[in] ctx Result context from which the string is retrieved.
	  * @param[out] res Buffer to store the retrieved string. The buffer must be pre-allocated and large enough to hold the string.
	  * @param[in] col Column index from which to retrieve the string (1-based).
	  *
	  * @returns Pointer to the result buffer containing the string, or NULL on error.
	  *
	  * @note Ensure the buffer size is sufficient to store the retrieved string to avoid buffer overflow.
	  */
	 char *get_string(void *ctx, char *res, unsigned int col);

	 /**!
	  * @brief Retrieve a string value, bounded by the destination buffer size.
	  *
	  * @param[in] ctx Result context from which the string is retrieved.
	  * @param[out] res Buffer to store the retrieved string.
	  * @param[in] col Column index from which to retrieve the string (1-based).
	  * @param[in] res_sz Size of res in bytes, including the terminator. The value is truncated to
	  *            res_sz - 1 characters and always NUL-terminated. 0 means the caller guarantees the
	  *            buffer holds the whole database field plus terminator (unbounded; prefer a size).
	  *
	  * @returns Pointer to the result buffer containing the string, or NULL if ctx/res is NULL, col
	  *          is 0, or the column is NULL (res is left untouched in that case).
	  */
	 char *get_string(void *ctx, char *res, unsigned int col, unsigned int res_sz);
	 /**!
	  * @brief Retrieve an integer value from the result context.
	  *
	  * This function extracts an integer from a specified column in the result context.
	  *
	  * @param[in] ctx Result context from which the integer is retrieved. It must be a valid pointer.
	  * @param[in] col Column index from which to retrieve the number (1-based).
	  *
	  * @returns The integer value retrieved from the specified column.
	  *
	  * @note Ensure the result context is valid before calling this function. Invalid contexts may lead to undefined behavior.
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

	 int begin_transaction();
	 int commit();
	 int rollback();


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
	  * Ensures the connection is properly released.
	  *
	  * @note This destructor is automatically called when the db_client_t object goes out of scope.
	  */
	 ~db_client_t();
 };

 #endif

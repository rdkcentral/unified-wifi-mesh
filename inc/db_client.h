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

#include "em_base.h"
#if defined(OPENWRT_BUILD) || defined(RDKB_BUILD)
// MariaDB C client header for cross-compiled builds (OpenWRT / RDKB), where headers are under <mysql/>
#include <mysql/mysql.h>
#else
// MariaDB C client header for a standard Linux install (Debian)
#include <mariadb/mysql.h>
#endif

/**!
 * @brief Abstract persistence-backend interface used by db_easy_mesh_t (and,
 * transitively, every dm_*_list_t table class) to create/load/sync/mutate
 * tables.
 *
 * This class used to be a concrete MariaDB wrapper. It has been turned into
 * a Strategy interface so the controller can bind to different persistence
 * backends (see db_client_type_t) without touching a single line of the
 * dm_*_list_t / db_easy_mesh_t table logic, which only ever depends on this
 * interface (passed around as db_client_t&).
 *
 * Concrete implementations:
 *   - db_client_local_t (db_client_local.h)  : existing on-box MariaDB/MySQL
 *   - db_client_cloud_t (db_client_cloud.h)  : reserved for future cloud DB
 *   - db_client_none_t  (db_client_none.h)   : no-op / in-memory-only backend
 *
 * Use db_client_t::create() to obtain the correct implementation for a given
 * db_client_type_t rather than constructing one directly.
 *
 * @note Implementations are not required to be thread-safe.
 */
class db_client_t {

public:

    /**!
     * @brief Initialize the database connection/backend.
     *
     * This function sets up the necessary environment to interact with the
     * backend identified by the given path/connection-string. It must be
     * called before any other database operations are performed.
     *
     * @param[in] path Backend-specific connection info (e.g. "user@password"
     * for the local MariaDB backend). Backends that need no connection info
     * (such as the no-db backend) ignore this parameter.
     *
     * @returns 0 on success, non-zero on failure.
     */
    virtual int init(const char *path) = 0;

    /**!
     * @brief Execute a query/command against the backend.
     *
     * @param[in] query Backend-specific query string (SQL for the local/cloud
     * backends). Backends without a query language (e.g. no-db) may ignore
     * the content and simply return an empty result context.
     *
     * @returns Pointer to an opaque result context on success, NULL on
     * failure. Callers must not assume anything about the context other than
     * passing it back into next_result()/get_string()/get_number().
     */
    virtual void *execute(const char *query) = 0;

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
    virtual bool next_result(void *ctx) = 0;

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
    virtual void free_result(void *ctx) = 0;

    /**!
     * @brief Retrieve a string value from the current result row.
     *
     * @param[in] ctx Result context.
     * @param[out] res Buffer to store the retrieved string.
     * @param[in] col Column index (1-based).
     *
     * @returns Pointer to res, or NULL on error / no data.
     */
    virtual char *get_string(void *ctx, char *res, unsigned int col) = 0;

    /**!
     * @brief Retrieve an integer value from the current result row.
     *
     * @param[in] ctx Result context.
     * @param[in] col Column index (1-based).
     *
     * @returns The integer value, or 0 if there is no data.
     */
    virtual int get_number(void *ctx, unsigned int col) = 0;

    /**!
     * @brief Recreate the backend store, deleting existing data.
     *
     * @returns 0 on success, non-zero on failure.
     *
     * @note Use with caution as this will erase all existing data. No-op for
     * backends that hold no persistent data.
     */
    virtual int recreate_db() = 0;

    /**!
     * @brief Identifies which concrete backend this instance implements.
     * Lets callers make backend-specific decisions (e.g. whether an "empty
     * table" result at startup should trigger a DB provisioning script)
     * without needing an RTTI dynamic_cast.
     *
     * @returns The db_client_type_t this instance implements.
     */
    virtual db_client_type_t get_type() const = 0;

    /**!
     * @brief Whether this backend actually persists/reads data.
     *
     * Callers building query strings (db_easy_mesh_t) use this to skip that
     * work entirely for backends that would just discard it, without having
     * to know which concrete backend (present or future) that applies to.
     *
     * @returns True if execute()/next_result() do real work, false if they
     * are no-ops (e.g. db_client_none_t).
     */
    virtual bool is_persistent() const { return true; }

    virtual ~db_client_t() {}
};

db_client_t *db_client_create(db_client_type_t type);
db_client_type_t db_client_type_from_string(const char *name);

#endif

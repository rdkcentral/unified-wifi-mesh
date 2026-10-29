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

#ifndef DB_CLIENT_LOCAL_H
#define DB_CLIENT_LOCAL_H

#include "db_client.h"
#include <sqlite3.h>
#include <mutex>

/**!
 * @brief db_client_type_local implementation of db_client_t: the existing,
 * on-box SQLite-backed database client. Behavior is unchanged from the
 * original (pre-refactor) db_client_t.
 *
 * @note SQLite operations are serialized by the connection mutex.
 */
class db_client_local_t : public db_client_t {
    sqlite3 *m_con;
    std::mutex m_mutex;
    char m_path[512];

    /**!
     * @brief Establish a connection to the database.
     *
     * @param[in] path Database file path, or NULL/empty to use EASYMESH_DB_FILE
     * or the default database location.
     *
     * @returns 0 on success, -1 on failure.
     */
    int connect(const char *path);

public:

    int init(const char *path) override;
    void *execute(const char *query) override;
    bool next_result(void *ctx) override;
    void free_result(void *ctx) override;
    char *get_string(void *ctx, char *res, unsigned int col) override;
    int get_number(void *ctx, unsigned int col) override;
    int recreate_db() override;
    int begin_transaction() override;
    int commit() override;
    int rollback() override;
    db_client_type_t get_type() const override { return db_client_type_local; }

    db_client_local_t();
    virtual ~db_client_local_t();
};

#endif

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

#if defined(OPENWRT_BUILD) || defined(RDKB_BUILD)
// MariaDB C client header for cross-compiled builds (OpenWRT / RDKB), where headers are under <mysql/>
#include <mysql/mysql.h>
#else
// MariaDB C client header for a standard Linux install (Debian)
#include <mariadb/mysql.h>
#endif

/**!
 * @brief db_client_type_local implementation of db_client_t: the existing,
 * on-box MariaDB-backed database client. Behavior is unchanged from the
 * original (pre-refactor) db_client_t.
 *
 * @note This class is not thread-safe.
 */
class db_client_local_t : public db_client_t {
    MYSQL *m_con;    ///< MariaDB connection instance

    /**!
     * @brief Establish a connection to the database.
     *
     * @param[in] path A constant character pointer representing the path to the
     * database in the format "username@password".
     *
     * @returns 0 on success, -1 on failure.
     */
    int connect(const char *path);

public:

    int init(const char *path) override;
    void *execute(const char *query) override;
    bool next_result(void *ctx) override;
    char *get_string(void *ctx, char *res, unsigned int col) override;
    int get_number(void *ctx, unsigned int col) override;
    int recreate_db() override;
    db_client_type_t get_type() const override { return db_client_type_local; }

    db_client_local_t();
    virtual ~db_client_local_t();
};

#endif

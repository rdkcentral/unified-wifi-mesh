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

#ifndef DB_CLIENT_NONE_H
#define DB_CLIENT_NONE_H

#include "db_client.h"

/**!
 * @brief db_client_type_none implementation of db_client_t.
 *
 * This backend persists nothing. Every operation is a cheap no-op that
 * reports "no data" (init() succeeds, execute() returns NULL, next_result()
 * is always false, get_string()/get_number() return empty/zero).
 *
 * Why this is enough to make "No DB" work:
 *
 * Every dm_*_list_t table class (e.g. dm_radio_list_t) already keeps its
 * authoritative state in an in-memory container (hash maps owned by
 * dm_easy_mesh_list_t / dm_xx_list_t, accessed via get_xx/put_xx/remove_xx).
 * db_easy_mesh_t::set_config() drives two independent things per entry:
 *   1. update_db()  -> issues the persistence read/write (insert/update/delete
 *                      row) via the db_client_t reference.
 *   2. update_list() -> mutates the in-memory container directly.
 *
 * Because (2) never depends on (1) succeeding or doing anything real, simply
 * making (1) a no-op leaves the controller's in-memory data model fully
 * functional: sets, gets, orchestration, and northbound queries all keep
 * working, and nothing is ever written to or read from disk.
 *
 * At startup, db_easy_mesh_t::load_table()/is_table_empty() will report
 * every table as empty (since execute()/next_result() never produce rows).
 * The controller's init() flow (dm_easy_mesh_ctrl_t::init()) treats that as
 * the expected steady-state for db_client_type_none rather than as an error
 * requiring an on-box DB provisioning script.
 */
class db_client_none_t : public db_client_t {

public:

    int init(const char *path) override;
    void *execute(const char *query) override;
    bool next_result(void *ctx) override;
    char *get_string(void *ctx, char *res, unsigned int col) override;
    int get_number(void *ctx, unsigned int col) override;
    int recreate_db() override;
    db_client_type_t get_type() const override { return db_client_type_none; }

    db_client_none_t();
    virtual ~db_client_none_t();
};

#endif

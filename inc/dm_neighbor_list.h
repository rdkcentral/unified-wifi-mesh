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

#ifndef DM_NEIGHBOR_LIST_H
#define DM_NEIGHBOR_LIST_H

#include "em_base.h"
#include "dm_neighbor.h"
#include "db_easy_mesh.h"

class dm_easy_mesh_t;

class dm_neighbor_list_t : public dm_neighbor_t, public db_easy_mesh_t {

public:
    int init();

	/**!
	 * @brief Builds the key identifying a neighbor entry in the in-memory list.
	 *
	 * A neighbor is identified by the tuple (reporting device AL MAC, local interface MAC,
	 * neighbor MAC, IEEE1905 flag); the neighbor MAC alone is not unique because a device
	 * reports the same neighbor on every interface that can reach it.
	 *
	 * @param[in] info Neighbor record to derive the key from.
	 * @param[out] key Receives the formatted key.
	 *
	 * @note The key is not stored in the database; the table is keyed on the equivalent columns.
	 */
    static void make_key(const em_neighbor_info_t *info, em_long_string_t key);

    dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_neighbor_t& bss);
    void update_list(const dm_neighbor_t& bss, dm_orch_type_t op);	
    void delete_list();

    void init_table();
    void init_columns();
    int sync_db(db_client_t& db_client, void *ctx);
    int update_db(db_client_t& db_client, dm_orch_type_t op, void *data);
    bool search_db(db_client_t& db_client, void *ctx, void *key);
    bool operator == (const db_easy_mesh_t& obj);
    int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    int set_config(db_client_t& db_client, dm_neighbor_t& bss, void *parent_id);
    int get_config(cJSON *obj, void *parent_id, bool summary = false);

    virtual dm_neighbor_t *get_first_neighbor() = 0;
    virtual dm_neighbor_t *get_next_neighbor(dm_neighbor_t *bss) = 0;
    virtual dm_neighbor_t *get_neighbor(const char *key) = 0;
    virtual void remove_neighbor(const char *key) = 0;
    virtual void put_neighbor(const char *key, const dm_neighbor_t *bss) = 0;

private:
	/**!
	 * @brief Builds the SQL predicate that selects exactly one neighbor row.
	 *
	 * @param[in] info Neighbor record to match.
	 * @param[out] where Receives the predicate, without the leading "where".
	 *
	 * @note Needed because the generic row helpers in db_easy_mesh_t key off column 0 only,
	 * which is not unique for this table.
	 */
    static void make_where_clause(const em_neighbor_info_t *info, em_2xlong_string_t where);

	/**!
	 * @brief Checks whether a neighbor row is already present in the table.
	 *
	 * @param[in] db_client Database client to query.
	 * @param[in] info Neighbor record to look for.
	 *
	 * @returns true if the row exists, false if it does not or the query failed.
	 *
	 * @note Used instead of entry_exists_in_table(), which fetches and scans the whole
	 * table and would therefore cost O(rows) for each of the many neighbors a device reports.
	 */
    bool row_exists(db_client_t& db_client, const em_neighbor_info_t *info);

};

#endif

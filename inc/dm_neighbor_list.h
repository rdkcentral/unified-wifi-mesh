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

};

#endif

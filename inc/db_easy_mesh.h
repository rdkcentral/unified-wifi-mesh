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
    virtual void init_table() = 0;
    virtual void init_columns() = 0;
    virtual int sync_db(db_client_t& db_client, void *ctx) = 0;
    virtual int update_db(db_client_t& db_client, dm_orch_type_t op, void *data) = 0;
    virtual bool search_db(db_client_t& db_client, void *ctx, void *key) = 0;
    virtual bool operator == (const db_easy_mesh_t& obj) = 0;

    virtual int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id) = 0;
    virtual int get_config(cJSON *obj, void *parent_id, bool summary = false) = 0;

    char *get_column_format(db_fmt_t fmt, unsigned int pos);
    int get_strings_by_token(char *parent, int token, unsigned int argc, char *argv[]);

    int create_table(db_client_t& db_client);
    int load_table(db_client_t& db_client);
    int sync_table(db_client_t& db_client);
    void delete_table(db_client_t& db_client);

    bool is_table_empty(db_client_t& db_client);
    bool entry_exists_in_table(db_client_t& db_client, void *key);

    int insert_row(db_client_t& db_client, ...);
    int update_row(db_client_t& db_client, ...);
    int compare_row(db_client_t& db_client, ...);
    int delete_row(db_client_t& db_client, ...);
    
    db_easy_mesh_t();
    virtual ~db_easy_mesh_t();
};

#endif

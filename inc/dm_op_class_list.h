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

#ifndef DM_OP_CLASS_LIST_H
#define DM_OP_CLASS_LIST_H

#include "em_base.h"
#include "dm_op_class.h"
#include "db_easy_mesh.h"

class dm_easy_mesh_t;
class dm_op_class_list_t : public dm_op_class_t, public db_easy_mesh_t {

public:
    int init();

    dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_op_class_t& op_class);
    void update_list(const dm_op_class_t& op_class, dm_orch_type_t op);
    void delete_list();

    void init_table();
    void init_columns();
    int sync_db(db_client_t& db_client, void *ctx);
    int update_db(db_client_t& db_client, dm_orch_type_t op, void *data);
    bool search_db(db_client_t& db_client, void *ctx, void *key);
    bool operator == (const db_easy_mesh_t& obj);
    int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    int set_config(db_client_t& db_client, dm_op_class_t& op_class, void *parent_id);
    int get_config(cJSON *obj, void *parent_id, bool summary = false);
    void get_config(cJSON *obj, em_op_class_type_t type);

    virtual dm_op_class_t *get_first_op_class() = 0;
    virtual dm_op_class_t *get_next_op_class(dm_op_class_t *op_class) = 0;
    virtual dm_op_class_t *get_op_class(const char *key) = 0;
    virtual void remove_op_class(const char *key) = 0;
    virtual void put_op_class(const char *key, const dm_op_class_t *op_class) = 0;

	virtual dm_op_class_t *get_first_pre_set_op_class_by_type(em_op_class_type_t type) = 0;
	virtual dm_op_class_t *get_next_pre_set_op_class_by_type(em_op_class_type_t type, dm_op_class_t *op_class) = 0;

};

#endif

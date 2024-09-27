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

#ifndef DM_NETWORK_LIST_H
#define DM_NETWORK_LIST_H

#include "em_base.h"
#include "dm_network.h"
#include "db_easy_mesh.h"

class dm_network_list_t : public dm_network_t, public db_easy_mesh_t {
    hash_map_t  *m_list;

public:
    int init();

    int decode(const cJSON *obj_arr, void *parent_id);
    void encode(cJSON *obj_arr);

    dm_network_t *get_first() { return (dm_network_t *)hash_map_get_first(m_list); }
    dm_network_t *get_next(dm_network_t *net) { return (dm_network_t *)hash_map_get_next(m_list, net); }
    dm_network_t *get_network(em_long_string_t net_id) { return (dm_network_t *)hash_map_get(m_list, net_id); }

    dm_orch_type_t get_dm_orch_type(const dm_network_t& net);
    void update_list(const dm_network_t& net, dm_orch_type_t op);
    void delete_list();

    em_interface_t *get_ctrl_al_interface(em_long_string_t net_id);

    void init_table();
    void init_columns();
    void sync_db(db_client_t& db_client, void *ctx);
    int update_db(db_client_t& db_client, dm_orch_type_t op, void *data = NULL);
    bool operator == (const db_easy_mesh_t& obj);
    int set_config(db_client_t& db_client, dm_network_t& net, void *parent_id);
    int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    int get_config(cJSON *obj, void *parent_id);
};

#endif

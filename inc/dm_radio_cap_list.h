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

#ifndef DM_RADIO_CAP_LIST_H
#define DM_RADIO_CAP_LIST_H

#include "em_base.h"
#include "dm_radio_cap.h"
#include "db_easy_mesh.h"

class dm_radio_cap_list_t : public dm_radio_cap_t, public db_easy_mesh_t {
    hash_map_t  *m_list;

public:
    int init();

    dm_radio_cap_t *get_first() { return (dm_radio_cap_t *)hash_map_get_first(m_list); }
    dm_radio_cap_t  *get_next(dm_radio_cap_t *radio_cap) { return (dm_radio_cap_t *)hash_map_get_next(m_list, radio_cap); }

    dm_orch_type_t get_dm_orch_type(const dm_radio_cap_t& radio_cap);
    void update_list(const dm_radio_cap_t& radio_cap, dm_orch_type_t op);
    void delete_list();

    void init_table();
    void init_columns();
    void sync_db(db_client_t& db_client, void *ctx);
    int update_db(db_client_t& db_client, dm_orch_type_t op, void *data = NULL);
    bool operator == (const db_easy_mesh_t& obj);
    int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    int get_config(cJSON *obj, void *parent_id);

};

#endif

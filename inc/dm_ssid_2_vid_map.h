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

#ifndef DM_SSID_2_VID_MAP_H
#define DM_SSID_2_VID_MAP_H

#include "em_base.h"
#include "db_easy_mesh.h"

class dm_ssid_2_vid_map_t : public db_easy_mesh_t {
    em_ssid_2_vid_map_info_t    m_ssid_2_vid_map_info;
    hash_map_t  *m_list;

public:
    int init();

    em_ssid_2_vid_map_info_t *get_ssid_2_vid_map_info() { return &m_ssid_2_vid_map_info; }
    dm_ssid_2_vid_map_t *get_first() { return static_cast<dm_ssid_2_vid_map_t *>(hash_map_get_first(m_list)); }
    dm_ssid_2_vid_map_t *get_next(dm_ssid_2_vid_map_t *ssid_2_vid) { return static_cast<dm_ssid_2_vid_map_t *>(hash_map_get_next(m_list, ssid_2_vid)); }
    dm_orch_type_t update_list(const dm_ssid_2_vid_map_t& ssid_2_vid);

    void init_table();
    void init_columns();
    int sync_db(db_client_t& db_client, void *ctx);
    int update_db(db_client_t& db_client, dm_orch_type_t op, void *data);
    bool search_db(db_client_t& db_client, void *ctx, void *key);
    bool operator == (const db_easy_mesh_t& obj);
    int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    int get_config(cJSON *obj, void *parent_id, bool summary = false);

    dm_ssid_2_vid_map_t(em_ssid_2_vid_map_info_t *ssid_2_vid);
    dm_ssid_2_vid_map_t(const dm_ssid_2_vid_map_t& ssid_2_vid);
    dm_ssid_2_vid_map_t();
    ~dm_ssid_2_vid_map_t();
};

#endif

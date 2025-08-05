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

#ifndef DM_CSI_CONTAINER_LIST_H
#define DM_CSI_CONTAINER_LIST_H

#include "em_base.h"
#include "dm_csi_container.h"

class dm_easy_mesh_t;
class em_cmd_t;

class dm_csi_container_list_t : public dm_csi_container_t {

public:
    int init();
    int load_data();
    dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_csi_container_t& cont);
    void update_list(const dm_csi_container_t& cont, dm_orch_type_t op);   
    void delete_list();
    int analyze_config(const cJSON *obj_arr, void *parent_id, em_cmd_t *cmd[], em_cmd_params_t *param);
    int get_config(cJSON *obj, void *parent_id);
    int get_config(cJSON *obj, void *parent_id, bool summary = false);
    int get_data(cJSON *obj, void *key);
    virtual dm_csi_container_t *get_first_csi_container() = 0;
    virtual dm_csi_container_t *get_next_csi_container(dm_csi_container_t *cont) = 0;
    virtual dm_csi_container_t *get_csi_container(const char *key) = 0;
    virtual void remove_csi_container(const char *key) = 0;
    virtual void put_csi_container(const char *key, const dm_csi_container_t *cont) = 0;
};

#endif

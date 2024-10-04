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


#ifndef DM_EM_LIST_H
#define DM_EM_LIST_H

#include "em_base.h"
#include "dm_easy_mesh.h"

class dm_easy_mesh_list_t {
    em_long_string_t	m_network_list[EM_MAX_NETWORKS];
    unsigned int m_num_networks;
    hash_map_t  *m_list;

public:

    dm_easy_mesh_t *get_data_model(const char *net_id, const unsigned char *al_mac);
    dm_easy_mesh_t *create_data_model(const char *net_id, const unsigned char *al_mac, em_profile_type_t profile);
    void delete_data_model(const char *net_id, const unsigned char *al_mac);

    void init();

    dm_easy_mesh_t *get_first_dm() { return (dm_easy_mesh_t *)hash_map_get_first(m_list); }
    dm_easy_mesh_t *get_next_dm(dm_easy_mesh_t *dm) { return (dm_easy_mesh_t *)hash_map_get_next(m_list, dm); }

    dm_network_t *get_first_network();
    dm_network_t *get_next_network(dm_network_t *net);
    dm_network_t *get_network(const char *key);
    void remove_network(const char *key);
    void put_network(const char *key, const dm_network_t *net);

    dm_device_t *get_first_device();
    dm_device_t *get_next_device(dm_device_t *dev);
    dm_device_t *get_device(const char *key);
    void remove_device(const char *key);
    void put_device(const char *key, const dm_device_t *dev);

    dm_radio_t *get_first_radio();
    dm_radio_t *get_next_radio(dm_radio_t *radio);
    dm_radio_t *get_radio(const char *key);
    void remove_radio(const char *key);
    void put_radio(const char *key, const dm_radio_t *radio);

    dm_bss_t *get_first_bss();
    dm_bss_t *get_next_bss(dm_bss_t *bss);
    dm_bss_t *get_bss(const char *key);
    void remove_bss(const char *key);
    void put_bss(const char *key, const dm_bss_t *bss);

    dm_sta_t *get_first_sta();
    dm_sta_t *get_next_sta(dm_sta_t *sta);
    dm_sta_t *get_sta(const char *key);
    void remove_sta(const char *key);
    void put_sta(const char *key, const dm_sta_t *sta);

    dm_network_ssid_t *get_first_network_ssid();
    dm_network_ssid_t *get_next_network_ssid(dm_network_ssid_t *network_ssid);
    dm_network_ssid_t *get_network_ssid(const char *key);
    void remove_network_ssid(const char *key);
    void put_network_ssid(const char *key, const dm_network_ssid_t *network_ssid);

    dm_op_class_t *get_first_op_class();
    dm_op_class_t *get_next_op_class(dm_op_class_t *op_class);
    dm_op_class_t *get_op_class(const char *key);
    void remove_op_class(const char *key);
    void put_op_class(const char *key, const dm_op_class_t *op_class);

    dm_easy_mesh_list_t();
    ~dm_easy_mesh_list_t();
};

#endif


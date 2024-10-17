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

#ifndef DM_EM_CTRL_H
#define DM_EM_CTRL_H

#include "em_base.h"
#include "dm_network_list.h"
#include "dm_device_list.h"
#include "dm_network_ssid_list.h"
#include "dm_ieee_1905_security_list.h"
#include "dm_radio_list.h"
#include "dm_radio_cap_list.h"
#include "dm_op_class_list.h"
#include "dm_bss_list.h"
#include "dm_sta_list.h"
#include "dm_dpp.h"
#include "db_client.h"
#include "dm_easy_mesh_list.h"

class em_cmd_t;
class dm_easy_mesh_t;

class dm_easy_mesh_ctrl_t :

    public dm_network_list_t, public dm_device_list_t, public dm_network_ssid_list_t,
    public dm_ieee_1905_security_list_t, public dm_radio_list_t, public dm_radio_cap_list_t,
        
    public dm_op_class_list_t, public dm_bss_list_t, public dm_sta_list_t {

    db_client_t m_db_client;
    bool	m_initialized;

    dm_easy_mesh_list_t	m_data_model_list;

    int set_device_list(cJSON *dev_list_obj);
    int set_radio_list(cJSON *radio_list_obj, mac_address_t *dev_mac);
    int set_bss_list(cJSON *bss_list_obj, mac_address_t *radio_mac);
    int set_op_class_list(cJSON *op_class_list_obj, mac_address_t *radio_mac);
    int set_radio_cap_list(cJSON *radio_cap_list_obj, mac_address_t *radio_mac);

public:
    int init(const char *data_model_path);

    bool    is_initialized() { return m_initialized; }
    void	set_initialized() { m_initialized = true; }

    //int analyze_network_ssid_list(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_set_ssid(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_set_channel(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_dpp_start(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_client_steer(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_reset(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_remove_device(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_m2_tx(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_config_renew(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_dev_test(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_radio_metrics_req(em_cmd_t *cmd[]);
    int analyze_ap_metrics_req(em_cmd_t *cmd[]);
    int analyze_client_metrics_req(em_cmd_t *cmd[]);

    int reset_config();
    int get_sta_config(cJSON *parent, char *key);
    int get_bss_config(cJSON *parent, char *key);
    int get_network_config(cJSON *parent, char *key);
    int get_device_config(cJSON *parent, char *key, bool summary = false);
    int get_radio_config(cJSON *parent, char *key);
    int get_network_ssid_config(cJSON *parent, char *key);
    int get_channel_config(cJSON *parent, char *key);
    int get_config(em_long_string_t net_id, em_subdoc_info_t *subdoc);
    int set_config(dm_easy_mesh_t *dm);
    int copy_config(dm_easy_mesh_t *dm, em_long_string_t net_id);

    em_interface_t *get_ctrl_al_interface(em_long_string_t net_id) { return dm_network_list_t::get_ctrl_al_interface(net_id); }

    dm_easy_mesh_t	*get_data_model(const char *net_id, const unsigned char *al_mac);   
    dm_easy_mesh_t	*create_data_model(const char *net_id, const unsigned char *al_mac, em_profile_type_t profile);    

    dm_network_t *get_first_network() { return m_data_model_list.get_first_network(); }
    dm_network_t *get_next_network(dm_network_t *net) { return m_data_model_list.get_next_network(net); }
    dm_network_t *get_network(const char *key) { return m_data_model_list.get_network(key); }
    void remove_network(const char *key) { m_data_model_list.remove_network(key); }
    void put_network(const char *key, const dm_network_t *net) { m_data_model_list.put_network(key, net); }
    
    dm_device_t *get_first_device() { return m_data_model_list.get_first_device(); }
    dm_device_t *get_next_device(dm_device_t *dev) { return m_data_model_list.get_next_device(dev); }
    dm_device_t *get_device(const char *key) { return m_data_model_list.get_device(key); }
    void remove_device(const char *key) { m_data_model_list.remove_device(key); }
    void put_device(const char *key, const dm_device_t *dev) { m_data_model_list.put_device(key, dev); }

    dm_radio_t *get_first_radio() { return m_data_model_list.get_first_radio(); }
    dm_radio_t *get_next_radio(dm_radio_t *radio) { return m_data_model_list.get_next_radio(radio); }
    dm_radio_t *get_radio(const char *key) { return m_data_model_list.get_radio(key); }
    void remove_radio(const char *key) { m_data_model_list.remove_radio(key); }
    void put_radio(const char *key, const dm_radio_t *radio) { m_data_model_list.put_radio(key, radio); }

    dm_bss_t *get_first_bss() { return m_data_model_list.get_first_bss(); }
    dm_bss_t *get_next_bss(dm_bss_t *bss) { return m_data_model_list.get_next_bss(bss); }
    dm_bss_t *get_bss(const char *key) { return m_data_model_list.get_bss(key); }
    void remove_bss(const char *key) { m_data_model_list.remove_bss(key); }
    void put_bss(const char *key, const dm_bss_t *bss) { m_data_model_list.put_bss(key, bss); }

    dm_sta_t *get_first_sta() { return m_data_model_list.get_first_sta(); }
    dm_sta_t *get_next_sta(dm_sta_t *sta) { return m_data_model_list.get_next_sta(sta); }
    dm_sta_t *get_sta(const char *key) { return m_data_model_list.get_sta(key); }
    void remove_sta(const char *key) { m_data_model_list.remove_sta(key); }
    void put_sta(const char *key, const dm_sta_t *sta) { m_data_model_list.put_sta(key, sta); }

    dm_op_class_t *get_first_op_class() { return m_data_model_list.get_first_op_class(); }
    dm_op_class_t *get_next_op_class(dm_op_class_t *op_class) { return m_data_model_list.get_next_op_class(op_class); }
    dm_op_class_t *get_op_class(const char *key) { return m_data_model_list.get_op_class(key); }
    void remove_op_class(const char *key) { m_data_model_list.remove_op_class(key); }
    void put_op_class(const char *key, const dm_op_class_t *op_class) { m_data_model_list.put_op_class(key, op_class); }

    dm_network_ssid_t *get_first_network_ssid() { return m_data_model_list.get_first_network_ssid(); }
    dm_network_ssid_t *get_next_network_ssid(dm_network_ssid_t *network_ssid) { return m_data_model_list.get_next_network_ssid(network_ssid); }
    dm_network_ssid_t *get_network_ssid(const char *key) { return m_data_model_list.get_network_ssid(key); }
    void remove_network_ssid(const char *key) { m_data_model_list.remove_network_ssid(key); }
    void put_network_ssid(const char *key, const dm_network_ssid_t *network_ssid) { m_data_model_list.put_network_ssid(key, network_ssid); }

    void handle_dirty_dm();
    void init_tables();
    int load_tables();
    int load_net_ssid_table();
    int update_tables(dm_easy_mesh_t *dm);
    void delete_data_model(const char *net_id, const unsigned char *al_mac) { m_data_model_list.delete_data_model(net_id, al_mac); }
    void delete_all_data_models() { m_data_model_list.delete_all_data_models(); }
    void debug_probe() { m_data_model_list.debug_probe(); }

    dm_easy_mesh_ctrl_t();
    ~dm_easy_mesh_ctrl_t(); 
};

#endif

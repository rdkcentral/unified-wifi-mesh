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

class em_cmd_t;
class dm_easy_mesh_t;

class dm_easy_mesh_ctrl_t {

    dm_network_list_t    m_network_list;
    dm_device_list_t     m_device_list;
    dm_network_ssid_list_t     m_network_ssid_list;
    dm_ieee_1905_security_list_t     m_ieee_1905_security_list;
    dm_radio_list_t m_radio_list;
    dm_radio_cap_list_t m_radio_cap_list;
    dm_op_class_list_t  m_op_class_list;
    dm_bss_list_t   m_bss_list;
    dm_sta_list_t   m_sta_list;
    dm_dpp_t    m_dpp;
    db_client_t m_db_client;

    int set_device_list(cJSON *dev_list_obj);
    int set_radio_list(cJSON *radio_list_obj, mac_address_t *dev_mac);
    int set_bss_list(cJSON *bss_list_obj, mac_address_t *radio_mac);
    int set_op_class_list(cJSON *op_class_list_obj, mac_address_t *radio_mac);
    int set_radio_cap_list(cJSON *radio_cap_list_obj, mac_address_t *radio_mac);

public:
    int init(const char *data_model_path);

    int analyze_network_ssid_list(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_dpp_start(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_client_steer(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_reset(em_bus_event_t *evt, em_cmd_t *cmd[]);
    int analyze_radio_metrics_req(em_cmd_t *cmd[]);
    int analyze_ap_metrics_req(em_cmd_t *cmd[]);
    int analyze_client_metrics_req(em_cmd_t *cmd[]);

    int reset_config();
    int get_config(em_subdoc_info_t *subdoc);
    int set_config(dm_easy_mesh_t *dm);
    int copy_config(dm_easy_mesh_t *dm, em_long_string_t net_id);

    em_interface_t *get_ctrl_al_interface(em_long_string_t net_id) { return m_network_list.get_ctrl_al_interface(net_id); }
    dm_ieee_1905_security_list_t *get_ieee_1905_security_list() { return &m_ieee_1905_security_list; }

    dm_easy_mesh_ctrl_t();
    ~dm_easy_mesh_ctrl_t(); 
};

#endif

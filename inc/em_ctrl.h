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

#ifndef EMCTRL_H
#define EMCTRL_H

#include "em.h"
#include "em_mgr.h"
#include "dm_easy_mesh_ctrl.h"
#include "em_orch_ctrl.h"

class em_cmd_ctrl_t;

class em_ctrl_t : public em_mgr_t {

    dm_easy_mesh_ctrl_t m_data_model;
    em_cmd_ctrl_t   *m_ctrl_cmd;
    em_orch_ctrl_t *m_orch;
    unsigned int m_tick_demultiplex;

    void handle_bus_event(em_bus_event_t *evt);

public:

    void input_listener();

    int data_model_init(const char *data_model_path);
    bool	is_data_model_initialized() { return m_data_model.is_initialized(); }
   
    int orch_init();

    void handle_dirty_dm();
    void handle_5s_timeout();
    void handle_timeout();
    void handle_event(em_event_t *evt);
    void handle_start_dpp(em_bus_event_t *evt);
    void handle_client_steer(em_bus_event_t *evt);
    void handle_set_ssid_list(em_bus_event_t *evt);
    void handle_set_channel_list(em_bus_event_t *evt);
    void handle_reset(em_bus_event_t *evt);
    void handle_dev_test(em_bus_event_t *evt);
    void handle_getdb(em_bus_event_t *evt);
    void handle_topology_req();
    void handle_radio_metrics_req();
    void handle_ap_metrics_req();
    void handle_client_metrics_req();
    void handle_get_dm_data(em_bus_event_t *evt);
    void handle_dm_commit(em_bus_event_t *evt);

    void io(void *data, bool input = true);
    bool io_process(em_event_t *evt);

    dm_easy_mesh_t *get_data_model(const char *net_id, const unsigned char *al_mac = NULL) { return m_data_model.get_data_model(net_id, al_mac); }
    dm_easy_mesh_t *create_data_model(const char *net_id, const unsigned char *al_mac, em_profile_type_t profile = em_profile_type_3) { return m_data_model.create_data_model(net_id, al_mac, profile); }

    em_service_type_t get_service_type() { return em_service_type_ctrl; }

    em_ctrl_t();
    ~em_ctrl_t();

};

#endif

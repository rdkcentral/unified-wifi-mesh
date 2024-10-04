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

#ifndef EM_CMD_H
#define EM_CMD_H

#include "em_base.h"
#include "em_ctrl.h"
#include <sys/time.h>
#include "dm_easy_mesh.h"

class em_cmd_t {
public:
    em_cmd_type_t   m_type;
    em_service_type_t   m_svc;
    em_cmd_params_t m_param;
    em_event_t  m_evt;
    em_string_t m_name;
    queue_t *m_em_candidates;
    dm_easy_mesh_t  m_data_model;
    struct timeval  m_start_time;

    unsigned int m_orch_op_idx;
    dm_orch_type_t  m_orch_op_array[EM_MAX_CMD];
    unsigned int m_num_orch_ops;
    em_freq_band_t m_rd_freq_band;
    unsigned int m_rd_op_class;
    unsigned int m_rd_channel;
    unsigned int	m_db_cfg_type;

public:
    int     load_params_file(char *buff);
    int 	write_params_file(char *buff);
    int 	edit_params_file();
    bool    validate();

    char *status_to_string(em_cmd_out_status_t status, em_status_string_t str);

    em_cmd_type_t get_type() { return m_type; }
    const char *get_cmd_name() { return m_name; }
    const char *get_arg() { return m_param.fixed_args; }
    em_service_type_t get_svc() { return m_svc; }
    em_event_t *get_event() { return &m_evt; }
    em_cmd_params_t *get_param() { return &m_param; }
    em_bus_event_t *get_bus_event() { return &m_evt.u.bevt; }
    dm_easy_mesh_t *get_data_model() { return &m_data_model; }

    void copy_bus_event(em_bus_event_t *evt) { m_evt.type = em_event_type_bus; memcpy(&m_evt.u.bevt, evt, sizeof(em_bus_event_t)); }

    virtual dm_orch_type_t get_orch_op() { return m_orch_op_array[m_orch_op_idx]; }
    virtual em_cmd_t *clone_for_next();
    virtual em_cmd_t *clone();
    virtual void set_orch_op_index(unsigned int idx) { m_orch_op_idx = idx; }
    virtual unsigned int get_orch_op_index() { return m_orch_op_idx; }
    virtual void override_op(unsigned int index, dm_orch_type_t op);
    

    em_interface_t *get_ctrl_al_interface() { return m_data_model.get_ctrl_al_interface(); }
    em_interface_t *get_agent_al_interface() { return m_data_model.get_agent_al_interface(); }
    em_interface_t *get_radio_interface(unsigned int index) { return m_data_model.get_radio_interface(index); }
        
    unsigned char *get_al_interface_mac() { return m_data_model.get_agent_al_interface_mac(); }
    char *get_manufacturer() { return m_data_model.get_manufacturer(); }
    char *get_manufacturer_model() { return m_data_model.get_manufacturer_model(); }
    char *get_serial_number() { return m_data_model.get_serial_number(); }
    em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() { return m_data_model.get_ieee_1905_security_cap(); }
    char *get_primary_device_type() { return m_data_model.get_primary_device_type(); }

    unsigned int get_num_network_ssid() { return m_data_model.get_num_network_ssid(); }

    dm_network_ssid_t *get_network_ssid(unsigned int index) { return m_data_model.get_network_ssid(index); }
    dm_dpp_t *get_dpp() { return m_data_model.get_dpp(); }
    dm_radio_t *get_radio(unsigned int index) { return m_data_model.get_radio(index); }
    dm_op_class_t *get_curr_op_class(unsigned int index) { return m_data_model.get_curr_op_class(index); }
    rdk_wifi_radio_t *get_radio_data(em_interface_t *radio) { return m_data_model.get_radio_data(radio); };
    em_freq_band_t get_curr_freq_band();
    void set_rd_freq_band(unsigned int i);
    em_freq_band_t get_rd_freq_band() { return m_rd_freq_band; }
    unsigned int get_rd_op_class() { return m_rd_op_class; }
    unsigned int get_rd_channel() { return m_rd_channel; }

    void set_start_time() { gettimeofday(&m_start_time, NULL);}

    void reset() { memset(&m_evt, 0, sizeof(em_event_t)); memset(&m_param, 0, sizeof(em_cmd_params_t));; }
    void init(dm_easy_mesh_t *dm);
    void init();
    void deinit();
    void reset_cmd_ctx() { m_data_model.reset_cmd_ctx(); }

    unsigned int get_db_cfg_type() { return m_db_cfg_type; }
    void set_db_cfg_type(unsigned int type) { m_db_cfg_type = type; }

    static em_cmd_type_t bus_2_cmd_type(em_bus_event_type_t type);
    static em_bus_event_type_t cmd_2_bus_event_type(em_cmd_type_t type);
    static const char *get_orch_op_str(dm_orch_type_t type);
    static const char *get_bus_event_type_str(em_bus_event_type_t type);
    static void dump_bus_event(em_bus_event_t *evt);
    
    em_cmd_t(em_cmd_type_t type, em_cmd_params_t param, dm_easy_mesh_t& dm);
    em_cmd_t(em_cmd_type_t type, em_cmd_params_t param);
    em_cmd_t();
    ~em_cmd_t();
};

#endif

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

#ifndef EM_MGR_H
#define EM_MGR_H

#include "em.h"
#include "em_orch.h"

class em_mgr_t {
   
    pthread_t   m_tid;
    bool m_exit;
    em_queue_t  m_queue;
	unsigned int m_tick_demultiplex;

public:
	pthread_mutex_t m_mutex;
    hash_map_t      *m_em_map;
    unsigned int m_timeout;
    fd_set  m_rset;
    
    int init(const char *data_model_path);
    int start();

    virtual bool    is_data_model_initialized() = 0;

    void push_to_queue(em_event_t *evt);
    em_event_t *pop_from_queue();

    int nodes_listen();
    int input_listen();
    void proto_process(unsigned char *data, unsigned int len, em_t *em = NULL);

    em_t *create_node(em_interface_t *ruid, em_freq_band_t band, dm_easy_mesh_t *dm, bool is_al_mac = false, em_profile_type_t profile = em_profile_type_3, em_service_type_t type = em_service_type_agent);
    void delete_node(em_interface_t* ruid);
    void delete_nodes();
    em_t *get_node_by_freq_band(em_freq_band_t *band);
    em_t *get_al_node();

    void nodes_listener();
    int reset_listeners();
    void handle_timeout();

    static void *mgr_nodes_listen(void *arg);
    static void *mgr_input_listen(void *arg);

    virtual em_t *find_em_for_msg_type(unsigned char *data, unsigned int len, em_t *al_em) = 0;
    virtual int data_model_init(const char *data_model_path) = 0;
    virtual int orch_init() = 0;
    virtual void input_listener() = 0;
	virtual void	start_complete() = 0;
    
    virtual void handle_event(em_event_t *evt) = 0;

    virtual void handle_5s_tick() = 0;
    virtual void handle_2s_tick() = 0;
    virtual void handle_1s_tick() = 0;
    virtual void handle_500ms_tick() = 0;

    virtual void io(void *data, bool input = true) = 0;
    virtual void update_network_topology() = 0;
    
    virtual dm_easy_mesh_t *get_data_model(const char *net_id, const unsigned char *al_mac = NULL) = 0;
    virtual dm_easy_mesh_t *create_data_model(const char *net_id, const unsigned char *al_mac, em_profile_type_t profile = em_profile_type_3) = 0;
    virtual void delete_data_model(const char *net_id, const unsigned char *al_mac) = 0;
    virtual void delete_all_data_models() = 0;
    virtual int update_tables(dm_easy_mesh_t *dm) = 0;
    virtual int load_net_ssid_table() = 0;
    virtual void debug_probe() = 0;

    virtual em_service_type_t get_service_type() = 0;

	bool io_process(em_event_t *evt);
	void io_process(em_bus_event_type_t type, char *data, unsigned int len, em_cmd_params_t *params = NULL);
	void io_process(em_bus_event_type_t type, unsigned char *data, unsigned int len, em_cmd_params_t *params = NULL);

    em_mgr_t();
    ~em_mgr_t();
};

#endif

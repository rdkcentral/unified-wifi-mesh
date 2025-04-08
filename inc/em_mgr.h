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
#include "ieee80211.h"

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

    /**
     * @brief Get the physical AL node.
     * In other words, the actual `em_t` node that is being used to perform EasyMesh operations.
     * 
     * @return Pointer to the physical AL node.
     */
    em_t *get_phy_al_node();

    void nodes_listener();
    int reset_listeners();
    void handle_timeout();

    static void *mgr_nodes_listen(void *arg);
    static void *mgr_input_listen(void *arg);

    /**
     * @brief Refresh the OneWifi subdoc with current information + provided data and send to OneWifi
     * 
     * @param log_name [in] The string to use when logging
     * @param type [in] The subdoc type
     * @return int 1 if successful, 0 if encode fails, -1 if send fails, -2 if unimplemented
     */
    virtual int refresh_onewifi_subdoc(const char *log_name, const webconfig_subdoc_type_t type) {
        printf("refresh_onewifi_subdoc not implemented\n");
        return -2;
    }

    /**
     * @brief Send an action frame. Optional to implement.
     * 
     * @param dest_mac The destination MAC address
     * @param action_frame The action frame to send
     * @param action_frame_len The length of the action frame
     * @param frequency The frequency to send the frame on (0 for current frequency)
     * @param wait_time_ms The time to dwell on the frequency before switching back to the original frequency (0 for no wait)
     * @return true if successful, false otherwise
     */
    virtual bool send_action_frame(uint8_t dest_mac[ETH_ALEN], uint8_t *action_frame, size_t action_frame_len, unsigned int frequency=0, unsigned int wait_time_ms=0) {
        printf("send_action_frame not implemented\n");
        return false;
    }

    /**
     * @brief Callback to determine if the mesh is capable of supporting additional onboarded APs.
     * 
     * Spec does not determine what the threshold for onboarding more APs is, so this is vendor/deployment specific.
     * 
     * @return true if the mesh can support an additional AP, otherwise false.
     */
    virtual bool can_onboard_additional_aps() {
        printf("%s not implemented\n", __func__);
        return true;
    }

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
    virtual dm_easy_mesh_t *create_data_model(const char *net_id, const em_interface_t *al_intf, em_profile_type_t profile = em_profile_type_3) = 0;
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
    virtual ~em_mgr_t();
};

#endif

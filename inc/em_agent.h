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

#ifndef EMAGNT_H
#define EMAGNT_H

#include "em.h"
#include "em_mgr.h"
#include "ieee80211.h"
#include "dm_easy_mesh_agent.h"
#include "em_crypto.h"
#include "em_orch_agent.h"
#include "em_simulator.h"
#include "bus.h"

#include <string>

class em_cmd_agent_t;
class AlServiceAccessPoint;

class em_agent_t : public em_mgr_t {

    em_orch_agent_t *m_orch;
    dm_easy_mesh_agent_t m_data_model;
    em_short_string_t   m_data_model_path;
    em_cmd_agent_t  *m_agent_cmd;
	em_simulator_t	m_simulator;

	void start_complete();
    void io_run(char *buff);
	void update_network_topology() { }

    void handle_5s_tick();
    void handle_2s_tick();
    void handle_1s_tick();
    void handle_500ms_tick();

    void handle_bus_event(em_bus_event_t *evt);
    void handle_action_frame(struct ieee80211_mgmt *frame);
    void handle_public_action_frame(struct ieee80211_mgmt *frame);
    void handle_vendor_public_action_frame(struct ieee80211_mgmt *frame);
    void handle_btm_request_action_frame(em_bus_event_t *evt);
    void handle_recv_wfa_action_frame(em_bus_event_t *evt);
    void handle_btm_response_action_frame(em_bus_event_t *evt);
    void handle_channel_scan_result(em_bus_event_t *evt);
    void handle_channel_scan_params(em_bus_event_t *evt);
    void handle_set_policy(em_bus_event_t *evt);
    void handle_beacon_report(em_bus_event_t *evt);
    void handle_recv_gas_frame(em_bus_event_t *evt);

public:

    bus_handle_t m_bus_hdl;
    bool do_start_dpp_onboarding = false;
    bool do_regen_dpp_uri = false;

    void input_listener();

    /**
     * @brief Refresh the OneWifi subdoc with current information + provided data and send to OneWifi
     * 
     * @param log_name [in] The string to use when logging
     * @param type [in] The subdoc type
     * @return int 1 if successful, 0 if encode fails, -1 if send fails, -2 if unimplemented
     */
    int refresh_onewifi_subdoc(const char *log_name, const webconfig_subdoc_type_t type) override;

    /**
     * @brief Send an action frame
     * 
     * @param dest_mac The destination MAC address
     * @param action_frame The action frame to send
     * @param action_frame_len The length of the action frame
     * @param frequency The frequency to send the frame on (0 for current frequency)
     * @param wait_time_ms The time to dwell on the frequency before switching back to the original frequency (0 for no wait)
     * @return true if successful, false otherwise
     */
    bool send_action_frame(uint8_t dest_mac[ETH_ALEN], uint8_t *action_frame, size_t action_frame_len, unsigned int frequency=0, unsigned int wait_time_ms=0) override;

    /**
     * @brief Callback to determine if the mesh is capable of supporting additional onboarded APs.
     * 
     * Spec does not determine what the threshold for onboarding more APs is, so this is vendor/deployment specific.
     * 
     * @return true if the mesh can support an additional AP, otherwise false.
     */
    bool can_onboard_additional_aps();

    /**
     * @brief Try to create a default EasymeshCfg.json file if one does not exist.
     * 
     * A default EasymeshCfg.json file only contains the `AL_MAC_ADDR` and `Colocated_mode` fields.
     * 
     * @param interface The interface to use for filling the `AL_MAC_ADDR` field
     * @return true if successful or if the file already exists, false otherwise
     */
    bool try_create_default_em_cfg(std::string interface);

    bool try_start_dpp_onboarding();

    int data_model_init(const char *data_model_path);
    bool is_data_model_initialized() { return true; }

    int orch_init();

    void handle_timeout();
    void handle_event(em_event_t *evt);
    void handle_frame_event(em_frame_event_t *evt);

    void handle_dev_init(em_bus_event_t *evt);  
    void handle_radio_config(em_bus_event_t *evt);  
    void handle_vap_config(em_bus_event_t *evt);    
    void handle_sta_list(em_bus_event_t *evt);
    void handle_ap_cap_query(em_bus_event_t *evt);
    void handle_autoconfig_renew(em_bus_event_t *evt);
    void handle_client_cap_query(em_bus_event_t *evt);
    void handle_onewifi_private_subdoc(em_bus_event_t *evt);
	void handle_onewifi_private_cb(em_bus_event_t *evt);
	void handle_onewifi_radio_cb(em_bus_event_t *evt);
    void handle_m2ctrl_configuration(em_bus_event_t *evt);
    void handle_channel_pref_query(em_bus_event_t *evt);
    void handle_channel_sel_req(em_bus_event_t *evt);
    void handle_sta_link_metrics(em_bus_event_t *evt);
    void handle_steer_sta(em_bus_event_t *evt);

    em_cmd_t& get_command(char *in);
    
    dm_easy_mesh_t *get_data_model(const char *net_id, const unsigned char *al_mac = NULL) { return &m_data_model; }
    dm_easy_mesh_t *create_data_model(const char *net_id, const em_interface_t *al_intf, em_profile_type_t profile = em_profile_type_3) { return &m_data_model; }
    void delete_data_model(const char *net_id, const unsigned char *al_mac) { }
    void delete_all_data_models() { }
    int update_tables(dm_easy_mesh_t *dm) { return 0; }
    int load_net_ssid_table() { return 0; }
    void debug_probe() { }

    em_service_type_t get_service_type() { return em_service_type_agent; }
    em_t *find_em_for_msg_type(unsigned char *data, unsigned int len, em_t *al_em);

    static void sta_cb(char *event_name, raw_data_t *data, void *userData);
    static void onewifi_cb(char *event_name, raw_data_t *data, void *userData);
    static int assoc_stats_cb(char *event_name, raw_data_t *data, void *userData);
    static int mgmt_action_frame_cb(char *event_name, raw_data_t *data, void *userData);
    static int channel_scan_cb(char *event_name, raw_data_t *data, void *userData);
    static int beacon_report_cb(char *event_name, raw_data_t *data, void *userData);
    void *get_assoc(void*);
    void io(void *data, bool input = true);
    bool agent_output(void *data);

#ifdef AL_SAP
    AlServiceAccessPoint* al_sap_register();
#endif

    em_agent_t();
    ~em_agent_t();

};

#endif

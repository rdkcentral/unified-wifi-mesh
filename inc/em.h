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

#ifndef EM_H
#define EM_H

#include "collection.h"
#include "em_base.h"
#include "em_crypto.h"
#include "em_configuration.h"
#include "em_discovery.h"
#include "em_provisioning.h"
#include "em_channel.h"
#include "em_capability.h"
#include "em_metrics.h"
#include "em_steering.h"
#include "em_policy_cfg.h"
#include "dm_easy_mesh.h"
#include "em_sm.h"

class em_t : 
    public em_configuration_t, public em_discovery_t, 
    public em_provisioning_t, public em_channel_t,
    public em_capability_t, public em_metrics_t,
    public em_steering_t, public em_policy_cfg_t  {
    
    dm_easy_mesh_t*  m_data_model;

    em_orch_state_t m_orch_state;
    em_cmd_t *m_cmd;
    em_sm_t  m_sm;
	em_service_type_t   m_service_type;
    int m_fd;
    em_interface_t  m_ruid;
    em_freq_band_t  m_band;
    em_profile_type_t   m_profile_type;
    em_queue_t  m_iq;
    pthread_t   m_tid;
    bool    m_exit;
    bool m_is_al_em;

    void proto_run();
    void proto_exit();
    void proto_process(unsigned char *data, unsigned int len);
    void proto_timeout();

    // em socket read and write
    void    create_raw_header(unsigned char *buff, unsigned int len);
    int set_bp_filter();
    int start_al_interface();
    int send_frame(unsigned char *buff, unsigned int len, bool multicast = false);
    int send_cmd(em_cmd_type_t type, em_service_type_t svc, unsigned char *buff, unsigned int len);



public:
    int init();
    void deinit();
    void stop() { proto_exit(); }
    void handle_timeout();
    void handle_agent_state();
    void handle_ctrl_state();

    bool is_al_interface_em() { return m_is_al_em; }
    bool is_set_ssid_candidate(dm_network_ssid_t *net_ssid) { return (is_al_interface_em() == true) ? false:true; }
    bool is_dev_test_candidate() { return is_al_interface_em(); }
    bool is_start_dpp_candidate(dm_dpp_t *dpp) { return (is_al_interface_em() == true) ? false:true; }
    bool is_start_dev_init(dm_radio_t *radio) { return (is_al_interface_em() == true) ? false:true; }
    bool is_tx_cfg_renew_candidate() { return is_al_interface_em(); }
    bool is_cfg_renew_candidate() { return (m_sm.get_state() == em_state_ctrl_misconfigured) ? true:false;; }
	bool is_dev_init_candidate(unsigned char *mac) { return (memcmp(mac, get_radio_interface_mac(), sizeof(mac_address_t)) == 0); }
    bool is_autoconfig_renew_candidate(em_freq_band_t radio_freq_band , em_freq_band_t em_freq_band) { return (radio_freq_band == em_freq_band) ? true:false;}
    bool is_matching_freq_band(em_freq_band_t *band);
    void set_al_type(bool is_al_mac) {m_is_al_em = is_al_mac;}

    void orch_execute(em_cmd_t *pcmd);
    em_orch_state_t get_orch_state() { return m_orch_state; }
    void set_orch_state(em_orch_state_t state);

    em_state_t get_state() { return m_sm.get_state(); }
    void set_state(em_state_t state) {  m_sm.set_state(state); }
	em_service_type_t   get_service_type() { return m_service_type; }
    em_profile_type_t   get_profile_type() { return m_profile_type; }
    void    set_profile_type(em_profile_type_t profile) { m_profile_type = profile; }


    dm_easy_mesh_t *get_data_model() { return m_data_model; }  
    void copy_data_model(dm_easy_mesh_t& dm) { *m_data_model = dm; }

    rdk_wifi_radio_t    *get_radio_data(em_interface_t *radio) { return m_data_model->get_radio_data(radio); };
    em_interface_t  *get_radio_interface() { return &m_ruid; }
    unsigned char   *get_radio_interface_mac() { return m_ruid.mac; }
    char *get_radio_interface_name() { return m_ruid.name; }

    unsigned char *get_al_interface_mac() { return (m_service_type == em_service_type_agent) ? 
            m_data_model->get_agent_al_interface_mac():m_data_model->get_ctrl_al_interface_mac(); }
    char *get_al_interface_name() { return m_data_model->get_agent_al_interface_name(); }
    em_cmd_t *get_current_cmd()  { return m_cmd; }    

    em_crypto_t *get_crypto() { return &m_crypto; }
    em_crypto_info_t    *get_crypto_info() { return m_crypto.get_crypto_info(); }
    em_ieee_1905_security_info_t *get_ieee_1905_security_info() { return m_data_model->get_ieee_1905_security_info(); }
    em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() { return m_data_model->get_ieee_1905_security_cap(); }
    em_device_info_t    *get_device_info() { return m_data_model->get_device_info(); }

    unsigned char *get_peer_mac() { return (m_service_type == em_service_type_ctrl) ? m_data_model->get_agent_al_interface_mac():m_data_model->get_ctrl_al_interface_mac(); }

    bool has_at_least_one_associated_sta() { return get_data_model()->has_at_least_one_associated_sta(); }
    dm_sta_t *find_sta(mac_address_t sta_mac, bssid_t bssid);

    void push_to_queue(em_event_t *evt);
    em_event_t *pop_from_queue();

    int get_fd() { return m_fd; }

    //Msg Construction supporting API
    short create_ap_cap_tlv(unsigned char *buff);
    short create_ht_tlv(unsigned char *buff);
    short create_vht_tlv(unsigned char *buff);
    short create_he_tlv(unsigned char *buff);
    short create_wifi6_tlv(unsigned char *buff);
    short create_wifi7_tlv(unsigned char *buff);
    short create_eht_operations_tlv(unsigned char *buff);
    short create_channelscan_tlv(unsigned char *buff);
    short create_prof_2_tlv(unsigned char *buff);
    short create_device_inventory_tlv(unsigned char *buff);
    short create_radioad_tlv(unsigned char *buff);
    short create_metric_col_int_tlv(unsigned char *buff);
    short create_cac_cap_tlv(unsigned char *buff);
    short create_ap_radio_basic_cap(unsigned char *buff);   
    //Msg-End

    char *get_manufacturer() { return m_data_model->get_manufacturer(); }
    char *get_manufacturer_model() { return m_data_model->get_manufacturer_model(); }
    char *get_software_version() { return m_data_model->get_software_version(); }
    char *get_serial_number() { return m_data_model->get_serial_number(); }
    char *get_primary_device_type() { return m_data_model->get_primary_device_type(); }
    em_network_ssid_info_t *get_network_ssid_info_by_haul_type(em_haul_type_t haul_type) { return m_data_model->get_network_ssid_info_by_haul_type(haul_type); }

    void set_manufacturer(char *manufacturer) { m_data_model->set_manufacturer(manufacturer); }
    void set_manufacturer_model(char *model) { m_data_model->set_manufacturer_model(model); }
    void set_software_version(char *version) { m_data_model->set_software_version(version); }
    void set_serial_number(char *serial) { m_data_model->set_serial_number(serial); }
    void set_primary_device_type(char *type) { m_data_model->set_primary_device_type(type); }
    em_freq_band_t get_band() { return m_band; }
    void set_band(em_freq_band_t band) { m_band = band; }
    em_rd_freq_band_t map_freq_band_to_rf_band(em_freq_band_t band);
    static em_freq_band_t convert_freq_band(em_freq_band_t band);
    
    static void *em_func(void *);
    static const char *get_band_type_str(em_freq_band_t band);
    static const char *state_2_str(em_state_t state);

    em_t(em_interface_t *ruid, em_freq_band_t band, dm_easy_mesh_t *dm, em_profile_type_t profile, em_service_type_t type);
    ~em_t();

};

#endif

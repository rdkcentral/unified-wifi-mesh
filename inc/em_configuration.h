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

#ifndef EM_CONFIGURATION_H
#define EM_CONFIGURATION_H

#include "em_base.h"
#include "em_crypto.h"
#include "dm_easy_mesh.h"

class em_cmd_t;
class em_configuration_t {

    int create_autoconfig_resp_msg(unsigned char *buff, em_freq_band_t band, unsigned char *dst);
    int create_autoconfig_search_msg(unsigned char *buff);
    int create_autoconfig_wsc_m1_msg(unsigned char *buff, unsigned char *dst);
    int create_autoconfig_wsc_m2_msg(unsigned char *buff, em_haul_type_t haul_type[], unsigned int num_hauls);
    int	create_operational_bss_tlv(unsigned char *buff);
    int	create_bss_config_rprt_tlv(unsigned char *buff);
    int create_device_info_type_tlv(unsigned char *buff);
    short create_client_assoc_event_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid, bool assoc);
    int create_ap_mld_config_tlv(unsigned char *buff);
    int create_bsta_mld_config_tlv(unsigned char *buff);
    int create_tid_to_link_map_policy_tlv(unsigned char *buff);

    int send_topology_response_msg(unsigned char *dst);
    int send_topology_notification_by_client(mac_address_t sta, bssid_t bssid, bool assoc);
    
    int handle_autoconfig_resp(unsigned char *buff, unsigned int len);
    int handle_autoconfig_search(unsigned char *buff, unsigned int len);
    int handle_autoconfig_wsc_m1(unsigned char *buff, unsigned int len);
    int handle_autoconfig_wsc_m2(unsigned char *buff, unsigned int len);
    int handle_wsc_m1(unsigned char *buff, unsigned int len);
    int handle_wsc_m2(unsigned char *buff, unsigned int len);
    int handle_autoconfig_renew(unsigned char *buff, unsigned int len);
    int handle_ap_radio_basic_cap(unsigned char *buff, unsigned int len);
    int handle_ap_radio_advanced_cap(unsigned char *buff, unsigned int len);
    int handle_topology_response(unsigned char *buff, unsigned int len);
    int handle_topology_notification(unsigned char *buff, unsigned int len);
	int handle_ap_operational_bss(unsigned char *buff, unsigned int len);
    int handle_bss_configuration_report(unsigned char *buff, unsigned int len);

    short create_m1_msg(unsigned char *buff);
    short create_m2_msg(unsigned char *buff, em_haul_type_t haul_type);
    short create_traffic_separation_policy(unsigned char *buff);
   
    // state handlers 
    void handle_state_config_none();
    void handle_state_autoconfig_rsp_pending();
    void handle_state_wsc_m1_pending();
    void handle_state_wsc_m2_pending();
    void handle_state_topology_notify();
    void handle_state_autoconfig_renew();

    // helpers
    void fill_media_data(em_media_spec_data_t *spec);

    virtual dm_easy_mesh_t *get_data_model() = 0;
    virtual em_state_t get_state() = 0;
    virtual void set_state(em_state_t state) = 0;
    virtual em_service_type_t get_service_type() = 0;
    virtual em_profile_type_t get_profile_type() = 0;
    virtual void set_profile_type(em_profile_type_t profile) = 0;
    virtual unsigned char *get_radio_interface_mac() = 0;
    virtual em_interface_t *get_radio_interface() = 0;
    virtual unsigned char *get_al_interface_mac() = 0;
    virtual rdk_wifi_radio_t *get_radio_data(em_interface_t *radio) = 0;
    virtual em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() = 0;
    virtual em_device_info_t *get_device_info() = 0;
    virtual unsigned char *get_peer_mac() = 0;
    virtual em_crypto_info_t *get_crypto_info() = 0;
    virtual em_crypto_t *get_crypto() = 0;
    virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
	virtual int push_event(em_event_t *evt) = 0;
    virtual em_cmd_t *get_current_cmd() = 0;
    virtual short create_ap_radio_basic_cap(unsigned char *buff) = 0;
    virtual bool is_al_interface_em() = 0;
	virtual dm_radio_t *get_radio_from_dm(bool command_dm = false) = 0;

    virtual char *get_manufacturer() = 0;
    virtual char *get_manufacturer_model() = 0;
    virtual char *get_software_version() = 0;
    virtual char *get_serial_number() = 0;
    virtual char *get_primary_device_type() = 0;

    virtual void set_manufacturer(char *) = 0;
    virtual void set_manufacturer_model(char *) = 0;
    virtual void set_software_version(char *) = 0;
    virtual void set_serial_number(char *) = 0;
    virtual void set_primary_device_type(char *) = 0;
    virtual em_freq_band_t get_band() = 0;
    virtual void set_band(em_freq_band_t band) = 0;
    virtual em_network_ssid_info_t *get_network_ssid_info_by_haul_type(em_haul_type_t haul_type) = 0;
    virtual em_rd_freq_band_t map_freq_band_to_rf_band(em_freq_band_t band) = 0;
    em_freq_band_t convert_freq_band(em_freq_band_t band);

private:
    em_profile_type_t   m_peer_profile;
    unsigned char m_m1_msg[MAX_EM_BUFF_SZ];
    unsigned char m_m2_msg[MAX_EM_BUFF_SZ];
    size_t m_m1_length;
    size_t m_m2_length;

    unsigned char m_m2_authenticator[SHA256_MAC_LEN];
    unsigned int m_m2_authenticator_len;
    unsigned char m_m2_encrypted_settings[MAX_EM_BUFF_SZ];
    unsigned int m_m2_encrypted_settings_len;

public:
    void process_msg(unsigned char *data, unsigned int len);	
    void process_agent_state();
    void process_ctrl_state();
    static em_wsc_msg_type_t get_wsc_msg_type(unsigned char *buff, unsigned int len);

    int send_topology_query_msg();
    int send_autoconfig_renew_msg();
    int handle_encrypted_settings();
    unsigned int create_encrypted_settings(unsigned char *buff, em_haul_type_t haul_type);
    unsigned int create_authenticator(unsigned char *buff);

    unsigned int get_e_uuid(unsigned char *uuid) { return m_crypto.get_e_uuid(uuid); }
    unsigned int get_r_uuid(unsigned char *uuid) { return m_crypto.get_r_uuid(uuid); }
    unsigned int get_e_nonce(unsigned char *nonce) { return m_crypto.get_e_nonce(nonce); }
    unsigned int get_r_nonce(unsigned char *nonce) { return m_crypto.get_r_nonce(nonce); }

    unsigned char *get_e_nonce() { return m_crypto.get_e_nonce(); }
    unsigned char *get_r_nonce() { return m_crypto.get_r_nonce(); }
    
    void set_e_uuid(unsigned char *uuid, unsigned int len) { m_crypto.set_e_uuid(uuid, len); }
    void set_r_uuid(unsigned char *uuid, unsigned int len) { m_crypto.set_r_uuid(uuid, len); }
    void set_e_nonce(unsigned char *nonce, unsigned int len) { m_crypto.set_e_nonce(nonce, len); }
    void set_r_nonce(unsigned char *nonce, unsigned int len) { m_crypto.set_r_nonce(nonce, len); }	

    unsigned char *get_e_public() { return m_crypto.get_e_public(); }
    unsigned int get_e_public_len() { return m_crypto.get_e_public_len(); }
    unsigned char *get_e_private() { return m_crypto.get_e_private(); }
    unsigned int get_e_private_len() { return m_crypto.get_e_private_len(); }
    unsigned char *get_r_public() { return m_crypto.get_r_public(); }
    unsigned int get_r_public_len() { return m_crypto.get_r_public_len(); }
    unsigned char *get_r_private() { return m_crypto.get_r_private(); }
    unsigned int get_r_private_len() { return m_crypto.get_r_private_len(); }

    void set_e_public(unsigned char *pub, unsigned int len) { m_crypto.set_e_public(pub, len); }
    void set_r_public(unsigned char *pub, unsigned int len) { m_crypto.set_r_public(pub, len); }

    unsigned char *get_e_mac() { return m_crypto.get_e_mac(); }
    unsigned char *get_r_mac() { return m_crypto.get_r_mac(); }

    void set_e_mac(unsigned char *mac) { m_crypto.set_e_mac(mac); }
    void set_r_mac(unsigned char *mac) { m_crypto.set_r_mac(mac); }

    int compute_secret(unsigned char **secret, unsigned short *secret_len, 
        unsigned char *remote_pub, unsigned short pub_len, 
        unsigned char *local_priv, unsigned short priv_len) { 
            return m_crypto.platform_compute_shared_secret(secret, secret_len, remote_pub, pub_len, local_priv, priv_len); 
    }

    int compute_digest(unsigned char num, unsigned char **addr, unsigned int *len, unsigned char *digest) {
        return m_crypto.platform_SHA256(num, addr, len, digest); 
    }

    int compute_kdk(unsigned char *key, unsigned short keylen, 
        unsigned char num_elem, unsigned char **addr, 
        unsigned int *len, unsigned char *hmac) {
            return m_crypto.platform_hmac_SHA256(key, keylen, num_elem, addr, len, hmac);
    }

    int derive_key(unsigned char *key, unsigned char *label_prefix, unsigned int label_prefix_len, 
        char *label, unsigned char *res, unsigned int res_len) {
            return m_crypto.wps_key_derivation_function(key, label_prefix, label_prefix_len, label, res, res_len);
    }

    int compute_keys(unsigned char *remote_pub, unsigned short pub_len, unsigned char *local_priv, unsigned short priv_len);

    //void test_topology_response_msg() { send_topology_response_msg(); }
    void print_ap_operational_bss_tlv(unsigned char *value, unsigned int len);
	void print_bss_configuration_report_tlv(unsigned char *value, unsigned int len);
    int get_renew_tx_count() { return m_renew_tx_cnt; }
    void set_renew_tx_count(unsigned int cnt) { m_renew_tx_cnt = cnt; }
    int get_topo_query_tx_count() { return m_topo_query_tx_cnt; }
    void set_topo_query_tx_count(unsigned int cnt) { m_topo_query_tx_cnt = cnt; }
    static unsigned short msg_id;

    em_crypto_t m_crypto;
    unsigned char m_auth_key[WPS_AUTHKEY_LEN];
    unsigned char m_key_wrap_key[WPS_KEYWRAPKEY_LEN];
    unsigned char m_emsk[WPS_EMSK_LEN];
    unsigned int m_renew_tx_cnt;
    unsigned int m_topo_query_tx_cnt;

    em_configuration_t();
    ~em_configuration_t();

};

#endif

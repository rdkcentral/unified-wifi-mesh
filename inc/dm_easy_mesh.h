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

#ifndef DM_EM_H
#define DM_EM_H

#include "em_base.h"
#include "wifi_webconfig.h"
#include "dm_device.h"
#include "dm_network.h"
#include "dm_ieee_1905_security.h"
#include "dm_network_ssid.h"
#include "dm_radio.h"
#include "dm_bss.h"
#include "dm_dpp.h"
#include "dm_op_class.h"
#include "dm_radio_cap.h"

class dm_easy_mesh_t {

    webconfig_subdoc_data_t m_wifi_data;
    dm_network_t    m_network;
    dm_device_t     m_device;
    dm_ieee_1905_security_t m_ieee_1905_security;
    dm_network_ssid_t   m_network_ssid;
    unsigned int    m_num_radios;
    unsigned int    m_num_opclass;
    dm_radio_t  m_radio[EM_MAX_BANDS];
    dm_radio_cap_t     m_radio_cap[EM_MAX_BANDS];
    dm_bss_t    m_bss[EM_MAX_BSSS];
    dm_dpp_t        m_dpp;
    hash_map_t  *m_sta_map = NULL;
    em_cmd_ctx_t    m_cmd_ctx;
    dm_op_class_t m_op_class[EM_MAX_OPCLASS];
    hash_map_t      *m_sta_assoc_map = NULL;
    hash_map_t      *m_sta_dassoc_map = NULL;
    unsigned int    m_num_bss;
    short           msg_id;
public:
    int init();
    void deinit();

    int analyze_dev_init(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_radio_config(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_vap_config(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_sta_list(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_ap_cap_query(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_autoconfig_renew(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_client_cap_query(em_bus_event_t *evt, em_cmd_t *pcmd[]);

    int decode_config(em_subdoc_info_t *subdoc, const char *key, unsigned int dev_index);
    int encode_config(em_subdoc_info_t *subdoc);
    int decode_sta_config(em_subdoc_info_t *subdoc, unsigned int dev_index);
    unsigned int decode_num_devices(em_subdoc_info_t *subdoc);
    int decode_client_cap_config(em_subdoc_info_t *subdoc, const char *key, char *clientmac, char *radio_mac);
    int decode_ap_cap_config(em_subdoc_info_t *subdoc, const char *key);

    int commit_config(dm_easy_mesh_t& dm, em_commit_target_t target);
    int commit_config(em_tlv_type_t tlv, unsigned char *data, unsigned int len, bssid_t id, em_commit_target_t target);
    int commit_config(em_attrib_id_t attrib, unsigned char *data, unsigned int len, bssid_t id, em_commit_target_t target);
    int commit_config(em_cmd_t  *cmd);

    void set_network(dm_network_t &network) { m_network = network; }

    em_interface_t *get_ctrl_al_interface() { return m_network.get_colocated_agent_interface(); }
    unsigned char *get_ctrl_al_interface_mac() { return m_network.get_colocated_agent_interface_mac(); }
    char *get_ctrl_al_interface_name() { return m_network.get_colocated_agent_interface_name(); }
    void set_ctrl_al_interface_mac(unsigned char *mac) { m_network.set_colocated_agent_interface_mac(mac); }
    void set_ctrl_al_interface_name(char *name) { return m_network.set_colocated_agent_interface_name(name); }

    em_interface_t *get_agent_al_interface() { return m_device.get_dev_interface(); }
    unsigned char *get_agent_al_interface_mac() { return m_device.get_dev_interface_mac(); }
    char *get_agent_al_interface_name() { return m_device.get_dev_interface_name(); }
    void set_agent_al_interface_mac(unsigned char *mac) { m_device.set_dev_interface_mac(mac); }
    void set_agent_al_interface_name(char *name) { return m_device.set_dev_interface_name(name); }

    em_interface_t *get_controller_interface() { return m_network.get_controller_interface(); }
    unsigned char *get_controller_interface_mac() { return m_network.get_controller_interface_mac(); }

    em_ieee_1905_security_info_t *get_ieee_1905_security_info() { return m_ieee_1905_security.get_ieee_1905_security_info(); }
    em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() { return m_ieee_1905_security.get_ieee_1905_security_cap(); }
    em_device_info_t *get_device_info() { return m_device.get_device_info(); }

    dm_network_t *get_network() { return &m_network; }
    dm_network_t& get_network_by_reference() { return m_network; }

    dm_device_t *get_device() { return &m_device; }
    dm_device_t& get_device_by_reference() { return m_device; }
    dm_device_t *find_matching_device(dm_device_t *dev);
    dm_op_class_t *get_curr_op_class(unsigned int index);

    dm_network_ssid_t *get_network_ssid() { return &m_network_ssid; }
    dm_dpp_t *get_dpp() { return &m_dpp; }

    dm_radio_t *get_radio(unsigned int index);
    dm_radio_t *get_radio(mac_address_t mac);
    em_interface_t *get_radio_interface(unsigned int index) { return m_radio[index].get_radio_interface(); }
    rdk_wifi_radio_t    *get_radio_data(em_interface_t *radio);
    unsigned int get_num_radios() { return m_num_radios; }
    unsigned int get_num_opclass() { return m_num_opclass; }
    dm_radio_t *find_matching_radio(dm_radio_t *radio);

    dm_radio_cap_t *get_radio_cap(mac_address_t mac);

    char *get_manufacturer() { return m_device.get_manufacturer(); }
    char *get_manufacturer_model() { return m_device.get_manufacturer_model(); }
    char *get_software_version() { return m_device.get_software_version(); }
    char *get_serial_number() { return m_device.get_serial_number(); }
    char *get_primary_device_type() { return m_device.get_primary_device_type(); }

    short   get_msg_id() { return msg_id;}

    void set_manufacturer(char *manufacturer) { m_device.set_manufacturer(manufacturer); }
    void set_manufacturer_model(char *model) { m_device.set_manufacturer_model(model); }
    void set_software_version(char *version) { m_device.set_software_version(version); }
    void set_serial_number(char *serial) { m_device.set_serial_number(serial); }
    void set_primary_device_type(char *type) { m_device.set_primary_device_type(type); }
    //void operator =(dm_easy_mesh_t const& obj);
    dm_easy_mesh_t operator =(dm_easy_mesh_t const& obj);
    bool operator ==(dm_easy_mesh_t const& obj);
    em_cmd_ctx_t *get_cmd_ctx() { return &m_cmd_ctx; }
    void    set_cmd_ctx(em_cmd_ctx_t *ctx) { memcpy(&m_cmd_ctx, ctx, sizeof(em_cmd_ctx_t)); }
    void    reset_cmd_ctx() { memset(&m_cmd_ctx, 0, sizeof(em_cmd_ctx_t)); }

    hash_map_t **get_assoc_sta_map() {return &m_sta_assoc_map;}
    hash_map_t **get_dassoc_sta_map() {return &m_sta_dassoc_map;}
    hash_map_t **get_sta_map() {return &m_sta_map;}
    
    static void print_hex_dump(unsigned int length, unsigned char *buffer);
    static char *macbytes_to_string(mac_address_t mac, char* string);
    static void string_to_macbytes (char *key, mac_address_t bmac);
    static int mac_address_from_name(const char *ifname, mac_address_t mac);
    static int name_from_mac_address(const mac_address_t *mac, char *ifname);

    static void create_autoconfig_renew_json_cmd(char* src_mac_addr, char* agent_al_mac, em_freq_band_t freq_band, char* autoconfig_renew_json);
    static void create_client_cap_query_json_cmd(char* src_mac_addr, char* agent_al_mac, char* ap_query_json, short msg_id, char *mac);
    static void create_ap_cap_query_json_cmd(char* src_mac_addr, char* agent_al_mac, char* ap_query_json, short msg_id);
    void print_config();

    dm_easy_mesh_t();
    dm_easy_mesh_t(const dm_network_t& net);
    ~dm_easy_mesh_t();  
};

#endif

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
#include "dm_sta.h"
#include "dm_dpp.h"
#include "dm_op_class.h"
#include "dm_radio_cap.h"
#include "dm_cac_comp.h"
#include "dm_ap_mld.h"
#include "webconfig_external_proto.h"

class em_t;

class dm_easy_mesh_t {
public:
    webconfig_subdoc_data_t m_wifi_data;
    dm_network_t    m_network;
    dm_device_t     m_device;
    dm_ieee_1905_security_t m_ieee_1905_security;
    unsigned int	m_num_net_ssids;
    dm_network_ssid_t   m_network_ssid[EM_MAX_NET_SSIDS];
    unsigned int    m_num_radios;
    dm_radio_t  m_radio[EM_MAX_BANDS];
    dm_radio_cap_t     m_radio_cap[EM_MAX_BANDS];
    unsigned int    m_num_bss;    
    dm_bss_t    m_bss[EM_MAX_BSSS];
    dm_dpp_t        m_dpp;
    em_cmd_ctx_t    m_cmd_ctx;
    unsigned int 	m_num_opclass;    
    dm_op_class_t m_op_class[EM_MAX_OPCLASS];
    hash_map_t  	*m_sta_map = NULL;
    hash_map_t      *m_sta_assoc_map = NULL;
    hash_map_t      *m_sta_dassoc_map = NULL;
    dm_cac_comp_t	m_cac_comp;
    unsigned short           msg_id;
    unsigned int	m_db_cfg_type;
    em_t *m_em;
    bool    m_colocated;
    unsigned int    m_num_ap_mld;
    dm_ap_mld_t     m_ap_mld[EM_MAX_AP_MLD];

public:
    int init();
    void deinit();

    virtual int analyze_dev_init(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_radio_config(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_vap_config(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_sta_list(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_ap_cap_query(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_client_cap_query(em_bus_event_t *evt, em_cmd_t *pcmd[]);

    int decode_config(em_subdoc_info_t *subdoc, const char *key, unsigned int index = 0, unsigned int *num = NULL);
    int decode_config_reset(em_subdoc_info_t *subdoc, const char *key);
    int decode_config_test(em_subdoc_info_t *subdoc, const char *key);
    int decode_config_set_ssid(em_subdoc_info_t *subdoc, const char *key);
    int decode_config_set_channel(em_subdoc_info_t *subdoc, const char *key, unsigned int index, unsigned int *num);
    int decode_config_op_class_array(cJSON *arr_obj, em_op_class_type_t type, unsigned char *mac);
    
    int encode_config(em_subdoc_info_t *subdoc, const char *key);
    int encode_config_reset(em_subdoc_info_t *subdoc, const char *key);
    int encode_config_test(em_subdoc_info_t *subdoc, const char *key);
    int encode_config_op_class_array(cJSON *arr_obj, em_op_class_type_t type, unsigned char *mac);

    int decode_sta_config(em_subdoc_info_t *subdoc, unsigned int dev_index);
    unsigned int decode_num_devices(em_subdoc_info_t *subdoc);
    int decode_client_cap_config(em_subdoc_info_t *subdoc, const char *key, char *clientmac, char *radio_mac);
    int decode_ap_cap_config(em_subdoc_info_t *subdoc, const char *key);

    int commit_config(dm_easy_mesh_t& dm, em_commit_target_t target);
    int commit_config(em_tlv_type_t tlv, unsigned char *data, unsigned int len, bssid_t id, em_commit_target_t target);
    int commit_config(em_attrib_id_t attrib, unsigned char *data, unsigned int len, bssid_t id, em_commit_target_t target);
    int commit_config(dm_easy_mesh_t& dm, unsigned int radio_index, unsigned int vap_index, unsigned int num_radios, unsigned int num_bss);
    int commit_config(em_cmd_t  *cmd);
    int commit_bss_config(dm_easy_mesh_t& dm, unsigned int vap_index);

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

    void update_cac_status_id(mac_address_t al_mac);

    em_interface_t *get_controller_interface() { return m_network.get_controller_interface(); }
    unsigned char *get_controller_interface_mac() { return m_network.get_controller_interface_mac(); }
    static em_ieee_1905_security_info_t *get_ieee_1905_security_info(void *dm) { return ((dm_easy_mesh_t *)dm)->get_ieee_1905_security_info(); }
    em_ieee_1905_security_info_t *get_ieee_1905_security_info() { return m_ieee_1905_security.get_ieee_1905_security_info(); }
    em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() { return m_ieee_1905_security.get_ieee_1905_security_cap(); }
    em_device_info_t *get_device_info() { return m_device.get_device_info(); }
    static em_device_info_t *get_device_info(void *dm) { return ((dm_easy_mesh_t *)dm)->get_device_info(); }
    
    dm_network_t *get_network() { return &m_network; }
    dm_network_t& get_network_by_ref() { return m_network; }
    em_network_info_t *get_network_info() { return m_network.get_network_info(); }
    static em_network_info_t *get_network_info(void *dm) { return ((dm_easy_mesh_t *)dm)->get_network_info(); }
    unsigned char *get_ctl_mac() { return m_network.get_controller_interface_mac();}

    dm_device_t *get_device() { return &m_device; }
    dm_device_t& get_device_by_ref() { return m_device; }
    dm_device_t *find_matching_device(dm_device_t *dev);
    dm_op_class_t *get_curr_op_class(unsigned int index);

    unsigned int get_num_network_ssid() { return m_num_net_ssids; }
    void set_num_network_ssid(unsigned int num) { m_num_net_ssids = num; }
    dm_network_ssid_t *get_network_ssid(unsigned int index) { return &m_network_ssid[index]; }
    dm_network_ssid_t& get_network_ssid_by_ref(unsigned int index) { return m_network_ssid[index]; }
    em_network_ssid_info_t *get_network_ssid_info_by_haul_type(em_haul_type_t haul_type);

    em_bss_info_t *get_bss_info(unsigned int index) { return m_bss[index].get_bss_info(); }
    static em_bss_info_t *get_bss_info(void *dm, unsigned int index) { return ((dm_easy_mesh_t *)dm)->get_bss_info(index); }
    em_op_class_info_t *get_op_class_info(unsigned int index) { return m_op_class[index].get_op_class_info(); }
    static em_op_class_info_t *get_op_class_info(void *dm, unsigned int index) { return ((dm_easy_mesh_t *)dm)->get_op_class_info(index); }

    unsigned int get_num_op_class() { return m_num_opclass; }
    static unsigned int get_num_op_class(void *dm) { return ((dm_easy_mesh_t *)dm)->get_num_op_class(); }
    void set_num_op_class(unsigned int num) { m_num_opclass = num; }
    static void set_num_op_class(void *dm, unsigned int num) { ((dm_easy_mesh_t *)dm)->set_num_op_class(num); }
    dm_op_class_t *get_op_class(unsigned int index) { return &m_op_class[index]; }
    dm_op_class_t& get_op_class_by_ref(unsigned int index) { return m_op_class[index]; }
	static void print_op_class_list(dm_easy_mesh_t *dm);

    unsigned int get_num_bss() { return m_num_bss; }
    static unsigned int get_num_bss(void *dm) { return ((dm_easy_mesh_t *)dm)->get_num_bss(); }
    void set_num_bss(unsigned int num) { m_num_bss = num; }
    static void set_num_bss(void *dm, unsigned int num) { ((dm_easy_mesh_t *)dm)->set_num_bss(num); }
    dm_bss_t *get_bss(unsigned int index) { return &m_bss[index]; }
    dm_bss_t *get_bss_index(mac_address_t radio, mac_address_t bss, bool *new_bss);
    dm_bss_t& get_bss_by_ref(unsigned int index) { return m_bss[index]; }

    unsigned int get_num_ap_mld() { return m_num_ap_mld; }
    static unsigned int get_num_ap_mld(void *dm) { return ((dm_easy_mesh_t *)dm)->get_num_ap_mld(); }
    void set_num_ap_mld(unsigned int num) { m_num_ap_mld = num; }
    static void set_num_ap_mld(void *dm, unsigned int num) { ((dm_easy_mesh_t *)dm)->set_num_ap_mld(num); }
    dm_ap_mld_t *get_ap_mld(unsigned int index) { return &m_ap_mld[index]; }
    dm_ap_mld_t& get_ap_mld_by_ref(unsigned int index) { return m_ap_mld[index]; }

    dm_dpp_t *get_dpp() { return &m_dpp; }

    dm_radio_t *get_radio(unsigned int index);
    dm_radio_t& get_radio_by_ref(unsigned int index) { return m_radio[index]; }
    dm_radio_t *get_radio(mac_address_t mac);
    em_interface_t *get_radio_interface(unsigned int index) { return m_radio[index].get_radio_interface(); }
    em_radio_info_t *get_radio_info(unsigned int index) { return m_radio[index].get_radio_info(); }
    static em_radio_info_t *get_radio_info(void *dm, unsigned int index) { return ((dm_easy_mesh_t *)dm)->get_radio_info(index); }

    rdk_wifi_radio_t    *get_radio_data(em_interface_t *radio);
    unsigned int get_num_radios() { return m_num_radios; }
    static unsigned int get_num_radios(void *dm) { return ((dm_easy_mesh_t *)dm)->get_num_radios(); }
    void set_num_radios(unsigned int num) { m_num_radios = num; }
    static void set_num_radios(void *dm, unsigned int num) { ((dm_easy_mesh_t *)dm)->set_num_radios(num); }
    dm_radio_t *find_matching_radio(dm_radio_t *radio);

    dm_radio_cap_t *get_radio_cap(mac_address_t mac);

    char *get_manufacturer() { return m_device.get_manufacturer(); }
    char *get_manufacturer_model() { return m_device.get_manufacturer_model(); }
    char *get_software_version() { return m_device.get_software_version(); }
    char *get_serial_number() { return m_device.get_serial_number(); }
    char *get_primary_device_type() { return m_device.get_primary_device_type(); }

    unsigned short get_msg_id() { return msg_id; }
    unsigned short set_msg_id(unsigned short id) { msg_id = id; }

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

    em_sta_info_t *get_first_sta_info(em_target_sta_map_t target);
    em_sta_info_t *get_next_sta_info(em_sta_info_t *info, em_target_sta_map_t target);
    em_sta_info_t *get_sta_info(mac_address_t sta, bssid_t bssid, mac_address_t ruid, em_target_sta_map_t target);
    void put_sta_info(em_sta_info_t *info, em_target_sta_map_t target);
    static em_sta_info_t *get_first_sta_info(void *dm, em_target_sta_map_t target) { return ((dm_easy_mesh_t *)dm)->get_first_sta_info(target); }
    static em_sta_info_t *get_next_sta_info(void *dm, em_sta_info_t *info, em_target_sta_map_t target) { return ((dm_easy_mesh_t *)dm)->get_first_sta_info(info, target); }
    static em_sta_info_t *get_sta_info(void *dm, mac_address_t sta, bssid_t bssid, mac_address_t ruid, em_target_sta_map_t target) { return ((dm_easy_mesh_t *)dm)->get_sta_info(sta, bssid, ruid, target); }
    static void put_sta_info(void *dm, em_sta_info_t *info, em_target_sta_map_t target) { ((dm_easy_mesh_t *)dm)->put_sta_info(info, target); }

    dm_sta_t *find_sta(mac_address_t sta_mac, bssid_t bssid);
    dm_sta_t *get_first_sta(mac_address_t sta_mac);
    dm_sta_t *get_next_sta(mac_address_t sta_mac, dm_sta_t *psta);
    bool has_at_least_one_associated_sta();
    
    static void print_hex_dump(unsigned int length, unsigned char *buffer);
    static char *hex(unsigned int in_len, unsigned char *in, unsigned int out_len, char *out);
    static unsigned char *unhex(unsigned int in_len, char *in, unsigned int out_len, unsigned char *out);
    static char *macbytes_to_string(mac_address_t mac, char* string);
    static void string_to_macbytes (char *key, mac_address_t bmac);
    static int mac_address_from_name(const char *ifname, mac_address_t mac);
    static int name_from_mac_address(const mac_address_t *mac, char *ifname);
    static void securitymode_to_str(unsigned short mode, char *sec_mode_str, int len);
	static void str_to_securitymode(unsigned short *mode, char *sec_mode_str, int len);


    static void create_autoconfig_renew_json_cmd(char* src_mac_addr, char* agent_al_mac, em_freq_band_t freq_band, char* autoconfig_renew_json);
    static void create_client_cap_query_json_cmd(char* src_mac_addr, char* agent_al_mac, char* ap_query_json, short msg_id, char *mac);
    static void create_ap_cap_query_json_cmd(char* src_mac_addr, char* agent_al_mac, char* ap_query_json, short msg_id);
    void print_config();

    unsigned int get_db_cfg_type() { return m_db_cfg_type; }
    void set_db_cfg_type(unsigned int type) { m_db_cfg_type = type; }

    void handle_dirty_dm();
    void set_em(em_t *em) { m_em = em; }
    void set_colocated(bool col) { m_colocated = col; }
    bool get_colocated() { return m_colocated; }
	void set_anticipated_channels_list(dm_op_class_t op_class[]);
    em_t *get_em() { return m_em; }
    void clone_hash_maps(dm_easy_mesh_t& obj);

    dm_easy_mesh_t();
    dm_easy_mesh_t(const dm_network_t& net);
    ~dm_easy_mesh_t();  
};

#endif

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

/*
 * NOTE: This file is included also in OneWifi project which is C based, thus
 * there should be only usage of C based constructs in this file.
 * C++ constructs are not allowed in this file.
 */
#ifndef EM_BASE_H
#define EM_BASE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "wifi_webconfig.h"
#include <openssl/evp.h>
#include <uuid/uuid.h>
#include "ec_base.h"

#define EM_MAX_NETWORKS	5
#define EM_MAX_NET_SSIDS 5
#define EM_MAX_INTERFACES	8 
#define EM_MAX_DEVICES 16
#define EM_MAX_PLATFORMS	5
#define ETH_P_1905      0x893a
#define MAX_INTF_NAME_SZ    16
#define EM_MAC_STR_LEN  17
#define EM_MAX_COLS     32
#define EM_MAX_DM_CHILDREN	32
#define EM_MAX_E4_TABLE_CHANNEL 32
#define EM_DATE_TIME_BUFF_SZ	64
#define EM_PROTO_TOUT   1
#define EM_METRICS_REQ_MULT 5
#define EM_MGR_TOUT     500 // in milliseconds
#define EM_1_TOUT_MULT 	2
#define EM_2_TOUT_MULT 	4	
#define EM_5_TOUT_MULT 	10	
#define EM_CTRL_CAP_SZ  8
#define MIN_MAC_LEN 12
#define MAX_EM_BUFF_SZ  1024
#define EM_MAX_FRAME_BODY_LEN	512
#define MAX_VENDOR_INFO 5
#define EM_MAX_BEACON_MEASUREMENT_LEN  400
#define EM_MAX_BEACON_REPORTS_PER_SCAN 10

#define EM_TEST_IO_PERM 0666
#define EM_IO_BUFF_SZ   4096
#define EM_LONG_IO_BUFF_SZ   4096*4

#define EM_MAX_OP_CLASS    48
#define EM_MAX_POLICIES	16	
#define EM_MAX_CHANNEL_PER_OP_CLASS  59
#define EM_MAX_SERVICE          8
#define EM_MAX_BSS_PER_RADIO           16
#define EM_MAX_RADIO_PER_AGENT         4
#define EM_MAX_TRAFFIC_SEP_SSID        8
#define EM_MAX_FREQ_RECORDS_PER_RADIO  8
#define MAP_INVENTORY_ITEM_LEN  64
#define MAX_MCS  6
#define MAP_AP_ROLE_MAX 2
#define MAX_MCS_NSS 6
#define EM_MAX_CAC_METHODS 4
#define EM_MAX_STA_PER_BSS         128
#define EM_MAX_STA_PER_STEER_POLICY        16 
#define EM_MAX_STA_PER_AGENT       (EM_MAX_RADIO_PER_AGENT * EM_MAX_STA_PER_BSS)
#define EM_MAX_NEIGHBORS	16
#define EM_MAX_CHANNEL_SCAN_RPRT_MSG_LEN		166
#define EM_MAX_CLIENT_MARKER    5

#define   EM_MAX_EVENT_DATA_LEN   4096*100
#define EM_MAX_CHANNELS_IN_LIST  64
#define EM_MAX_CMD_GEN_TTL  10
#define EM_MAX_CMD_EXT_TTL  30
#define EM_MAX_RENEW_TX_THRESH  5
#define EM_MAX_CAP_QUERY_TX_THRESH  2
#define EM_MAX_TOPO_QUERY_TX_THRESH  5
#define EM_MAX_CLIENT_STEER_REQ_TX_THRESH  5
#define EM_MAX_CLIENT_ASSOC_CTRL_REQ_TX_THRESH  5
#define MAX_STA_TO_DISASSOC		32
#define EM_MAX_DB_CFG_CRITERIA	32

#define EM_CLI_MAX_ARGS 5

/* Authentication Type Flags */
#define EM_AUTH_OPEN 0x0001
#define EM_AUTH_WPAPSK 0x0002
#define EM_AUTH_SHARED 0x0004 /* deprecated */
#define EM_AUTH_SAE 0x0005
#define EM_AUTH_WPA 0x0008
#define EM_AUTH_WPA2 0x0010
#define EM_AUTH_WPA2PSK 0x0020
#define EM_AUTH_SAE_AKM8 0x0040
#define EM_AUTH_DPP_AKM 0x0080
#define EM_AUTH_SAE_AKM24 0x0100
#define EM_AUTH_TYPES (EM_AUTH_OPEN | EM_AUTH_WPAPSK | EM_AUTH_SHARED | \
            EM_AUTH_WPA | EM_AUTH_WPA2 | EM_AUTH_WPA2PSK | EM_AUTH_SAE_AKM8 | \
            EM_AUTH_DPP_AKM | EM_AUTH_SAE_AKM24 )
    
/* Encryption Type Flags */
#define EM_ENCR_NONE 0x0001
#define EM_ENCR_WEP 0x0002 /* deprecated */
#define EM_ENCR_TKIP 0x0004
#define EM_ENCR_AES 0x0008
#define EM_ENCR_TYPES (EM_ENCR_NONE | EM_ENCR_WEP | EM_ENCR_TKIP | \
            EM_ENCR_AES)

/* RF Bands */
#define EM_RF_24GHZ 0x01
#define EM_RF_50GHZ 0x02
#define EM_RF_60GHZ 0x04
#define EM_RF_6GHZ  0x08

/* Config Methods */
#define EM_CONFIG_USBA 0x0001
#define EM_CONFIG_ETHERNET 0x0002
#define EM_CONFIG_LABEL 0x0004
#define EM_CONFIG_DISPLAY 0x0008
#define EM_CONFIG_EXT_NFC_TOKEN 0x0010
#define EM_CONFIG_INT_NFC_TOKEN 0x0020
#define EM_CONFIG_NFC_INTERFACE 0x0040
#define EM_CONFIG_PUSHBUTTON 0x0080
#define EM_CONFIG_KEYPAD 0x0100
#define EM_CONFIG_VIRT_PUSHBUTTON 0x0280
#define EM_CONFIG_PHY_PUSHBUTTON 0x0480
#define EM_CONFIG_P2PS 0x1000
#define EM_CONFIG_VIRT_DISPLAY 0x2008
#define EM_CONFIG_PHY_DISPLAY 0x4008
    
/* Connection Type Flags */
#define EM_CONN_ESS 0x01
#define EM_CONN_IBSS 0x02

#define EM_MAX_BANDS    3
#define EM_MAX_BSSS     EM_MAX_BANDS*8  
#define EM_MAX_AKMS     10
#define EM_MAX_HAUL_TYPES   8
#define EM_MAX_OPCLASS  64
#define EM_MAX_AP_MLD   64
#define EM_MAX_BSTA_MLD   64
#define EM_MAX_ASSOC_STA_MLD   64
#define EM_MAX_PRE_SET_CHANNELS   6

#define EM_MAX_CMD  16

#define EM_BACKHAUL_DOWNMAC_ADDR 16

#define EM_PATH_PREFIX "/tmp/onewifi_mesh"
#define EM_AGENT_PATH   "agent"
#define EM_CTRL_PATH    "ctrl"
#define EM_CLI_PATH "cli"
#define EM_CFG_FILE "/nvram/EasymeshCfg.json"

#define EM_MAX_SSID_LEN                33 
#define EM_MAX_WIFI_PASSWORD_LEN       65 
/* Disallowed STAList */
#define EM_MSCS_DISALLOWED_STA      10
#define EM_SCS_DISALLOWED_STA       10

#define EM_MIN_OP_CLASS_24 81
#define EM_MAX_OP_CLASS_24 84
#define EM_MIN_OP_CLASS_5 112
#define EM_MAX_OP_CLASS_5 130
#define EM_MIN_OP_CLASS_6 136

#define MAX_WIFI_SSID_LEN           33 /* Length = 32 + 1 for Null character at the end */
#define MAX_SSID_LEN                33 /* Length = 32 + 1 for adding NULL character at the end */
#define MAX_WIFI_PASSWORD_LEN       65 /* Length = 64 + 1 for Null character at the end */

#define DH_KEY_SZ   192
#define AUTHENTICATOR_LEN   8

#define WIFI_EASYMESH_NOTIFICATION "Device.WiFi.Easymesh.Notification"

#define EM_MEDIA_ETH    0x0000
#define EM_MEDIA_WIFI   0x0100
#define EM_MEDIA_ETH_fast   htons(EM_MEDIA_ETH | 0x00)
#define EM_MEDIA_ETH_gig    htons(EM_MEDIA_ETH | 0x01)
#define EM_MEDIA_WIFI_80211b_2_4    htons(EM_MEDIA_WIFI | 0x00)
#define EM_MEDIA_WIFI_80211g_2_4    htons(EM_MEDIA_WIFI | 0x01)
#define EM_MEDIA_WIFI_80211a_5      htons(EM_MEDIA_WIFI | 0x02)
#define EM_MEDIA_WIFI_80211n_2_4    htons(EM_MEDIA_WIFI | 0x03)
#define EM_MEDIA_WIFI_80211n_5      htons(EM_MEDIA_WIFI | 0x04)
#define EM_MEDIA_WIFI_80211ac_5     htons(EM_MEDIA_WIFI | 0x05)
#define EM_MEDIA_WIFI_80211ad_60    htons(EM_MEDIA_WIFI | 0x06)
#define EM_MEDIA_WIFI_80211af       htons(EM_MEDIA_WIFI | 0x07)
#define EM_MEDIA_WIFI_80211ax_6     htons(EM_MEDIA_WIFI | 0x08)

#define 	EM_PARSE_NO_ERR			0
#define 	EM_PARSE_ERR_GEN		EM_PARSE_NO_ERR	- 1	
#define 	EM_PARSE_ERR_NET_ID		EM_PARSE_NO_ERR	- 2	
#define 	EM_PARSE_ERR_CONFIG		EM_PARSE_NO_ERR	- 3	
#define 	EM_PARSE_ERR_NO_CHANGE	EM_PARSE_NO_ERR	- 4	

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif // ETH_ALEN

#ifndef WIFI_EM_CHANNEL_SCAN_REQUEST
#define WIFI_EM_CHANNEL_SCAN_REQUEST          "Device.WiFi.EM.ChannelScanRequest"
#endif

#ifndef WIFI_EC_SEND_TRIG_STA_SCAN
#define WIFI_EC_SEND_TRIG_STA_SCAN          "Device.WiFi.EC.TriggerStaScan"
#endif


#ifndef WIFI_EM_CHANNEL_SCAN_REPORT
#define WIFI_EM_CHANNEL_SCAN_REPORT           "Device.WiFi.EM.ChannelScanReport"
#endif

#ifndef WIFI_SET_DISCONN_STEADY_STATE
#define WIFI_SET_DISCONN_STEADY_STATE         "Device.WiFi.EM.SetDisconnSteadyState"
#endif

#ifndef WIFI_SET_DISCONN_SCAN_NONE_STATE
#define WIFI_SET_DISCONN_SCAN_NONE_STATE      "Device.WiFi.EM.SetDisconnScanNoneState"
#endif

typedef char em_interface_name_t[32];
typedef unsigned char em_nonce_t[16];
typedef unsigned char em_dh5_key_t[192];    // because this is DH group 5 (1536 bits)
typedef char    em_short_string_t[64];
typedef char    em_long_string_t[128];
typedef char    em_2xlong_string_t[256];
typedef char    em_3xlong_string_t[512];
typedef char    em_string_t[32];
typedef char    em_small_string_t[16];
typedef char    em_tiny_string_t[4];
typedef char    em_subdoc_name_space_t[64];
typedef char    em_subdoc_data_buff_t[0];
typedef char    em_status_string_t[EM_IO_BUFF_SZ];
typedef unsigned	char    em_raw_data_t[0];


typedef struct {
    unsigned char   dsap;
    unsigned char   ssap;
    unsigned char   ctrl;
} __attribute__((__packed__)) llc_hdr_t;

typedef struct {
    unsigned char   oui[3];
    unsigned short  type;
} __attribute__((__packed__)) snap_hdr_t;

typedef struct {
    mac_address_t   dst;
    mac_address_t   src;
    unsigned short  type;
} __attribute__((__packed__)) em_raw_hdr_t;

typedef struct {
    mac_address_t   dst;
    mac_address_t   src;
    unsigned short  len;
    llc_hdr_t       llc;
    snap_hdr_t      snap;
} __attribute__((__packed__)) em_raw_ext_hdr_t;

typedef struct {
    unsigned short  id;
    unsigned short  len;
    unsigned char   value[0];
} __attribute__((__packed__)) em_attrib_t;

typedef struct {
    unsigned char   type;
    unsigned short  len;
    unsigned char   value[0];
} __attribute__((__packed__)) em_tlv_t;

typedef struct {
    unsigned char ver;
    unsigned char   reserved;
    unsigned short  type;
    unsigned short  id;
    unsigned char   frag_id;
    unsigned char   reserved_field:6;
    unsigned char   relay_ind:1;
    unsigned char   last_frag_ind:1;
} __attribute__((__packed__)) em_cmdu_t;

typedef struct {
    mac_address_t   cli_mac_address;
    mac_address_t   bssid;
    unsigned char   reserved_field:7;
    unsigned char   assoc_event:1;
} __attribute__((__packed__)) em_client_assoc_event_t;

typedef unsigned char em_enum_type_t;

typedef enum {
    em_service_type_ctrl,
    em_service_type_agent,
    em_service_type_cli,
    em_service_type_none
} em_service_type_t;

typedef enum {
    em_profile_type_reserved,
    em_profile_type_1,
    em_profile_type_2,
    em_profile_type_3,
} em_profile_type_t;

typedef enum {
    em_freq_band_24,    //IEEE-1905-1-2013 table 6-23
    em_freq_band_5,
    em_freq_band_60,
    em_freq_band_unknown
} em_freq_band_t;

typedef struct {
    unsigned char   channel[0];
} __attribute__((__packed__)) em_channels_list_t;

typedef struct {
    unsigned char   op_class;
    unsigned char   max_tx_eirp;
	unsigned char   num;
    em_channels_list_t  channels;
} __attribute__((__packed__)) em_op_class_t;

typedef struct {
    mac_address_t   ruid;
    unsigned char   num_bss;
    unsigned char   op_class_num;
    em_op_class_t   op_classes[0];
} __attribute__((__packed__)) em_ap_radio_basic_cap_t;


typedef enum {
    mandatory,
    optional,
    bad,
} em_tlv_requirement_t;

typedef enum {
    em_msg_type_topo_disc = 0x0000,
    em_msg_type_topo_notif,
    em_msg_type_topo_query,
    em_msg_type_topo_resp,
    em_msg_type_topo_vendor,
    em_msg_type_link_metric_query,
    em_msg_type_link_metric_resp,
    em_msg_type_autoconf_search,
    em_msg_type_autoconf_resp,
    em_msg_type_autoconf_wsc,
    em_msg_type_autoconf_renew,
    em_msg_type_1905_ack = 0x8000,
    em_msg_type_ap_cap_query,
    em_msg_type_ap_cap_rprt,
    em_msg_type_map_policy_config_req,
    em_msg_type_channel_pref_query,
    em_msg_type_channel_pref_rprt,
    em_msg_type_channel_sel_req,
    em_msg_type_channel_sel_rsp,
    em_msg_type_op_channel_rprt,
    em_msg_type_client_cap_query,
    em_msg_type_client_cap_rprt,
    em_msg_type_ap_metrics_query,
    em_msg_type_ap_metrics_rsp,
    em_msg_type_assoc_sta_link_metrics_query,
    em_msg_type_assoc_sta_link_metrics_rsp,
    em_msg_type_unassoc_sta_link_metrics_query,
    em_msg_type_unassoc_sta_link_metrics_rsp,
    em_msg_type_beacon_metrics_query,
    em_msg_type_beacon_metrics_rsp,
    em_msg_type_combined_infra_metrics,
    em_msg_type_client_steering_req,
    em_msg_type_client_steering_btm_rprt,
    em_msg_type_client_assoc_ctrl_req,
    em_msg_type_steering_complete,
    em_msg_type_higher_layer_data,
    em_msg_type_bh_steering_req,
    em_msg_type_bh_steering_rsp,
    em_msg_type_channel_scan_req,
    em_msg_type_channel_scan_rprt,
    em_msg_type_dpp_cce_ind,
    em_msg_type_1905_rekey_req,
    em_msg_type_1905_decrypt_fail,
    em_msg_type_cac_req,
    em_msg_type_cac_term,
    em_msg_type_client_disassoc_stats,
    em_msg_type_svc_prio_req,
    em_msg_type_err_rsp,
    em_msg_type_assoc_status_notif,
    em_msg_type_tunneled,
    em_msg_type_bh_sta_cap_query,
    em_msg_type_bh_sta_cap_rprt,
    em_msg_type_proxied_encap_dpp,
    em_msg_type_direct_encap_dpp,
    em_msg_type_reconfig_trigger,
    em_msg_type_bss_config_req,
    em_msg_type_bss_config_rsp,
    em_msg_type_bss_config_res,
    em_msg_type_chirp_notif,
    em_msg_type_1905_encap_eapol,
    em_msg_type_dpp_bootstrap_uri_notif,
    em_msg_type_anticipated_channel_pref,
    em_msg_type_failed_conn,
    em_msg_type_agent_list = 0x8035,
    em_msg_type_anticipated_channel_usage_rprt,
    em_msg_type_qos_mgmt_notif,
    em_msg_type_ap_mld_config_req = 0x8044,
    em_msg_type_ap_mld_config_resp,
    em_msg_type_bsta_mld_config_req,
    em_msg_type_bsta_mld_config_resp,
    em_msg_type_avail_spectrum_inquiry = 0x8049,
} em_msg_type_t;

typedef enum {
    em_attrib_id_auth_type  = 0x1003,
    em_attrib_id_encr_type = 0x100f,
    em_attrib_id_encr_settings = 0x1018,
    em_attrib_id_key_wrap_auth = 0x101e,
    em_attrib_id_manufacturer  = 0x1021,
    em_attrib_id_message_type,
    em_attrib_id_model_name,
    em_attrib_id_model_number,
    em_attrib_id_network_index = 0x1026,
    em_attrib_id_network_key,
    em_attrib_id_serial_number = 0x1042,
    em_attrib_id_ssid   = 0x1045,
    em_attrib_id_uuid_e  = 0x1047,
    em_attrib_id_uuid_r,
    em_attrib_id_version  = 0x104a,
    em_attrib_id_primary_device_type = 0x1054,
} em_attrib_id_t;

typedef enum {
    em_wsc_msg_type_none,
    em_wsc_msg_type_beacon,
    em_wsc_msg_type_probe_req,
    em_wsc_msg_type_probe_rsp,
    em_wsc_msg_type_m1,
    em_wsc_msg_type_m2,
    em_wsc_msg_type_m2d,
    em_wsc_msg_type_m3,
    em_wsc_msg_type_m4,
    em_wsc_msg_type_m5,
    em_wsc_msg_type_m6,
    em_wsc_msg_type_m7,
    em_wsc_msg_type_m8,
    em_wsc_msg_type_ack,
    em_wsc_msg_type_nack,
    em_wsc_msg_type_done,
} em_wsc_msg_type_t;

typedef enum {
    em_tlv_type_eom = 0,
    em_tlv_type_al_mac_address = 1, 
    em_tlv_type_mac_address = 2,
    em_tlv_type_device_info = 3,
    em_tlv_type_device_bridging_cap = 4,
    em_tlv_type_non1905_neigh_list = 6,
    em_tlv_type_1905_neigh_list = 7,
    em_tlv_type_link_metric = 8,
    em_tlv_type_transmitter_link_metric = 9,
    em_tlv_type_receiver_link_metric = 0x0a,
    em_tlv_type_vendor_specific = 0x0b,
    em_tlv_type_link_metric_result_code = 0x0c,
    em_tlv_type_searched_role = 0x0d,
    em_tlv_type_autoconf_freq_band = 0x0e,
    em_tlv_type_supported_role = 0x0f,
    em_tlv_type_supported_freq_band = 0x10,
    em_tlv_type_wsc = 0x11,
    em_tlv_type_supported_service = 0x80,
    em_tlv_type_searched_service = 0x81,
    em_tlv_type_radio_id = 0x82,
    em_tlv_type_operational_bss = 0x83,
    em_tlv_type_associated_clients = 0x84,
    em_tlv_type_ap_radio_basic_cap = 0x85,
    em_tlv_type_ht_cap = 0x86,
    em_tlv_type_vht_cap = 0x87,
    em_tlv_type_he_cap = 0x88,
    em_tlv_type_steering_policy = 0x89,
    em_tlv_type_metric_reporting_policy = 0x8a,
    em_tlv_type_channel_pref = 0x8b,
    em_tlv_type_radio_op_restriction = 0x8c,
    em_tlv_type_tx_power = 0x8d,
    em_tlv_type_channel_sel_resp = 0x8e,
    em_tlv_type_op_channel_report = 0x8f,
    em_tlv_type_client_info = 0x90,
    em_tlv_type_client_cap_report = 0x91,
    em_tlv_type_client_assoc_event = 0x92,
    em_tlv_type_ap_metrics_query = 0x93,
    em_tlv_type_ap_metrics = 0x94,
    em_tlv_type_sta_mac_addr = 0x95,
    em_tlv_type_assoc_sta_link_metric = 0x96,
    em_tlv_type_unassoc_sta_link_metric_query = 0x97,
    em_tlv_type_unassoc_sta_link_metric_rsp = 0x98,
    em_tlv_type_bcon_metric_query = 0x99,
    em_tlv_type_bcon_metric_rsp = 0x9a,
    em_tlv_type_steering_request = 0x9b,
    em_tlv_type_steering_btm_rprt = 0x9c,
    em_tlv_type_client_assoc_ctrl_req = 0x9d,
    em_tlv_type_bh_steering_req = 0x9e,
    em_tlv_type_bh_steering_rsp = 0x9f,
    em_tlv_type_higher_layer_data = 0xa0,
    em_tlv_type_ap_cap = 0xa1,
    em_tlv_type_assoc_sta_traffic_sts = 0xa2,
    em_tlv_type_error_code = 0xa3,
    em_tlv_type_channel_scan_rprt_policy = 0xa4,
    em_tlv_type_channel_scan_cap = 0xa5,
    em_tlv_type_channel_scan_req = 0xa6,
    em_tlv_type_channel_scan_rslt = 0xa7,
    em_tlv_type_timestamp = 0xa8,
    em_tlv_type_1905_layer_security_cap = 0xa9,
    em_tlv_type_ap_wifi6_cap = 0xaa,
    em_tlv_type_mic = 0xab,
    em_tlv_type_encrypt_payload = 0xac,
    em_tlv_type_cac_req = 0xad,
    em_tlv_type_cac_term = 0xae,
    em_tlv_type_cac_cmpltn_rprt = 0xaf,
    em_tlv_type_assoc_wifi6_sta_rprt = 0xb0,
    em_tlv_type_cac_sts_rprt = 0xb1,
    em_tlv_type_cac_cap = 0xb2,
    em_tlv_type_profile = 0xb3,
    em_tlv_type_profile_2_ap_cap = 0xb4,
    em_tlv_type_dflt_8021q_settings = 0xb5,
    em_tlv_type_traffic_separation_policy = 0xb6,
    em_tlv_type_bss_conf_rep = 0xb7,
    em_tlv_type_bssid = 0xb8,
    em_tlv_type_svc_prio_rule = 0xb9,
    em_tlv_type_dscp_map_tbl = 0xba,
    em_tlv_type_bss_conf_req = 0xbb,
    em_tlv_type_profile_2_error_code = 0xbc,
    em_tlv_type_bss_conf_rsp = 0xbd,
    em_tlv_type_ap_radio_advanced_cap = 0xbe,
    em_tlv_type_assoc_sts_notif = 0xbf,
    em_tlv_type_src_info = 0xc0,
    em_tlv_type_tunneled_msg_type = 0xc1,
    em_tlv_type_tunneled = 0xc2,
    em_tlv_type_profile2_steering_request = 0xc3,
    em_tlv_type_unsucc_assoc_policy = 0xc4,
    em_tlv_type_metric_cltn_interval = 0xc5,
    em_tlv_type_radio_metric = 0xc6,
    em_tlv_type_ap_ext_metric = 0xc7,
    em_tlv_type_assoc_sta_ext_link_metric = 0xc8,
    em_tlv_type_status_code = 0xc9,
    em_tlv_type_reason_code = 0xca,
    em_tlv_type_bh_sta_radio_cap = 0xcb,
    em_tlv_type_akm_suite = 0xcc,
    em_tlv_type_1905_encap_dpp = 0xcd,
    em_tlv_type_1905_encap_eapol = 0xce,
    em_tlv_type_dpp_bootstrap_uri_notification = 0xcf,
    em_tlv_type_backhaul_bss_conf = 0xd0,
    em_tlv_type_dpp_msg = 0xd1,
    em_tlv_type_dpp_cce_indication = 0xd2,
    em_tlv_type_dpp_chirp_value = 0xd3,
    em_tlv_type_device_inventory = 0xd4,
    em_tlv_type_agent_list = 0xd5,
    em_tlv_type_anticipated_channel_pref = 0xd6,
    em_tlv_type_channel_usage = 0xd7,
    em_tlv_type_spatial_reuse_req = 0xd8,
    em_tlv_type_spatial_reuse_rep = 0xd9,
    em_tlv_type_spatial_reuse_cfg_rsp = 0xda,
    em_tlv_type_qos_mgmt_policy = 0xdb,
    em_tlv_type_qos_mgmt_desc = 0xdc,
    em_tlv_type_ctrl_cap = 0xdd,
    em_tlv_type_wifi7_agent_cap = 0xdf,
    em_tlv_type_ap_mld_config = 0xe0,
    em_tlv_type_bsta_mld_config = 0xe1,
    em_tlv_type_assoc_sta_mld_conf_rep = 0xe2,
    em_tlv_type_tid_to_link_map_policy = 0xe6,
    em_tlv_eht_operations = 0xe7,
    em_tlv_type_avail_spectrum_inquiry_reg = 0xe8,
    em_tlv_type_avail_spectrum_inquiry_rsp = 0xe9,
    em_tlv_type_vendor_sta_metrics = 0xf1,
    em_tlv_vendor_plolicy_cfg = 0xf2,
    em_tlv_type_vendor_operational_bss = 0xf3,

	// RDK Proprietary TLV values
	em_tlv_type_rdk_radio_enable = 0xfe,
} em_tlv_type_t;

typedef struct {
    unsigned short qmid;
    mac_address_t bssid;
    mac_address_t client_mac;
    unsigned char desc_element[0];
} __attribute__((__packed__)) em_qos_mgmt_des_t;

typedef struct {
    unsigned char num_agents;
    mac_address_t agent_mac;
    unsigned char multi_ap_profile;
    unsigned char security;
} __attribute__((__packed__)) em_agent_list_t;

typedef struct {
    unsigned char op_class;
    unsigned char channel_num;
    unsigned char ref_bssid[6];
    unsigned char usage_entries;
    unsigned char burst_start_time[4];
    unsigned char burst_len[4];
    unsigned char repetitions[4];
    unsigned char burst_interval[4];
    unsigned char rubitmask_len;
    unsigned char rubitmask[10];
    unsigned char trans_id[6];
    unsigned char power_level;
    unsigned char channel_usage_reason;
    unsigned char reserved[4];
} __attribute__((__packed__)) em_anti_chan_usage_t;

typedef struct {
    mac_address_t   ruid;
    unsigned char bssid[6];
    mac_address_t bsta_addr;
    unsigned char dpp_uri[0];
}__attribute__((__packed__)) em_dpp_bootstrap_uri_t;

typedef struct {
    uint8_t advertise_cce; // 1->Enable, 0->Disable
} __attribute__((__packed__)) em_cce_indication_t;

typedef struct {
    unsigned char enrollee_mac_addr_present : 1;
    unsigned char reserved : 1;
    unsigned char dpp_frame_indicator : 1;
    unsigned char reserved2 : 5;
/*
    Contains:
        - dest_mac_addr (6 bytes, if enrollee_mac_addr_present)
        - frame_type (1 byte)
        - encap_frame_len (2 bytes)
        - encap_frame (encap_frame_len bytes)
*/
    unsigned char data[0];

}__attribute__((__packed__)) em_encap_dpp_t;

typedef struct {
    unsigned char bssid[6];
    unsigned char num_bssid;
    unsigned char assoc_allow_status;
}__attribute__((__packed__)) em_assoc_sts_notif_t;

typedef struct {
    unsigned char reason_code;
    unsigned char bssid[6]; 
    unsigned int svc_prior_rule_id; 
    unsigned short qmid; 
}__attribute__((__packed__)) em_prof2_error_t;

typedef struct {
    mac_address_t   ruid;
    unsigned char num_radios;
    unsigned char op_class;
    unsigned char channel;
}__attribute__((__packed__)) em_cac_term_t;


typedef struct {
    unsigned char num_radios;
    mac_address_t ruid;
    unsigned char op_lass;
    unsigned char channel;
    unsigned char cas_method : 3;
    unsigned char cac_completion_action : 3;
    unsigned char reserved : 2;
}__attribute__((__packed__)) em_cac_req_t;

typedef struct {
    unsigned char timestamp_length;
    unsigned char timestamp[0]; 
}__attribute__((__packed__)) em_timestamp_t;


typedef enum {
	em_scanner_type_radio = 1,
	em_scanner_type_sta,
} em_scanner_type_t;

typedef struct {
    em_long_string_t    net_id;
	mac_address_t	dev_mac;
	mac_address_t scanner_mac;
    unsigned char op_class;
    unsigned char channel;
	em_scanner_type_t	scanner_type;	
} em_scan_result_id_t;

typedef struct {
	bssid_t bssid;
	ssid_t	ssid;
    signed char signal_strength;
	wifi_channelBandwidth_t	bandwidth;
    unsigned char bss_color;
    unsigned char channel_util;
    unsigned short sta_count;
} em_neighbor_t;

typedef struct {
	em_scan_result_id_t	id;
	unsigned char scan_status;
	em_long_string_t timestamp;
    unsigned char util;
    unsigned char noise;
	unsigned short num_neighbors;
	em_neighbor_t	neighbor[EM_MAX_NEIGHBORS];
    unsigned int  aggr_scan_duration;
    unsigned char scan_type;
} em_scan_result_t;

typedef struct {
    mac_address_t ruid;
    unsigned char op_class;
    unsigned char channel;
    unsigned char scan_status;
    unsigned char timestamp_len;
    char timestamp[0]; 
}__attribute__((__packed__)) em_channel_scan_result_t;

typedef struct {
	mac_address_t ruid;	
	unsigned int num_op_classes;
	struct {
		unsigned char op_class;
		unsigned int num_channels;
		unsigned char	channels[EM_MAX_CHANNELS_IN_LIST];
	} op_class[EM_MAX_OP_CLASS];
} em_scan_params_t;

typedef struct {
    unsigned char op_class;
    unsigned char num_channels;
    unsigned char channel_list[0]; 
} __attribute__((__packed__)) em_channel_scan_req_op_class_t;

typedef struct {
    unsigned char perform_fresh_scan : 1;
    unsigned char reserved : 7;
    unsigned char num_radios;
    mac_address_t ruid;
    unsigned char num_op_classes;
	em_channel_scan_req_op_class_t op_class[0];
}__attribute__((__packed__)) em_channel_scan_req_t;

typedef struct {
    unsigned char higher_layer_proto;
    unsigned char *payload;
}__attribute__((__packed__)) em_higher_layer_data_t;

typedef struct {
    unsigned char reason_code;
    mac_address_t sta_mac_addr;
}__attribute__((__packed__)) em_error_code_t;

typedef struct {
    mac_address_t bh_sta_mac_addr;
    unsigned char target_bssid[6];
    unsigned char result_code;
}__attribute__((__packed__)) em_bh_steering_resp_t;

typedef struct {
    mac_address_t bh_sta_mac_addr;
    unsigned char target_bssid[6];
    unsigned char op_class;
    unsigned char channel_numb;
}__attribute__((__packed__)) em_bh_steering_req_t;

typedef struct {
    bssid_t 	bssid;
    unsigned char assoc_control;
    unsigned short validity_period;
    unsigned char count;
    mac_address_t sta_mac;
}__attribute__((__packed__)) em_client_assoc_ctrl_req_t;

typedef struct {
    unsigned char bssid[6];
    mac_address_t sta_mac_addr;
    unsigned char btm_status_code;
    unsigned char target_bssid[6];
}__attribute__((__packed__)) em_steering_btm_rprt_t;

typedef struct {
    bssid_t bssid;
    unsigned char req_mode : 1;
    unsigned char btm_dissoc_imminent : 1;
    unsigned char btm_abridged : 1;
    unsigned char btm_link_removal_imminent : 1;
    unsigned char reserved : 4;
    unsigned short steering_opportunity_window;
    unsigned short btm_dissoc_timer;
    unsigned char sta_list_count;
    mac_address_t sta_mac_addr;
    unsigned char target_bssid_list_count;
    bssid_t target_bssids;
    unsigned char target_bss_op_class;
    unsigned char target_bss_channel_num;
}__attribute__((__packed__)) em_steering_req_t;

typedef struct {
    unsigned char pref_candidate_list_inc : 1;
    unsigned char btm_abridged : 1;
    unsigned char btm_disassoc_imminent : 1;
    unsigned char bss_termination_inc : 1;
    unsigned char ess_disassoc_imminent : 1;
    unsigned char reserved : 3;
}__attribute__((__packed__)) em_80211_btm_req_reqmode_t;

typedef struct {
    unsigned char elem_id;//52
    unsigned char length;
    bssid_t bssid;
    unsigned int bssid_info;
    unsigned char op_class;
    unsigned char channel_num;
    unsigned char phy_type;
    //optional elements
    unsigned char var[0];
}__attribute__((__packed__)) em_80211_neighbor_report_t;

typedef struct {
    //todo: bss_termination_duration;
    //session_info_url;
    em_80211_neighbor_report_t bss_transition_cand_list[0];
}__attribute__((__packed__)) em_80211_btm_req_var_t;

typedef struct {
    em_steering_req_t agile_multiband;
    unsigned char reason_code;
}__attribute__((__packed__)) em_profile2_steering_req_t;

typedef struct {
    mac_address_t sta_mac_addr;
    unsigned char reserved;
    unsigned char meas_rprt_count;
    unsigned char meas_reports[0];
}__attribute__((__packed__)) em_beacon_metrics_resp_t;

typedef struct {
    unsigned char ap_channel_rprt_len;
    unsigned char ap_channel_op_class;
    unsigned char ap_channel_list[6];
}__attribute__((__packed__)) em_beacon_ap_channel_rprt_t;

typedef struct {
    unsigned char num_element_id;
    unsigned char element_list[6];
}__attribute__((__packed__)) em_beacon_element_list_t;

typedef struct {
    mac_address_t sta_mac_addr;
    unsigned char op_class;
    unsigned char channel_num;
    bssid_t bssid;
    unsigned char rprt_detail;
    unsigned char ssid_len;
    ssid_t ssid;
    unsigned char num_ap_channel_rprt;
    em_beacon_ap_channel_rprt_t ap_channel_rprt[6];
    unsigned char num_element_id;
    em_beacon_element_list_t element_list;
}__attribute__((__packed__)) em_beacon_metrics_query_t;

typedef struct {
    unsigned char op_class;
    unsigned char num_channels;
    unsigned char channel_num;
    unsigned char num_sta_mac_addr;
    mac_address_t sta_mac_addr;
}__attribute__((__packed__)) em_unassoc_sta_link_metrics_query_t;

typedef struct {
    unsigned char op_class;
    unsigned char num_sta_entries;
    mac_address_t sta_mac_addr;
    unsigned char channel_num;
    unsigned int  time_delta_ms;
    unsigned char uplink_rcpi;
}__attribute__((__packed__)) em_unassoc_sta_link_metrics_rsp_t;

typedef struct {
     mac_address_t sta_mac_addr;
}__attribute__((__packed__)) em_assoc_sta_mac_addr_t;

typedef struct {
    bssid_t     bssid;
    unsigned int  time_delta_ms;
    unsigned int  est_mac_data_rate_dl;
    unsigned int  est_mac_data_rate_ul;
    unsigned char rcpi;
}__attribute__((__packed__)) em_assoc_link_metrics_t;

typedef struct {
    mac_address_t sta_mac;
    unsigned char num_bssids;
    em_assoc_link_metrics_t	assoc_link_metrics[0];
}__attribute__((__packed__)) em_assoc_sta_link_metrics_t;

typedef struct {
    bssid_t 	bssid;
    unsigned int  last_data_dl_rate;
    unsigned int  last_data_ul_rate;
    unsigned int  util_receive;
    unsigned int  util_transmit;
}__attribute__((__packed__)) em_assoc_ext_link_metrics_t;

typedef struct {
    mac_address_t sta_mac;
    unsigned char num_bssids;
    em_assoc_ext_link_metrics_t	assoc_ext_link_metrics[0];
}__attribute__((__packed__)) em_assoc_sta_ext_link_metrics_t;

typedef struct {
    bssid_t     bssid;
    unsigned int  packets_received;
    unsigned int  packets_sent;
    unsigned int  bytes_received;
    unsigned int  bytes_sent;
}__attribute__((__packed__)) em_assoc_vendor_link_metrics_t;

typedef struct {
    mac_address_t sta_mac;
    bssid_t bssid;
    em_string_t sta_client_type;
    //unsigned char num_bssids;
    //em_assoc_vendor_link_metrics_t assoc_vendor_link_metrics[0];
}__attribute__((__packed__)) em_assoc_sta_vendor_link_metrics_t;

typedef struct {
    unsigned char num_bssids;
    unsigned char bssid[6];
}__attribute__((__packed__)) em_ap_metrics_query_t;

typedef struct {
    mac_address_t   ruid;
}__attribute__((__packed__)) em_ap_radio_id_t;

typedef struct {
    bssid_t bssid;
    unsigned char channel_util;
    unsigned short num_sta;
    unsigned char est_service_params_BE_bit : 1;
    unsigned char est_service_params_BK_bit : 1;
    unsigned char est_service_params_VO_bit : 1;
    unsigned char est_service_params_VI_bit : 1;
    unsigned char reserved : 4;
    unsigned char est_service_params_BE[3];
    unsigned char est_service_params_BK[3];
    unsigned char est_service_params_VO[3];
    unsigned char est_service_params_VI[3];
} __attribute__((__packed__)) em_ap_metric_t;


typedef struct {
    unsigned char bssid[6];
    unsigned char uni_bytes_sent[4];
    unsigned char uni_bytes_recv[4];
    unsigned char multi_bytes_sent[4];
    unsigned char multi_bytes_recv[4];
    unsigned char bcast_bytes_sent[4];
    unsigned char bcast_bytes_recv[4];
} __attribute__((__packed__)) em_ap_ext_metric_t;

typedef struct {
    mac_address_t ruid;
    unsigned char noise;
    unsigned char transmit;
    unsigned char rece_self;
    unsigned char rece_other;
} __attribute__((__packed__)) em_radio_metric_t;

typedef struct {
    mac_address_t sta_mac_addr;
    unsigned int bytes_sent;
    unsigned int bytes_recv;
    unsigned int packets_sent;
    unsigned int packets_recv;
    unsigned int tx_packets_errors;
    unsigned int rx_packets_errors;
    unsigned int retrans_count;
} __attribute__((__packed__)) em_assoc_sta_traffic_sts_t;

typedef struct {
    mac_address_t sta_mac_addr;
    unsigned char n;
    unsigned char tid;
    unsigned char queue_size;
} __attribute__((__packed__)) em_assoc_wifi6_sta_sts_t;

typedef struct {
    mac_address_t client_mac_addr;
    unsigned char bssid[6];
} __attribute__((__packed__)) em_client_info_t;

typedef struct {
    unsigned char result_code;
    unsigned short  assoc_frame_body_len;
    unsigned char *assoc_frame_body;
} __attribute__((__packed__)) em_client_cap_rprt_t;

typedef struct {
    unsigned char op_class;
    unsigned char channel;
} __attribute__((__packed__)) em_op_class_ch_rprt_t;

typedef struct {
    mac_address_t  ruid;
    unsigned char  op_classes_num;
    em_op_class_ch_rprt_t  op_classes[0];
} __attribute__((__packed__)) em_op_channel_rprt_t;

typedef struct {
    mac_address_t ruid;
    unsigned char reserved1 : 1;
    unsigned char partial_bss_color : 1;
    unsigned char bss_color : 6;
    unsigned char reserved2 : 3;
    unsigned char hesiga_spatial_reuse_value15_allowed : 1;
    unsigned char srg_info_valid : 1;
    unsigned char non_srg_offset_valid : 1;
    unsigned char reserved3 : 1;
    unsigned char psr_disallowed : 1;
    unsigned char non_srg_obsspd_max_offset;
    unsigned char srg_obsspd_min_offset;
    unsigned char srg_obsspd_max_offset;
    unsigned char srg_bss_color_bitmap[8];
    unsigned char srg_partial_bssid_bitmap[8];
    unsigned char neigh_bss_color_in_use_bitmap[8];
    unsigned char reserved[2];
} __attribute__((__packed__)) em_spatial_reuse_rprt_t;

typedef enum {
    em_chan_sel_resp_code_type_accept,
    em_chan_sel_resp_code_type_decline,
    em_chan_sel_resp_code_type_decline_rep_pref,
    em_chan_sel_resp_code_type_decline_conflict,
} em_chan_sel_resp_code_type_t;

typedef enum {
    em_prof2_error_code_reason_code_reserved,
    em_prof2_error_code_reason_code_svc_prio_rule_not_found,
    em_prof2_error_code_reason_code_svc_prio_rule_max,
    em_prof2_error_code_reason_code_pcp_vlan_id_not_provided,
    em_prof2_error_code_reason_code_reserved2,
    em_prof2_error_code_reason_code_vlan_id_max,
    em_prof2_error_code_reason_code_reserved3,
    em_prof2_error_code_reason_code_traf_sep_comb_ass_unsupported,
    em_prof2_error_code_reason_code_mix_traf_sep_unsupported,
    em_prof2_error_code_reason_code_reserved4,
    em_prof2_error_code_reason_code_traf_sep_not_supported,
    em_prof2_error_code_reason_code_qos_mgmt_policy_not_conf,
    em_prof2_error_code_reason_code_qos_mgmt_dscp_policy_rejected,
    em_prof2_error_code_reason_code_agent_not_onboard_other,
    em_prof2_error_code_reason_code_eht_subchan_bitmap_error,
} em_prof2_error_code_reason_code_type_t;

typedef struct {
    mac_address_t ruid;
    unsigned char response_code;
} __attribute__((__packed__)) em_channel_sel_rsp_t;

typedef struct {
    em_channel_sel_rsp_t config_resp;
} __attribute__((__packed__)) em_spatial_reuse_cfg_rsp_t;

typedef struct {
    unsigned char op_class;
	unsigned char   num;
    em_channels_list_t channels;
} __attribute__((__packed__)) em_channel_pref_op_class_t;

typedef struct {
    mac_address_t ruid;
    unsigned char op_classes_num;
    em_channel_pref_op_class_t op_classes[0];
} __attribute__((__packed__)) em_channel_pref_t;

typedef struct {
    mac_address_t ruid;
    unsigned char tx_power_eirp;
} __attribute__((__packed__)) em_tx_power_limit_t;

typedef struct {
    mac_address_t ruid;
    unsigned char reserved1 : 2;
    unsigned char bss_color : 6;
    unsigned char reserved2 : 3;
    unsigned char hesiga_spatial_reuse_value15_allowed : 1;
    unsigned char srg_info_valid : 1;
    unsigned char non_srg_offset_valid : 1;
    unsigned char reserved3: 1;
    unsigned char psr_disallowed : 1;
    unsigned char non_srg_obsspd_max_offset;
    unsigned char srg_obsspd_min_offset;
    unsigned char srg_obsspd_max_offset;
    unsigned char srg_bss_color_bitmap[8];
    unsigned char srg_partial_bssid_bitmap[8];
    unsigned char reserved[2];
} __attribute__((__packed__)) em_spatial_reuse_req_t;

typedef struct {
    unsigned char channel;
    unsigned char freq_restrict;
} __attribute__((__packed__)) em_radio_op_restrict_channel_t;

typedef struct {
    unsigned char op_class;
    unsigned char channels_num;
    em_radio_op_restrict_channel_t channels[0];
} __attribute__((__packed__)) em_radio_op_restrict_op_class_t;

typedef struct {
    mac_address_t ruid;
    unsigned char op_classes_num;
    em_radio_op_restrict_op_class_t op_classes[0];
} __attribute__((__packed__)) em_radio_op_restriction_t;


typedef struct {
    unsigned char op_class;
    unsigned char channel;
} __attribute__((__packed__)) em_cac_comp_rprt_pair_t;

typedef struct {
    mac_address_t ruid;
    unsigned char op_class;
    unsigned char channel;
    unsigned char status;
    unsigned char detected_pairs_num;
    em_cac_comp_rprt_pair_t detected_pairs[0];
} __attribute__((__packed__)) em_cac_comp_rprt_radio_t;

typedef struct {
    unsigned char radios_num;
    em_cac_comp_rprt_radio_t   radios[0];
} __attribute__((__packed__)) em_cac_comp_rprt_t;


typedef struct  {
    unsigned char  op_class;
    unsigned char  channel;
    unsigned short mins_since_cac_comp;
} __attribute__((__packed__)) em_cac_avail_t;

typedef struct {
    unsigned char  op_class;
    unsigned char  channel;
    unsigned short sec_remain_non_occ_dur;
} __attribute__((__packed__)) em_cac_non_occ_t;

typedef struct {
    unsigned char  op_class;
    unsigned char  channel;
    unsigned char  countdown_cac_comp[3];
} __attribute__((__packed__)) em_cac_active_t;

typedef struct {
    unsigned char         avail_num;
    em_cac_avail_t   avail[0];
} __attribute__((__packed__)) em_cac_status_rprt_avail_t;

typedef struct {
    unsigned char         non_occ_num;
    em_cac_non_occ_t   non_occ[0];
} __attribute__((__packed__)) em_cac_status_rprt_non_occ_t;

typedef struct {
    unsigned char   active_num;
    em_cac_active_t   active[0];
} __attribute__((__packed__)) em_cac_status_rprt_active_t;

typedef struct {
    unsigned short  media_type;
    unsigned char  media_spec_size; // size of the ensuing data
    mac_address_t network_memb;
    unsigned char  role;
    unsigned char  band;
    unsigned char  center_freq_index_1;
    unsigned char  center_freq_index_2;
} __attribute__((__packed__)) em_media_spec_data_t;

typedef struct {
    mac_address_t  mac_addr;
	em_media_spec_data_t	media_data;
} __attribute__((__packed__)) em_local_interface_t;

typedef struct {
    mac_address_t  al_mac_addr;
    unsigned char  local_interface_num;
	em_local_interface_t 	local_interface[0];
} __attribute__((__packed__)) em_device_info_type_t;

typedef struct {
    mac_address_t mac_addr;
} __attribute__((__packed__)) em_bridge_tuple_mac_entry_t;

typedef struct {
    unsigned char bridge_tuple_macs_nr;
    em_bridge_tuple_mac_entry_t  *bridge_tuple_macs;
} __attribute__((__packed__)) em_bridge_tuple_entry_t;

typedef struct {
    unsigned char   bridge_tuples_num;
    em_bridge_tuple_entry_t  *bridge_tuples;
} __attribute__((__packed__)) em_device_bridge_cap_t;

typedef struct {
    mac_address_t  mac_addr;
} __attribute__((__packed__)) em_non_1905_neigh_entry_t;

typedef struct {
    mac_address_t  local_mac_addr;
    unsigned char   non_1905_neigh_num;
    em_non_1905_neigh_entry_t  *non_1905_neigh;
} __attribute__((__packed__)) em_non_1905_neigh_device_list_t;

typedef struct {
    mac_address_t  mac_addr;
    unsigned char  bridge_flag;
} __attribute__((__packed__)) em_neigh_entry_t;

typedef struct {
    mac_address_t  local_mac_addr;
    unsigned char   neigh_num;
    em_neigh_entry_t  *neigh;
} __attribute__((__packed__)) em_neigh_device_list_t;

typedef struct {
	   mac_address_t bssid;
		  unsigned short haultype;
} __attribute__((__packed__)) em_ap_vendor_operational_bss_t;

typedef struct {
	   mac_address_t ruid;
	   unsigned char	 bss_num;
	   em_ap_vendor_operational_bss_t  bss[0];
} __attribute__((__packed__)) em_ap_vendor_op_bss_radio_t;

typedef struct {
	   unsigned char	radios_num;
	   em_ap_vendor_op_bss_radio_t		 radios[0];
} __attribute__((__packed__)) em_ap_vendor_op_bss_t;

typedef struct {
    mac_address_t bssid;
    unsigned char  ssid_len;
    char  ssid[0];
} __attribute__((__packed__)) em_ap_operational_bss_t;

typedef struct {
    mac_address_t ruid;
    unsigned char     bss_num;
    em_ap_operational_bss_t  bss[0];
} __attribute__((__packed__)) em_ap_op_bss_radio_t;

typedef struct {
    unsigned char    radios_num;
    em_ap_op_bss_radio_t   radios[0];
} __attribute__((__packed__)) em_ap_op_bss_t;

typedef struct {
    mac_address_t   mac_addr;
    unsigned short   assoc_time;
} __attribute__((__packed__)) em_assoc_clients_sta_t;

typedef struct {
    mac_address_t   bssid;
    unsigned short   stas_num;
    em_assoc_clients_sta_t *stas;
} __attribute__((__packed__)) em_assoc_clients_bss_t;

typedef struct {
    unsigned char  bss_num;
    em_assoc_clients_bss_t  bss[EM_MAX_BSS_PER_RADIO];
} __attribute__((__packed__)) em_assoc_clients_t;

typedef struct {
    mac_address_t   bssid;
} __attribute__((__packed__)) em_bssid_t;

typedef struct {
    unsigned short status_code;
} __attribute__((__packed__)) em_status_code_t;

typedef struct {
    unsigned short reason_code;
} __attribute__((__packed__)) em_reason_code_t;

typedef struct {
    unsigned char *dpp_config_obj;
} __attribute__((__packed__)) em_bss_conf_rsp_t;

typedef struct {
    unsigned char *dpp_config_req_obj;
} __attribute__((__packed__)) em_bss_conf_req_t;

typedef struct {
    unsigned short primary_vlan_id;
    unsigned char  default_pcp : 3;
    unsigned char  reserved : 5;
} __attribute__((__packed__)) em_8021q_settings_t;

typedef struct {
    unsigned char  ssid_len;
    char  ssid[0];
} __attribute__((__packed__)) em_traffic_sep_policy_ssid_t;

typedef struct {
    unsigned char  ssids_num;
    em_traffic_sep_policy_ssid_t  ssids[0];
} __attribute__((__packed__)) em_traffic_sep_policy_t;

typedef struct {
    unsigned char  oui[3];
    unsigned char  akm_suite_type;
} __attribute__((__packed__)) em_bh_akm_suite_t;

typedef struct {
    unsigned char  oui[3];
    unsigned char  akm_suite_type;
} __attribute__((__packed__)) em_fh_akm_suite_t;

typedef struct {
    unsigned char  bh_akm_suite_count;
    em_bh_akm_suite_t  *bh_akm_suites;
    unsigned char  fh_akm_suite_count;
    em_fh_akm_suite_t  *fh_akm_suites;
} __attribute__((__packed__)) em_akm_suite_info_t;

typedef struct {
    mac_address_t  ruid;
    unsigned char  bsta_mac_present : 1;
    unsigned char  reserved : 7;
    mac_address_t  bsta_addr;
} __attribute__((__packed__)) em_bh_sta_radio_cap_t;

typedef struct {
        unsigned char   op_class_num;
        em_op_class_t   op_classes[EM_MAX_OP_CLASS];
} __attribute__((__packed__)) em_anti_channel_pref_t;

typedef struct {
    unsigned char  max_prior_rule;
    unsigned char  reserved1;
    unsigned char  byte_counter_units : 2;
    unsigned char  prioritization : 1;
    unsigned char  dpp_onboarding : 1;
    unsigned char  traffic_separation : 1;
    unsigned char  reserved2 : 3;
    unsigned char  max_vid_count;
} __attribute__((__packed__)) em_profile_2_ap_cap_t;

typedef struct {
    unsigned int   rule_id;
    unsigned char  add_rule : 1;
    unsigned char  reserved1 : 7;
    unsigned char  rule_precedence;
    unsigned char  rule_output;
    unsigned char  always_match : 1;
    unsigned char  reserved2 : 7;
} __attribute__((__packed__)) em_service_prio_rule_t;

typedef struct {
    unsigned char   dscp_pcp[64];
} __attribute__((__packed__)) em_dscp_map_table_t;

typedef struct  {
    mac_address_t sta_mac;
    unsigned int tx_bytes;
    unsigned int rx_bytes;
    unsigned int tx_pkts;
    unsigned int rx_pkts;
    unsigned int tx_pkt_errors;
    unsigned int rx_pkt_errors;
    unsigned int retx_cnt;
} __attribute__((__packed__)) em_assoc_sta_traffic_stats_t;

typedef struct {
    mac_address_t src_mac;
} __attribute__((__packed__)) em_source_info_t;

typedef struct {
    unsigned char msg_type;
} __attribute__((__packed__)) em_tunneled_msg_type_t;

typedef struct {
    unsigned short  frame_body_len;
    unsigned char  *frame_body;
} __attribute__((__packed__)) em_tunneled_t;

typedef struct {
    mac_address_t mac_addr;         
} __attribute__((__packed__)) em_1905_mac_addr_t;

typedef struct {
    unsigned char  vendor_oui[3];
    unsigned short m_num;
    unsigned char  *m;
} __attribute__((__packed__)) em_vendor_specific_t;

typedef struct {
    unsigned char  destination;    
    mac_address_t  specific_neigh;
    unsigned char  link_metrics_type; 
} __attribute__((__packed__)) em_link_metric_query_t;

typedef struct {
    mac_address_t   local_interface_addr;
    mac_address_t   neigh_interface_addr;
    unsigned short  intf_type;
    unsigned char   bridge_flag;
    unsigned int    packet_errors;
    unsigned int    tx_packets;
    unsigned short  mac_tp_capacity;
    unsigned short  link_availability;
    unsigned short  phy_rate;
} __attribute__((__packed__)) em_tx_link_metric_entry_t;

typedef struct {
    mac_address_t   local_al_addr;
    mac_address_t   neigh_al_addr;
    unsigned char   tx_link_metrics_num;
    em_tx_link_metric_entry_t  *tx_link_metrics;
} __attribute__((__packed__)) em_tx_link_metric_t;

typedef struct {
    mac_address_t   local_interface_addr;
    mac_address_t   neigh_interface_addr;
    unsigned short  intf_type;
    unsigned int    packet_errors;
    unsigned int    rx_packets;
    unsigned char   rssi;
} __attribute__((__packed__)) em_rx_link_metric_entry_t;

typedef struct {
    mac_address_t   local_al_addr;
    mac_address_t   neigh_al_addr;
    unsigned char   rx_link_metrics_num;
    em_rx_link_metric_entry_t  *rx_link_metrics;
} __attribute__((__packed__)) em_rx_link_metric_t;

typedef struct {
    mac_address_t   ruid;
    unsigned char   vendor_len;
    unsigned char   vendor[MAP_INVENTORY_ITEM_LEN];
} __attribute__((__packed__)) em_radio_vendor_t;

typedef struct {
    unsigned char   serial_len;
    unsigned char   serial[MAP_INVENTORY_ITEM_LEN];
    unsigned char   ver_len;
    unsigned char   version[MAP_INVENTORY_ITEM_LEN];
    unsigned char   envi_len;
    unsigned char   environment[MAP_INVENTORY_ITEM_LEN];
    unsigned char   radios_num;
    em_radio_vendor_t radios[EM_MAX_RADIO_PER_AGENT];
} __attribute__((__packed__)) em_device_inventory_t;

typedef struct {
    mac_address_t  ruid;
    unsigned char  max_sprt_tx_streams : 2;
    unsigned char  max_sprt_rx_streams : 2;
    unsigned char  gi_sprt_20mhz : 1;
    unsigned char  gi_sprt_40mhz : 1;
    unsigned char  ht_sprt_40mhz : 1;
    unsigned char  reserved : 1;
} __attribute__((__packed__)) em_ap_ht_cap_t;

typedef struct {
    mac_address_t  ruid;
    unsigned short sprt_tx_mcs;
    unsigned short sprt_rx_mcs;
    unsigned char  max_sprt_tx_streams : 3;
    unsigned char  max_sprt_rx_streams : 3;
    unsigned char  gi_sprt_80mhz : 1;
    unsigned char  gi_sprt_160mhz : 1;
    unsigned char  sprt_80_80_mhz : 1;
    unsigned char  sprt_160mhz : 1;
    unsigned char  su_beamformer_cap : 1;
    unsigned char  mu_beamformer_cap : 1;
    unsigned char  reserved : 4;
} __attribute__((__packed__)) em_ap_vht_cap_t;

typedef struct {
    mac_address_t  ruid;
    unsigned char  sprt_mcs_len;
    unsigned short sprt_tx_rx_mcs[MAX_MCS];
    unsigned char  max_sprt_tx_streams : 3;
    unsigned char  max_sprt_rx_streams : 3;
    unsigned char  sprt_80_80_mhz : 1;
    unsigned char  sprt_160mhz : 1;
    unsigned char  su_beamformer_cap : 1;
    unsigned char  mu_beamformer_cap : 1;
    unsigned char  ul_mimo_cap : 1;
    unsigned char  ul_mimo_ofdma_cap : 1;
    unsigned char  dl_mimo_ofdma_cap : 1;
    unsigned char  ul_ofdma_cap : 1;
    unsigned char  dl_ofdma_cap : 1;
    unsigned char  reserved : 1;
} __attribute__((__packed__))em_ap_he_cap_t;


typedef struct {
    unsigned char  agent_role : 2;
    unsigned char  he_160 : 1;
    unsigned char  he_8080 : 1;
    unsigned char  mcs_nss_num : 4;
    unsigned short mcs_nss[MAX_MCS_NSS];
    unsigned char  su_beam_former : 1;
    unsigned char  su_beam_formee : 1;
    unsigned char  mu_beam_former : 1;
    unsigned char  beam_formee_sts_l80 : 1;
    unsigned char  beam_formee_sts_g80 : 1;
    unsigned char  ul_mumimo : 1;
    unsigned char  ul_ofdma : 1;
    unsigned char  dl_ofdma : 1;
    unsigned char  max_dl_mumimo_tx : 4;
    unsigned char  max_ul_mumimo_rx : 4;
    unsigned char  max_dl_ofdma_tx;
    unsigned char  max_ul_ofdma_rx;
    unsigned char  rts : 1;
    unsigned char  mu_rts : 1;
    unsigned char  multi_bssid : 1;
    unsigned char  mu_edca : 1;
    unsigned char  twt_req : 1;
    unsigned char  twt_resp : 1;
    unsigned char  spatial_reuse : 1;
    unsigned char  reserved : 1;
} __attribute__((__packed__)) em_radio_wifi6_cap_data_t;

typedef struct {
    mac_address_t  ruid;
    unsigned char  roles_num;
    em_radio_wifi6_cap_data_t  cap_data[MAP_AP_ROLE_MAX];
} __attribute__((__packed__))em_ap_wifi6_cap_t;

typedef struct {
    mac_address_t ruid;
    unsigned char freq_sep : 5;
    unsigned char reserved : 3;
} __attribute__((__packed__)) em_radio_wifi7_freq_record_t;

typedef struct {
    unsigned char num_records;
    em_radio_wifi7_freq_record_t records[EM_MAX_FREQ_RECORDS_PER_RADIO];
} __attribute__((__packed__)) em_radio_wifi7_freq_records_t;

typedef struct {
    unsigned char max_num_mlds;
    unsigned char ap_max_links : 4;
    unsigned char bsta_max_links : 4;
    unsigned char tid_link_mapping_cap : 2;
    unsigned char reserved1 : 6;
    unsigned char reserved2[13];
} __attribute__((__packed__)) em_radio_wifi7_cap_data_t;

typedef struct {
    mac_address_t ruid;
    unsigned char reserved3[24];
    unsigned char ap_str_support : 1;
    unsigned char ap_nstr_support : 1;
    unsigned char ap_emlsr_support : 1;
    unsigned char ap_emlmr_support : 1;
    unsigned char reserved4 : 4;
    unsigned char bsta_str_support : 1;
    unsigned char bsta_nstr_support : 1;
    unsigned char bsta_emlrs_support : 1;
    unsigned char bsta_emlmr_support : 1;
    unsigned char reserved5 : 4;
    em_radio_wifi7_freq_records_t ap_str;
    em_radio_wifi7_freq_records_t ap_nstr;
    em_radio_wifi7_freq_records_t ap_emlsr;
    em_radio_wifi7_freq_records_t ap_emlmr;
    em_radio_wifi7_freq_records_t bsta_str;
    em_radio_wifi7_freq_records_t bsta_nstr;
    em_radio_wifi7_freq_records_t bsta_emlsr;
    em_radio_wifi7_freq_records_t bsta_emlmr;
} __attribute__((__packed__)) em_radio_wifi7_radio_t;

typedef struct {
    em_radio_wifi7_cap_data_t cap_data;
    unsigned char radios_num;
    em_radio_wifi7_radio_t radios[EM_MAX_RADIO_PER_AGENT];
} __attribute__((__packed__)) em_wifi7_agent_cap_t;

typedef struct {
    mac_address_t bssid;
    unsigned char op_info_valid : 1;
    unsigned char disabled_subchannel_valid : 1;
    unsigned char default_pe_duration : 1;
    unsigned char group_addr_bu_ind_limit : 1;
    unsigned char group_addr_bu_ind_exp : 2;
    unsigned char reserved1 : 2;
    unsigned char eht_msc_nss_set[4];
    unsigned char control;
    unsigned char ccfs0;
    unsigned char ccfs1;
    unsigned char disabled_subchannel_bitmap[2];
    unsigned char reserved2[16];
} __attribute__((__packed__)) em_eht_operations_bss_t;

typedef struct {
    mac_address_t ruid;
    unsigned char bss_num;
    em_eht_operations_bss_t bss[EM_MAX_BSS_PER_RADIO];
    unsigned char reserved[25];
} __attribute__((__packed__)) em_eht_operations_radio_t;

typedef struct {
    unsigned char reserved[32];
    unsigned char radios_num;
    em_eht_operations_radio_t radios[EM_MAX_RADIO_PER_AGENT];
} __attribute__((__packed__)) em_eht_operations_t;

typedef struct {
    unsigned char *avail_spectrum_inquiry_req_obj;
} __attribute__((__packed__)) em_avail_spectrum_inquiry_req_t;

typedef struct {
    unsigned char *avail_spectrum_inquiry_rsp_obj;
} __attribute__((__packed__)) em_avail_spectrum_inquiry_rsp_t;

typedef struct {
    mac_address_t  ruid;
    unsigned char  boot_only : 1;
    unsigned char  scan_impact : 2;
    unsigned int   min_scan_interval;
    unsigned char  op_classes_num;
    em_op_class_t  op_classes[EM_MAX_OP_CLASS];
} __attribute__((__packed__))em_channel_scan_cap_radio_t;

typedef struct {
    unsigned char  radio_num;
    em_channel_scan_cap_radio_t  radios[EM_MAX_RADIO_PER_AGENT];
} __attribute__((__packed__))em_channel_scan_cap_t;

typedef struct {
    unsigned char   cac_method;
    unsigned int    cac_duration;
    unsigned char   op_classes_num;
    em_op_class_t   op_classes[EM_MAX_OP_CLASS];
} __attribute__((__packed__)) em_cac_cap_method_t;

typedef struct {
    mac_address_t   ruid;
    unsigned char   cac_methods_num;
    em_cac_cap_method_t  cac_methods[EM_MAX_CAC_METHODS];
} __attribute__((__packed__))em_cac_cap_radio_t;

typedef struct {
    unsigned short   country_code;
    unsigned char    radios_num;
    em_cac_cap_radio_t  radios[EM_MAX_RADIO_PER_AGENT];
}  __attribute__((__packed__))em_cac_cap_t;

typedef struct {
    unsigned int  metric_cltn_interval;
} __attribute__((__packed__))em_metric_cltn_interval_t;

typedef struct {
    unsigned char   num_sta;
    mac_address_t   sta_mac[EM_MAX_STA_PER_STEER_POLICY];
} __attribute__((__packed__))em_steering_policy_sta_t;

typedef struct {
    mac_address_t   ruid;
    unsigned char   steering_policy;
    unsigned char   channel_util_thresh;
    unsigned char   rssi_steering_thresh;
} __attribute__((__packed__))em_steering_policy_radio_t;

typedef struct {
    em_steering_policy_sta_t local_steer_policy;
    em_steering_policy_sta_t btm_steer_policy;
    unsigned char radio_num;
    em_steering_policy_radio_t radio_steer_policy[EM_MAX_RADIO_PER_AGENT];
} __attribute__((__packed__))em_steering_policy_t;

typedef struct {
    mac_address_t   ruid;
    unsigned char   rcpi_thres;
    unsigned char   rcpi_hysteresis;
    unsigned char   util_thres;
    unsigned char   sta_policy;
} __attribute__((__packed__)) em_metric_rprt_policy_radio_t;

typedef struct {
    unsigned char   interval;
    unsigned char   radios_num;
    em_metric_rprt_policy_radio_t radios[EM_MAX_RADIO_PER_AGENT];
} __attribute__((__packed__)) em_metric_rprt_policy_t;

typedef struct {
   unsigned char rprt_ind_ch_scan : 1;
   unsigned char reserved : 7;
} __attribute__((__packed__)) em_channel_scan_rprt_policy_t;

typedef struct {
    unsigned char  rprt_flag : 1;
    unsigned char  reserved : 7;
    unsigned int   max_rprt_rate;
} __attribute__((__packed__)) em_unsuccessful_assoc_policy_t;

typedef struct {
    mac_address_t  bssid;
    unsigned char  p1_bsta_disallowed : 1;
    unsigned char  p2_bsta_disallowed : 1;
    unsigned char  reserved : 6;
} __attribute__((__packed__)) em_bh_bss_config_t;

typedef struct {
    unsigned char  mscs_disallowed_num;
    em_assoc_sta_mac_addr_t  mac_addr_mscs_disallowed[EM_MAX_STA_PER_AGENT];
    unsigned char  scs_disallowed_num;
    em_assoc_sta_mac_addr_t  mac_addr_scs_disallowed[EM_MAX_STA_PER_AGENT];
    unsigned char  reserved[20];
} __attribute__((__packed__)) em_qos_mgmt_policy_t;

typedef struct {
    em_string_t managed_client_marker;
}__attribute__((__packed__)) em_vendor_policy_t;

typedef struct {
    em_steering_policy_t steering_policy;
    em_metric_rprt_policy_t metrics_policy;
    em_8021q_settings_t def_8021q_settings;
    em_traffic_sep_policy_ssid_t traffic_separation_policy;
    em_channel_scan_rprt_policy_t channel_scan_policy;
    em_unsuccessful_assoc_policy_t unsuccessful_assoc_policy;
    em_bh_bss_config_t bh_bss_cfg_policy;
    em_qos_mgmt_policy_t qos_mgmt_policy;
    em_vendor_policy_t vendor_policy;
} em_policy_cfg_params_t;

typedef struct {
    unsigned char   num;
    unsigned char   service[EM_MAX_SERVICE];
} __attribute__((__packed__)) em_supported_service_t;

typedef struct {
    unsigned char   num;
    unsigned char   service[EM_MAX_SERVICE];
} __attribute__((__packed__)) em_searched_service_t;

typedef struct {
    unsigned char   reserved:5;
    unsigned char   rcpi_steering:1;
    unsigned char   unassociated_client_link_metrics_non_op_channels:1;
    unsigned char   unassociated_client_link_metrics_op_channels:1;
} __attribute__((__packed__)) em_ap_capability_t;


typedef struct {
    mac_address_t   ruid;
    unsigned char   comb_front_back : 1;
    unsigned char   comp_prof1_prof2 : 1;
    unsigned char   mscs : 1;
    unsigned char   scs : 1;
    unsigned char   qos_map : 1;
    unsigned char   dscp_policy : 1;
    unsigned char   reserved : 2;
} __attribute__((__packed__)) em_ap_radio_advanced_cap_t;

typedef enum {
	em_media_type_ieee8023ab = 0x01,
    em_media_type_ieee80211b_24 = 0x0100,
    em_media_type_ieee80211g_24,
    em_media_type_ieee80211a_5,
    em_media_type_ieee80211n_24,
    em_media_type_ieee80211n_5,
    em_media_type_ieee80211ac_5,
    em_media_type_ieee80211ad_60,
    em_media_type_ieee80211af,
} em_media_type_t;

typedef struct {
    uint8_t mac_present : 1;  // Bit 7: Enrollee MAC Address Present
    uint8_t hash_valid : 1;   // Bit 6: Hash Validity
    uint8_t reserved : 6;     // Bits 5-0: Reserved
    uint8_t data[0];           // Flexible array for MAC address (if present) + hash length + hash value
} __attribute__((__packed__)) em_dpp_chirp_value_t;

typedef struct {
    unsigned char   value[EM_CTRL_CAP_SZ];
} __attribute__((__packed__)) em_ctrl_cap_t;

typedef struct {
    unsigned short  id;
    unsigned short len;
    unsigned char val[0];
} __attribute__((__packed__)) data_elem_attr_t;

typedef enum {
    attr_id_ap_channel = 0x1001,
    attr_id_assoc_state,
    attr_id_auth_type,
    attr_id_auth_type_flags,
    attr_id_authenticator,
    attr_id_cfg_methods = 0x1008,
    attr_id_cfg_error,
    attr_id_cnf_url4,
    attr_id_cnf_url6,
    attr_id_conn_type,
    attr_id_conn_type_flags,
    attr_id_cred,
    attr_id_encryption_type,
    attr_id_encryption_type_flags,
    attr_id_device_name = 0x1011,
    attr_id_device_password_id,
    attr_id_e_hash1 = 0x1014,
    attr_id_e_hash2,
    attr_id_e_snonce1,
    attr_id_e_snonce2,
    attr_id_encrypted_settings,
    attr_id_enrollee_nonce = 0x101a,
    attr_id_feature_id,
    attr_id_identity,
    attr_id_identity_proof,
    attr_id_key_wrap_authenticator,
    attr_id_key_id,
    attr_id_mac_address,
    attr_id_manufacturer,
    attr_id_msg_type,
    attr_id_model_name,
    attr_id_model_number,
    attr_id_network_index = 0x1026,
    attr_id_network_key,
    attr_id_network_key_index,
    attr_id_new_device_name,
    attr_id_new_password = 0x102a,
    attr_id_oob_device_password = 0x102c,
    attr_id_os_version,
    attr_id_power_level,
    attr_id_psk_current,
    attr_id_psk_max,
    attr_id_public_key = 0x1032,
    attr_id_radio_enabled,
    attr_id_reboot,
    attr_id_registrar_current,
    attr_id_registrar_established,
    attr_id_registrar_list,
    attr_id_registrar_max,
    attr_id_registrar_nonce,
    attr_id_request_type,
    attr_id_response_type,
    attr_id_rf_bands,
    attr_id_r_hash1,
    attr_id_r_hash2,
    attr_id_r_snonce1,
    attr_id_r_snonce2,
    attr_id_selected_registrar,
    attr_id_serial_num,
    attr_id_wifi_wsc_state = 0x1044,
    attr_id_ssid,
    attr_id_totalPnetworks,
    attr_id_uuid_e, 
    attr_id_uuid_r, 
    attr_id_version,
    attr_id_primary_device_type = 0x1054,
	attr_id_haul_type,
	attr_id_no_of_haul_type,
} data_elem_attr_id_t;

typedef enum {
    em_state_agent_unconfigured,
    em_state_agent_autoconfig_rsp_pending,
    em_state_agent_wsc_m2_pending,
    em_state_agent_owconfig_pending,
    em_state_agent_onewifi_bssconfig_ind,
	em_state_agent_autoconfig_renew_pending,
    em_state_agent_topo_synchronized,
	em_state_agent_channel_pref_query,
	em_state_agent_channel_selection_pending,
	em_state_agent_channel_select_configuration_pending,
    em_state_agent_channel_report_pending,
	em_state_agent_channel_scan_result_pending,
    em_state_agent_configured,
	
	// Transient agent stats
    em_state_agent_topology_notify,
    em_state_agent_ap_cap_report,
    em_state_agent_client_cap_report,
    em_state_agent_sta_link_metrics_pending,
    em_state_agent_steer_btm_res_pending,
    em_state_agent_beacon_report_pending,
    em_state_agent_ap_metrics_pending,

    em_state_ctrl_unconfigured = 0x100,
    em_state_ctrl_wsc_m1_pending,
    em_state_ctrl_wsc_m2_sent,
    em_state_ctrl_topo_sync_pending,
    em_state_ctrl_topo_synchronized,
    em_state_ctrl_channel_query_pending,
	em_state_ctrl_channel_pref_report_pending,
    em_state_ctrl_channel_queried,
	em_state_ctrl_channel_select_pending,
    em_state_ctrl_channel_selected,
    em_state_ctrl_channel_cnf_pending,
    em_state_ctrl_channel_report_pending,
	em_state_ctrl_channel_scan_pending,
    em_state_ctrl_configured,
    em_state_ctrl_misconfigured,
    em_state_ctrl_sta_cap_pending,
    em_state_ctrl_sta_cap_confirmed,
    em_state_ctrl_sta_link_metrics_pending,
    em_state_ctrl_sta_steer_pending,
    em_state_ctrl_steer_btm_req_ack_rcvd,
    em_state_ctrl_sta_disassoc_pending,
    em_state_ctrl_set_policy_pending,
    em_state_ctrl_ap_mld_config_pending,
    em_state_ctrl_ap_mld_configured,
    em_state_ctrl_bsta_mld_config_pending,
    em_state_ctrl_ap_mld_req_ack_rcvd,
    em_state_ctrl_avail_spectrum_inquiry_pending,

    em_state_max,
} em_state_t;

typedef enum {
    em_cmd_type_none,
    em_cmd_type_reset,
    em_cmd_type_get_network,
    em_cmd_type_get_device,
    em_cmd_type_remove_device,
    em_cmd_type_get_radio,
    em_cmd_type_set_radio,
    em_cmd_type_get_ssid,
    em_cmd_type_set_ssid,
    em_cmd_type_get_channel,
    em_cmd_type_set_channel,
    em_cmd_type_scan_channel,
    em_cmd_type_scan_result,
    em_cmd_type_get_bss,
    em_cmd_type_get_sta,
    em_cmd_type_steer_sta,
    em_cmd_type_disassoc_sta,
    em_cmd_type_btm_sta,
    em_cmd_type_dev_init,
    em_cmd_type_dev_test,
    em_cmd_type_set_dev_test,
    em_cmd_type_cfg_renew,
    em_cmd_type_vap_config,
    em_cmd_type_sta_list,
    em_cmd_type_start_dpp,
    em_cmd_type_ap_cap_query,
    em_cmd_type_client_cap_query,
    em_cmd_type_topo_sync,
    em_cmd_type_em_config,
    em_cmd_type_onewifi_cb,
    em_cmd_type_sta_assoc,
    em_cmd_type_channel_pref_query,
    em_cmd_type_sta_link_metrics,
    em_cmd_type_op_channel_report,
    em_cmd_type_sta_steer,
    em_cmd_type_btm_report,
    em_cmd_type_sta_disassoc,
    em_cmd_type_get_policy,
    em_cmd_type_set_policy,
    em_cmd_type_avail_spectrum_inquiry,
    em_cmd_type_get_mld_config,
    em_cmd_type_mld_reconfig,
    em_cmd_type_beacon_report,
    em_cmd_type_ap_metrics_report,

    em_cmd_type_max,
} em_cmd_type_t;


typedef struct {
    queue_t *queue;
    pthread_cond_t  cond;
    pthread_mutex_t lock;
    unsigned int    timeout;
} em_queue_t;

typedef enum {
    em_event_type_frame,
    em_event_type_device,
    em_event_type_node,
    em_event_type_bus,
    em_event_type_max
} em_event_type_t;

typedef enum {
	em_haul_type_fronthaul,
	em_haul_type_backhaul,
	em_haul_type_iot,
	em_haul_type_configurator,
	em_haul_type_hotspot,
	em_haul_type_max,
} em_haul_type_t;

typedef struct {
    unsigned int frame_len;
    unsigned char *frame;
} __attribute__((__packed__)) em_frame_info_t;

typedef struct {
	em_short_string_t	platform;
	em_media_type_t	media;
} em_interface_preference_t;

typedef struct {
    em_interface_name_t name;
    mac_address_t   mac;
	em_media_type_t	media;
} __attribute__((__packed__)) em_interface_t;

typedef em_frame_info_t em_frame_event_t;

typedef struct {
    em_long_string_t    id;
    unsigned short    num_of_devices;
    em_long_string_t    timestamp;
    em_interface_t    ctrl_id; // CM MAC
    unsigned char    num_mscs_disallowed_sta;
    em_string_t     mscs_disallowed_sta[EM_MSCS_DISALLOWED_STA];
    unsigned char    num_scs_disallowed_sta;
    em_string_t     scs_disallowed_sta[EM_SCS_DISALLOWED_STA];
    em_interface_t    colocated_agent_id; // Controller and Colocated Agent AL MAC
	em_media_type_t	media;
} em_network_info_t;

typedef struct {
    unsigned short  auth_flags;
    unsigned short  encr_flags;
    unsigned short  conn_flags;
    unsigned short  cfg_methods;
} ieee_1905_security_t;

typedef struct {
	em_long_string_t    net_id;
	mac_address_t	dev_mac;
	em_media_type_t	media;	
} em_device_id_t;

typedef struct {
	em_device_id_t	id;
    em_interface_t	intf;
    em_profile_type_t   profile;
    em_long_string_t    multi_ap_cap;
    unsigned int   coll_interval;
    bool    report_unsuccess_assocs;
    unsigned short  max_reporting_rate;
    unsigned short  ap_metrics_reporting_interval;
    em_long_string_t    manufacturer;
    em_long_string_t    serial_number;
    em_long_string_t    manufacturer_model;
    em_string_t             software_ver;
    em_string_t             exec_env;
    em_string_t             dscp_map;
    unsigned char   max_pri_rules;
    unsigned char   max_vids;
    em_tiny_string_t        country_code;
    bool    prioritization_sup;
    bool    report_ind_scans;
    bool    traffic_sep_allowed;
    bool    svc_prio_allowed;
    bool    dfs_enable;
    unsigned short  max_unsuccessful_assoc_report_rate;
    bool    sta_steer_state;
    bool    coord_cac_allowed;
    em_string_t    ctrl_operation_mode;
    em_interface_t   backhaul_mac;
    unsigned char    num_backhaul_down_mac;
    em_string_t      backhaul_down_mac[EM_BACKHAUL_DOWNMAC_ADDR];
    wifi_ieee80211Variant_t  backhaul_media_type;
    unsigned int    backhaul_phyrate;
    em_interface_t   backhaul_alid;
    bool    traffic_sep_cap;
    bool    easy_conn_cap;
    unsigned char test_cap;
    unsigned char apmld_maxlinks;
    em_string_t   tidlink_map;
    unsigned char assoc_sta_reporting_int;
    unsigned char max_nummlds;
    unsigned char bstamld_maxlinks;

    em_small_string_t    primary_device_type;
    em_small_string_t    secondary_device_type;
    ieee_1905_security_t    sec_1905;
} em_device_info_t;

typedef struct {
    unsigned char  onboarding_proto;
    unsigned char  integrity_algo;
    unsigned char  encryption_algo;
} __attribute__((__packed__)) em_ieee_1905_security_cap_t;

typedef struct {
    mac_address_t   id;
    em_ieee_1905_security_cap_t sec_cap;
} em_ieee_1905_security_info_t;

typedef struct {
    em_long_string_t    id; // ssid@mac_address
    ssid_t  ssid;
    unsigned short vid;
} em_ssid_2_vid_map_info_t;

typedef struct {
    em_long_string_t    id;
    ssid_t  ssid;
    em_long_string_t    pass_phrase;
    unsigned char   num_bands;
    em_short_string_t    band[EM_MAX_BANDS];
    bool    enable;
    unsigned char   num_akms;
    em_short_string_t akm[EM_MAX_AKMS];
    em_string_t suite_select;
    bool    advertisement;
    em_string_t mfp;
    mac_address_t   mobility_domain;
    unsigned char   num_hauls;
    em_haul_type_t haul_type[EM_MAX_HAUL_TYPES];   
} em_network_ssid_info_t;

typedef enum {
    em_op_class_type_none,
    em_op_class_type_current,
    em_op_class_type_capability,
    em_op_class_type_cac_available,
	em_op_class_type_cac_non_occ,
	em_op_class_type_cac_active,
    em_op_class_type_preference,
    em_op_class_type_anticipated,
    em_op_class_type_scan_param,
} em_op_class_type_t;

typedef struct {
    mac_address_t  ruid;
    em_op_class_type_t  type;
    unsigned int 	op_class;
} em_op_class_id_t;

typedef struct {
    em_op_class_id_t    id;
    unsigned int op_class;
    unsigned int channel;
    int tx_power;
    int max_tx_power;
    unsigned int    num_channels;
    unsigned int    channels[EM_MAX_CHANNELS_IN_LIST];
    unsigned short	mins_since_cac_comp;
	unsigned short	sec_remain_non_occ_dur;
	unsigned int	countdown_cac_comp;
} em_op_class_info_t;

typedef struct {
	mac_address_t	ruid;
	unsigned char op_class;
    unsigned char channel;
    unsigned char status;
    unsigned char detected_pairs_num;
	em_cac_comp_rprt_pair_t	detected_pairs[EM_MAX_CAC_METHODS];
} em_cac_comp_info_t;

typedef struct {
    mac_address_t   id;
    mac_address_t   bssid;
    mac_address_t radiomac;
    bool associated;
    em_string_t sta_client_type;
    em_long_string_t    timestamp;
    unsigned int    last_ul_rate;
    unsigned int    last_dl_rate;
    unsigned int    est_ul_rate;
    unsigned int    est_dl_rate;
    unsigned int    last_conn_time;
    unsigned int    retrans_count;
    signed int      signal_strength;
    unsigned char   rcpi;
    unsigned int    util_tx;
    unsigned int    util_rx;
    unsigned int    pkts_tx;
    unsigned int    pkts_rx;
    unsigned int    bytes_tx;
    unsigned int    bytes_rx;
    unsigned int    errors_tx;
    unsigned int    errors_rx;
    unsigned int 	frame_body_len;
    unsigned char	frame_body[EM_MAX_FRAME_BODY_LEN];
    unsigned int    num_vendor_infos;
    bool            multi_band_cap;
    unsigned int    num_beacon_meas_report;
    unsigned int    beacon_report_len;
    unsigned char   beacon_report_elem[EM_MAX_BEACON_MEASUREMENT_LEN];

    em_long_string_t    cap;
    em_long_string_t    ht_cap;
    em_long_string_t    vht_cap;
    em_long_string_t    he_cap;
    em_long_string_t    wifi6_cap;
    em_long_string_t    wifi7_cap;
    em_long_string_t    cellular_data_pref;
    em_long_string_t    listen_interval;
    em_long_string_t    ssid;
    em_long_string_t    supp_rates;
    em_long_string_t    power_cap;
    em_long_string_t    supp_channels;
    em_long_string_t    rsn_info;
    em_long_string_t    ext_supp_rates;
    em_long_string_t    supp_op_classes;
    em_long_string_t    ext_cap;
    em_long_string_t    rm_cap;
    em_long_string_t    vendor_info[MAX_VENDOR_INFO];

    wifi_BeaconReport_t beacon_reports[EM_MAX_BEACON_REPORTS_PER_SCAN];
} em_sta_info_t;

typedef enum {
    em_target_sta_map_assoc,
    em_target_sta_map_disassoc,
    em_target_sta_map_consolidated,
} em_target_sta_map_t;

typedef struct {
	em_long_string_t	net_id;
	mac_address_t	dev_mac;
    mac_address_t  ruid;
    mac_address_t  bssid;
	em_haul_type_t	haul_type;
} em_bss_id_t;

typedef struct {
	em_bss_id_t	id;
	em_interface_t	bssid;
	em_interface_t	ruid;
    ssid_t  ssid;
    bool    enabled;
    unsigned int last_change;
    em_long_string_t     timestamp;
    unsigned int unicast_bytes_sent;
    unsigned int    unicast_bytes_rcvd;
    unsigned int    numberofsta;
    em_string_t     est_svc_params_be;
    em_string_t     est_svc_params_bk;
    em_string_t     est_svc_params_vi;
    em_string_t     est_svc_params_vo;
    unsigned int    byte_counter_units;
    unsigned char   num_fronthaul_akms;
    em_short_string_t     fronthaul_akm[EM_MAX_AKMS];
    unsigned char   num_backhaul_akms;
    em_short_string_t     backhaul_akm[EM_MAX_AKMS];
    bool    profile_1b_sta_allowed;
    bool    profile_2b_sta_allowed;
    unsigned int    assoc_allowed_status;
    bool    backhaul_use;
    bool    fronthaul_use;
    bool    r1_disallowed;
    bool    r2_disallowed;
    bool    multi_bssid;
    bool    transmitted_bssid;
    em_eht_operations_bss_t eht_ops;
    em_short_string_t mesh_sta_passphrase;

    // Extra vendor information elements for the BSS
    // @note Don't manually allocate, use the helper functions to add/remove elements 
    unsigned char vendor_elements[WIFI_AP_MAX_VENDOR_IE_LEN];
    size_t vendor_elements_len;
} em_bss_info_t;

typedef struct {
    bool  mac_addr_valid;
    bool  link_id_valid;
    em_interface_t  ruid;
    mac_address_t  mac_addr;
    unsigned char  link_id;
} em_affiliated_ap_info_t;

typedef struct {
    bool  mac_addr_valid;
    ssid_t  ssid;
    mac_address_t  mac_addr;
    bool  str;
    bool  nstr;
    bool  emlsr;
    bool  emlmr;
    unsigned char  num_affiliated_ap;
    em_affiliated_ap_info_t  affiliated_ap[EM_MAX_AP_MLD];
} em_ap_mld_info_t;

typedef struct {
    bool  mac_addr_valid;
    em_interface_t  ruid;
    mac_address_t  mac_addr;
} em_affiliated_bsta_info_t;

typedef struct {
    bool  mac_addr_valid;
    bool  ap_mld_mac_addr_valid;
    mac_address_t  mac_addr;
    mac_address_t  ap_mld_mac_addr;
    bool  str;
    bool  nstr;
    bool  emlsr;
    bool  emlmr;
    unsigned char  num_affiliated_bsta;
    em_affiliated_bsta_info_t  affiliated_bsta[EM_MAX_AP_MLD];
} em_bsta_mld_info_t;

typedef struct {
    mac_address_t  bssid;
    mac_address_t  mac_addr;
} em_affiliated_sta_info_t;

typedef struct {
    mac_address_t  mac_addr;
    mac_address_t  ap_mld_mac_addr;
    bool  str;
    bool  nstr;
    bool  emlsr;
    bool  emlmr;
    unsigned char  num_affiliated_sta;
    em_affiliated_sta_info_t  affiliated_sta[EM_MAX_AP_MLD];
} em_assoc_sta_mld_info_t;

typedef struct {
    bool  add_remove;
    mac_address_t  sta_mld_mac_addr;
    bool  direction;
    bool  default_link_map;
    bool  map_switch_time_present;
    bool  expected_dur_present;
    bool  link_map_size;
    unsigned char  link_map_presence_ind;
    unsigned char  expected_dur[3];
    unsigned char tid_to_link_map;
} em_tid_to_link_map_info_t;

typedef struct {
    bool  is_bsta_config;
    mac_address_t  mld_mac_addr;
    bool  tid_to_link_map_neg;
    unsigned char  num_mapping;
    em_tid_to_link_map_info_t  tid_to_link_mapping[EM_MAX_AP_MLD];
} em_tid_to_link_info_t;

typedef struct {
	em_long_string_t	net_id;
	mac_address_t	dev_mac;
	mac_address_t	ruid;
} em_radio_id_t;

typedef struct {
    em_radio_id_t  id;
	em_interface_t intf;
    bool    enabled;
    em_freq_band_t band;
    em_media_spec_data_t	media_data;
    unsigned  int   number_of_bss;
    unsigned  int   number_of_unassoc_sta;
    int     noise;
    unsigned short utilization;
    bool    traffic_sep_combined_fronthaul;
    bool    traffic_sep_combined_backhaul;
    unsigned int steering_policy;
    unsigned int channel_util_threshold;
    unsigned int rcpi_steering_threshold;
    unsigned int sta_reporting_rcpi_threshold;
    unsigned int sta_reporting_hysteresis_margin_override;
    unsigned int channel_utilization_reporting_threshold;
    bool    associated_sta_traffic_stats_inclusion_policy;
    bool    associated_sta_link_mterics_inclusion_policy;
    bool    unassociated_sta_link_mterics_opclass_inclusion_policy;
    bool    unassociated_sta_link_mterics_nonopclass_inclusion_policy;
    bool    support_rcpi_steering;
    em_long_string_t    chip_vendor;
    bool    ap_metrics_wifi6;
    em_device_inventory_t inventory_info;
    int     transmit_power_limit;
    unsigned char partial_bss_color;
    unsigned char bss_color;
    bool hesiga_spatial_reuse_value15_allowed;
    bool srg_information_valid;
    bool non_srg_offset_valid;
    bool psr_disallowed;
    unsigned char non_srg_obsspd_max_offset;
    unsigned char srg_obsspd_min_offset;
    unsigned char srg_obsspd_max_offset;
    unsigned char srg_bss_color_bitmap[8];
    unsigned char srg_partial_bssid_bitmap[8];
    unsigned char neigh_bss_color_in_use_bitmap[8];
} em_radio_info_t;

typedef struct {
    em_interface_t  ruid;
    em_ap_ht_cap_t  ht_cap;
    em_ap_vht_cap_t vht_cap;
    em_ap_he_cap_t  he_cap;
    em_long_string_t    eht_cap;
    em_radio_wifi6_cap_data_t wifi6_cap;
    em_wifi7_agent_cap_t wifi7_cap;
    em_eht_operations_t eht_ops;
    em_radio_info_t ch_scan;
    em_ap_radio_advanced_cap_t radio_ad_cap;
    em_profile_2_ap_cap_t   prof_2_ap_cap;
    em_cac_cap_radio_t cac_cap;
    em_metric_cltn_interval_t metric_interval;
    unsigned int        num_op_classes;
} em_radio_cap_info_t;

typedef struct {
	bssid_t	bssid;
	unsigned char	desc;
    unsigned char   reserved;
    unsigned char   ssid_len;
	char ssid[0];	
} __attribute__((__packed__)) em_bss_rprt_t;

 typedef struct {
    mac_address_t ruid;
    unsigned char num_bss;
	em_bss_rprt_t	bss_rprt[0];
} __attribute__((__packed__)) em_radio_rprt_t;

typedef struct {
    unsigned char num_radios;
    em_radio_rprt_t radio_rprt[0];
} __attribute__((__packed__)) em_bss_config_rprt_t;

typedef struct {
    unsigned char ssid_len;
    char ssid[0];
} __attribute__((__packed__)) em_ap_mld_ssids_t;

typedef struct {
    unsigned char affiliated_mac_addr_valid : 1;
    unsigned char link_id_valid : 1;
    unsigned char reseverd1 : 6;
    mac_address_t ruid;
    mac_addr_t affiliated_mac_addr;
    unsigned char link_id;
    unsigned char reserved2[18];
} __attribute__((__packed__)) em_affiliated_ap_mld_t;

typedef struct {
    unsigned char ap_mld_mac_addr_valid : 1;
    unsigned char reserved1 : 7;
    em_ap_mld_ssids_t ssids[0];
    mac_addr_t ap_mld_mac_addr;
    unsigned char str : 1;
    unsigned char nstr : 1;
    unsigned char emlsr : 1;
    unsigned char emlmr : 1;
    unsigned char reseverd2 : 4;
    unsigned char reserved3[20];
    unsigned char num_affiliated_ap;
    em_affiliated_ap_mld_t affiliated_ap_mld[0];
} __attribute__((__packed__)) em_ap_mld_t;

typedef struct {
    unsigned char num_ap_mld;
    em_ap_mld_t ap_mld[0];
} __attribute__((__packed__)) em_ap_mld_config_t;

typedef struct {
    unsigned char affiliated_bsta_mac_addr_valid : 1;
    unsigned char reseverd1 : 7;
    mac_address_t ruid;
    mac_addr_t affiliated_bsta_mac_addr;
    unsigned char reserved2[19];
} __attribute__((__packed__)) em_affiliated_bsta_mld_t;

typedef struct {
    unsigned char bsta_mld_mac_addr_valid : 1;
    unsigned char ap_mld_mac_addr_valid : 1;
    unsigned char reserved1 : 6;
    mac_addr_t bsta_mld_mac_addr;
    mac_addr_t ap_mld_mac_addr;
    unsigned char str : 1;
    unsigned char nstr : 1;
    unsigned char emlsr : 1;
    unsigned char emlmr : 1;
    unsigned char reseverd2 : 4;
    unsigned char reserved3[17];
    unsigned char num_affiliated_bsta;
    em_affiliated_bsta_mld_t affiliated_bsta_mld[0];
} __attribute__((__packed__)) em_bsta_mld_t;

typedef struct {
    unsigned char num_bsta_mld;
    em_bsta_mld_t bsta_mld[0];
} __attribute__((__packed__)) em_bsta_mld_config_t;

typedef struct {
    bssid_t bssid;
    mac_addr_t affiliated_sta_mac_addr;
    unsigned char reserved1[19];
} __attribute__((__packed__)) em_affiliated_sta_mld_t;

typedef struct {
    mac_addr_t sta_mld_mac_addr;
    mac_addr_t ap_mld_mac_addr;
    unsigned char str : 1;
    unsigned char nstr : 1;
    unsigned char emlsr : 1;
    unsigned char emlmr : 1;
    unsigned char reseverd1 : 4;
    unsigned char reserved2[18];
    unsigned char num_affiliated_sta;
    em_affiliated_sta_mld_t affiliated_sta_mld[0];
} __attribute__((__packed__)) em_assoc_sta_mld_t;

typedef struct {
    unsigned char num_assoc_sta_mld;
    em_assoc_sta_mld_t assoc_sta_mld[0];
} __attribute__((__packed__)) em_assoc_sta_mld_config_report_t;

typedef struct {
    unsigned char add_remove : 1;
    unsigned char reserved4 : 7;
    mac_addr_t sta_mld_mac_addr;
    unsigned char direction : 2;
    unsigned char default_link_mapping : 1;
    unsigned char map_switch_time_present : 1;
    unsigned char exp_dur_present : 1;
    unsigned char link_map_size : 1;
    unsigned char reserved5 : 2;
    unsigned char link_map_presence_ind;
    unsigned char expected_duration[3];
    unsigned char tid_to_link_map[0];
    unsigned char reserved6[7];
} __attribute__((__packed__)) em_tid_to_link_mapping_t;

typedef struct {
    unsigned char is_bsta_config : 1;
    unsigned char reserved1 : 7;
    mac_addr_t mld_mac_addr;
    unsigned char tid_to_link_map_negotiation : 1;
    unsigned char reserved2 : 7;
    unsigned char reserved3[22];
    unsigned char num_mapping;
    em_tid_to_link_mapping_t tid_to_link_mapping[0];
} __attribute__((__packed__)) em_tid_to_link_map_policy_t;

typedef struct {
    em_nonce_t  e_nonce;  
    em_nonce_t  r_nonce;  
    uuid_t  e_uuid;
    uuid_t  r_uuid;
    mac_address_t   e_mac;
    mac_address_t   r_mac;
    unsigned char   e_priv[DH_KEY_SZ];
    unsigned int    e_priv_len;
    unsigned char   e_pub[DH_KEY_SZ];
    unsigned int    e_pub_len;
    unsigned char   r_priv[DH_KEY_SZ];
    unsigned int    r_priv_len;
    unsigned char   r_pub[DH_KEY_SZ];
    unsigned int    r_pub_len;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *kctx;
    DH *dh;
} em_crypto_info_t;


typedef enum {
    em_bus_event_type_none,
    em_bus_event_type_chirp,
    em_bus_event_type_reset,
    em_bus_event_type_dev_test,
    em_bus_event_type_set_dev_test,
    em_bus_event_type_get_network,
    em_bus_event_type_get_device,
    em_bus_event_type_remove_device,
    em_bus_event_type_get_radio,
    em_bus_event_type_get_ssid,
    em_bus_event_type_set_ssid,
    em_bus_event_type_get_channel,
    em_bus_event_type_set_channel,
    em_bus_event_type_scan_channel,
    em_bus_event_type_scan_result,
    em_bus_event_type_get_bss,
    em_bus_event_type_get_sta,
    em_bus_event_type_steer_sta,
    em_bus_event_type_disassoc_sta,
    em_bus_event_type_get_policy,
    em_bus_event_type_set_policy,
    em_bus_event_type_btm_sta,
    em_bus_event_type_start_dpp,
    em_bus_event_type_dev_init,
    em_bus_event_type_cfg_renew,
    em_bus_event_type_radio_config,
    em_bus_event_type_vap_config,
    em_bus_event_type_sta_list,
    em_bus_event_type_ap_cap_query,
    em_bus_event_type_client_cap_query,
    em_bus_event_type_listener_stop,
    em_bus_event_type_dm_commit,
    em_bus_event_type_m2_tx,
    em_bus_event_type_topo_sync,
    em_bus_event_type_onewifi_private_cb,
    em_bus_event_type_onewifi_mesh_sta_cb,
    em_bus_event_type_onewifi_radio_cb,
    em_bus_event_type_m2ctrl_configuration,
    em_bus_event_type_sta_assoc,
    em_bus_event_type_channel_pref_query,
    em_bus_event_type_channel_sel_req,
    em_bus_event_type_sta_link_metrics,
    em_bus_event_type_set_radio,
    em_bus_event_type_bss_tm_req,
    em_bus_event_type_btm_response,
	em_bus_event_type_channel_scan_params,
    em_bus_event_type_get_mld_config,
    em_bus_event_type_mld_reconfig,
    em_bus_event_type_beacon_report,
    em_bus_event_type_recv_wfa_action_frame,
    em_bus_event_type_recv_gas_frame,
    em_bus_event_type_get_sta_client_type,
    em_bus_event_type_assoc_status,
    em_bus_event_type_ap_metrics_report,
    em_bus_event_type_bss_info,

    em_bus_event_type_max
} em_bus_event_type_t;

typedef struct {
    em_subdoc_name_space_t  name;
    em_subdoc_data_buff_t   buff;
} __attribute__((__packed__)) em_subdoc_info_t;

typedef struct {
    mac_address_t	mac;
    em_long_string_t	net_id;
    int sz;
} __attribute__((__packed__)) em_commit_info_t;

typedef enum {
    dm_orch_type_none,
    dm_orch_type_net_insert,
    dm_orch_type_net_update,
    dm_orch_type_net_delete,
    dm_orch_type_al_insert,
    dm_orch_type_al_update,
    dm_orch_type_al_delete,
    dm_orch_type_em_insert,
    dm_orch_type_em_update,
    dm_orch_type_em_delete,
    dm_orch_type_em_reset,
    dm_orch_type_em_test,
    dm_orch_type_bss_insert,
    dm_orch_type_bss_update,
    dm_orch_type_bss_delete,
    dm_orch_type_ssid_insert,
    dm_orch_type_ssid_update,
    dm_orch_type_ssid_delete,
    dm_orch_type_sta_insert,
    dm_orch_type_sta_update,
    dm_orch_type_sta_aggregate,
    dm_orch_type_sta_delete,
    dm_orch_type_sec_insert,
    dm_orch_type_sec_update,
    dm_orch_type_sec_delete,
    dm_orch_type_cap_insert,
    dm_orch_type_cap_update,
    dm_orch_type_cap_delete,
    dm_orch_type_op_class_insert,
    dm_orch_type_op_class_update,
    dm_orch_type_op_class_delete,
    dm_orch_type_ssid_vid_insert,
    dm_orch_type_ssid_vid_update,
    dm_orch_type_ssid_vid_delete,
    dm_orch_type_dpp_insert,
    dm_orch_type_dpp_update,
    dm_orch_type_dpp_delete,
    dm_orch_type_db_reset,
    dm_orch_type_db_cfg,
    dm_orch_type_db_insert,
    dm_orch_type_db_update,
    dm_orch_type_db_delete,
    dm_orch_type_dm_delete,
    dm_orch_type_dm_delete_all,
    dm_orch_type_tx_cfg_renew,
    dm_orch_type_owconfig_req,
    dm_orch_type_owconfig_cnf,
    dm_orch_type_ctrl_notify,
    dm_orch_type_ap_cap_report,
    dm_orch_type_client_cap_report,
    dm_orch_type_1905_security_update,
    dm_orch_type_topology_response,
    dm_orch_type_net_ssid_update,
    dm_orch_type_topo_sync,
    dm_orch_type_topo_update,
    dm_orch_type_channel_pref,
    dm_orch_type_channel_sel,
    dm_orch_type_channel_cnf,
    dm_orch_type_channel_sel_resp,
    dm_orch_type_channel_scan_req,
    dm_orch_type_channel_scan_res,
    dm_orch_type_sta_cap,
    dm_orch_type_sta_link_metrics,
    dm_orch_type_op_channel_report,
    dm_orch_type_sta_steer,
    dm_orch_type_sta_steer_btm_report,
    dm_orch_type_sta_disassoc,
    dm_orch_type_policy_cfg,
    dm_orch_type_mld_reconfig,
    dm_orch_type_beacon_report
} dm_orch_type_t;

typedef struct {
	dm_orch_type_t	op;
	bool	submit;
} em_orch_desc_t;

typedef enum {
	db_cfg_type_none,
	db_cfg_type_network_list_update = (1 << 0),
	db_cfg_type_network_list_delete = (1 << 1),
	db_cfg_type_device_list_update = (1 << 2),
	db_cfg_type_device_list_delete = (1 << 3),
	db_cfg_type_radio_list_update = (1 << 4),
	db_cfg_type_radio_list_delete = (1 << 5),
	db_cfg_type_op_class_list_update = (1 << 6),
	db_cfg_type_op_class_list_delete = (1 << 7),
	db_cfg_type_bss_list_update = (1 << 8),
	db_cfg_type_bss_list_delete = (1 << 9),
	db_cfg_type_sta_list_update = (1 << 10),
	db_cfg_type_sta_list_delete = (1 << 11),
	db_cfg_type_network_ssid_list_update = (1 << 12),
	db_cfg_type_network_ssid_list_delete = (1 << 13),
	db_cfg_type_radio_cap_list_update = (1 << 14),
	db_cfg_type_radio_cap_list_delete = (1 << 15),
	db_cfg_type_1905_security_list_update = (1 << 16),
	db_cfg_type_1905_security_list_delete = (1 << 17),
	db_cfg_type_sta_metrics_update = (1 << 18),
	db_cfg_type_policy_list_update = (1 << 19),
	db_cfg_type_policy_list_delete = (1 << 20),
	db_cfg_type_scan_result_list_update = (1 << 21),
	db_cfg_type_scan_result_list_delete = (1 << 22),
} db_cfg_type_t;

typedef struct {
    unsigned int db_cfg_type;
	em_long_string_t	db_cfg_criteria[EM_MAX_DB_CFG_CRITERIA];
} em_db_cfg_param_t;

typedef struct{
	em_long_string_t ssid[EM_MAX_BSS_PER_RADIO];
	unsigned int authtype[EM_MAX_BSS_PER_RADIO];
	em_long_string_t password[EM_MAX_BSS_PER_RADIO];
	mac_address_t bssid_mac[EM_MAX_BSS_PER_RADIO];
	unsigned int key_wrap_authenticator[EM_MAX_BSS_PER_RADIO];
	bool enable[EM_MAX_BSS_PER_RADIO];
	em_freq_band_t freq;
	unsigned int noofbssconfig;
	em_haul_type_t haultype[EM_MAX_BSS_PER_RADIO];
	mac_address_t radio_mac[EM_MAX_BSS_PER_RADIO];
} m2ctrl_radioconfig;

typedef struct{
	int op_class;
	em_freq_band_t band;
	int channel_spacing;
	int num_channels;
	int channels[EM_MAX_E4_TABLE_CHANNEL];
} em_e4_table_t;

typedef struct{
    unsigned int num;
    em_op_class_info_t op_class_info[EM_MAX_OP_CLASS];
	em_tx_power_limit_t tx_power;
    em_spatial_reuse_req_t spatial_reuse_req;
    em_eht_operations_t eht_ops;
	em_freq_band_t freq_band;
} op_class_channel_sel;

typedef struct {
    mac_address_t   mac;
    unsigned short  msg_id;
} em_bus_event_type_channel_pref_query_params_t;

typedef struct {
    mac_address_t   al;
    mac_address_t   radio;
} em_bus_event_type_m2_tx_params_t;

typedef struct {
    mac_address_t   dev;
    em_client_assoc_event_t   assoc;
} em_bus_event_type_client_assoc_params_t;

typedef struct {
    mac_address_t   radio;
    mac_address_t   ctrl_src;
} em_bus_event_type_cfg_renew_params_t;

typedef struct {
    unsigned int num_args;
    em_long_string_t args[EM_CLI_MAX_ARGS];
    em_long_string_t fixed_args;
} em_cmd_args_t;

typedef enum {
    em_steering_opportunity_none,
} em_steering_opportunity_t;

typedef enum {
    em_steering_mandate_none,
} em_steering_mandate_t;

typedef struct {
    em_steering_opportunity_t	opportunity;
    em_steering_mandate_t	mandate;
} em_steer_req_mode_t;

typedef struct {
    mac_address_t	sta_mac;
    bssid_t	source;
    bssid_t	target;
    unsigned int	request_mode;
    bool	disassoc_imminent;
    bool	btm_abridged;
    bool	link_removal_imminent;
    unsigned int	steer_opportunity_win;
    unsigned int    btm_disassociation_timer;
    unsigned int 	target_op_class;
    unsigned int	target_channel;
} em_cmd_steer_params_t;

typedef struct {
    bssid_t	source;
    mac_address_t	sta_mac;
    unsigned char status_code;
    bssid_t	target;
} em_cmd_btm_report_params_t;

typedef struct {
    mac_address_t	sta_mac;
    bssid_t	bssid;
    unsigned int disassoc_time;
    unsigned int reason;
    bool	silent;
} em_disassoc_params_t;

typedef struct {
    unsigned int num;
    em_disassoc_params_t	params[MAX_STA_TO_DISASSOC];
} em_cmd_disassoc_params_t;

typedef struct {
    mac_address_t   ruid;
    bool sta_link_metrics_include;
    bool sta_traffic_stats_include;
    bool wifi6_status_report_include;
} __attribute__((__packed__)) em_cmd_ap_metrics_rprt_params_t;

typedef enum {
    em_network_node_data_type_invalid,
    em_network_node_data_type_false,
    em_network_node_data_type_true,
    em_network_node_data_type_null,
    em_network_node_data_type_number,
    em_network_node_data_type_string,
    em_network_node_data_type_obj,
    em_network_node_data_type_array_obj,
    em_network_node_data_type_array_str,
    em_network_node_data_type_array_num,
    em_network_node_data_type_raw,
} em_network_node_data_type_t;

typedef struct {
    bool collapsed;
    unsigned int orig_node_ctr;
    unsigned int node_ctr;
    unsigned int node_pos;
} em_node_display_info_t;

typedef struct em_network_node {
    em_long_string_t   key;
    em_node_display_info_t	display_info;
    em_network_node_data_type_t type;
    em_long_string_t    value_str;
    unsigned int        value_int;
    unsigned int        num_children;
    struct em_network_node     *child[EM_MAX_DM_CHILDREN];
} em_network_node_t;

typedef em_scan_params_t em_cmd_scan_params_t;
typedef struct {
    union {
        em_cmd_args_t	args;
        em_cmd_steer_params_t	steer_params;
        em_cmd_btm_report_params_t  btm_report_params;
        em_cmd_disassoc_params_t	disassoc_params;
		em_cmd_scan_params_t	scan_params;
        em_cmd_ap_metrics_rprt_params_t ap_metrics_params;
    } u;
	em_network_node_t *net_node;
} em_cmd_params_t;

typedef struct {
    unsigned int arr_index;
    dm_orch_type_t  type;
    em_long_string_t        obj_id;
} em_cmd_ctx_t;

typedef struct {
    em_cmd_type_t   type;
    unsigned int count;
    unsigned int time;
} em_cmd_stats_t;

typedef struct {
    em_bus_event_type_t type;
    em_cmd_params_t params;
	unsigned int data_len;
    union {
        em_subdoc_info_t    subdoc;
        em_commit_info_t	commit;
        em_raw_data_t raw_buff;
    } u;
} __attribute__((__packed__)) em_bus_event_t;

typedef struct {
    em_event_type_t     type;
    union {
        em_frame_event_t    fevt;
        em_bus_event_t      bevt;
    } u;    
} __attribute__((__packed__)) em_event_t;

typedef em_long_string_t db_table_name_t;
typedef em_long_string_t db_column_name_t;

typedef enum {
    db_data_type_char,
    db_data_type_varchar,
    db_data_type_binary,
    db_data_type_varbinary,
    db_data_type_text,
    db_data_type_integer,
    db_data_type_int,
    db_data_type_smallint,
    db_data_type_tinyint,
    db_data_type_mediumint,
    db_data_type_bigint,
    db_data_type_decimal,
    db_data_type_numeric,
    db_data_type_float,
    db_data_type_double,
    db_data_type_bit,
    db_data_type_date,
    db_data_type_datetime,
    db_data_type_timestamp,
} db_data_type_t;

typedef unsigned int db_data_type_args_t;
typedef unsigned char em_advertise_cce_t;
typedef unsigned char em_eapol_frame_payload_t[0];

typedef char db_query_t[2048];
typedef char db_result_t[2048];
typedef char db_fmt_t[8];

typedef enum {
    em_orch_state_none,
    em_orch_state_idle,
    em_orch_state_pending,
    em_orch_state_progress,
    em_orch_state_fini,
    em_orch_state_cancel
} em_orch_state_t;

typedef enum {
    em_commit_target_cmd,
    em_commit_target_al,
    em_commit_target_em,
    em_commit_target_agent,
    em_commit_target_sta_hash_map,
    em_commit_target_radio,
    em_commit_target_bss,
} em_commit_target_type_t;

typedef struct {
    em_commit_target_type_t type;
    unsigned char params[64];
    unsigned int params_size;
} em_commit_target_t;

typedef enum {
    em_cmd_out_status_success,
    em_cmd_out_status_not_ready,
    em_cmd_out_status_invalid_input,
    em_cmd_out_status_timeout,
    em_cmd_out_status_invalid_mac,
    em_cmd_out_status_interface_down,
    em_cmd_out_status_other,
    em_cmd_out_status_prev_cmd_in_progress,
    em_cmd_out_status_no_change,
} em_cmd_out_status_t;

typedef struct {
    char ssid[MAX_WIFI_SSID_LEN];
    char keypass_phrase[MAX_WIFI_PASSWORD_LEN];
}__attribute__((__packed__)) em_vap_info_t;

typedef enum {
    tag_ssid = 0,
    tag_supported_rates = 1,
    tag_power_capability = 33,
    tag_supported_channels = 36,
    tag_ht_capabilities = 45,
    tag_rsn_information = 48,
    tag_extended_supported_rates = 50,
    tag_supported_operating_classes = 59,
    tag_rm_enabled_capability = 70,
    tag_extended_capabilities = 127,
    tag_vht_capability = 191,
    tag_vendor_specific = 221,
} tag_type_t;

typedef struct {
    tag_type_t tag_id;
    unsigned char length;
    unsigned char value[0];
} __attribute__((packed)) ieee80211_tagvalue_t;

typedef enum {
    em_get_sta_list_reason_none,
    em_get_sta_list_reason_steer,
    em_get_sta_list_reason_btm,
    em_get_sta_list_reason_disassoc,
    em_get_sta_list_reason_neighbors,
} em_get_sta_list_reason_t;

typedef enum {
	em_get_radio_list_reason_none,
	em_get_radio_list_reason_radio_summary,
	em_get_radio_list_reason_radio_enable,
	em_get_radio_list_reason_channel_scan,
} em_get_radio_list_reason_t;

typedef enum {
	em_get_channel_list_reason_none,
	em_get_channel_list_reason_set_anticipated,
	em_get_channel_list_reason_scan_params,
} em_get_channel_list_reason_t;

typedef enum {
	em_policy_id_type_steering_local,
	em_policy_id_type_steering_btm,
	em_policy_id_type_steering_param,
	em_policy_id_type_ap_metrics_rep,
	em_policy_id_type_radio_metrics_rep,
	em_policy_id_type_channel_scan,
	em_policy_id_type_backhaul_bss_config,
	em_policy_id_type_unknown,
} em_policy_id_type_t;

typedef struct {
    em_long_string_t    net_id;
	mac_address_t	dev_mac;
	mac_address_t	radio_mac;
	em_policy_id_type_t	type;
} em_policy_id_t;

typedef enum {
	em_steering_policy_type_disallowed,
	em_steering_policy_type_rcpi_mandated,
	em_steering_policy_type_rcpi_allowed,
	em_steering_policy_type_unknown,
} em_steering_policy_type_t;

typedef struct {
	em_policy_id_t	id;
	unsigned int num_sta;
	mac_address_t	sta_mac[EM_MAX_STA_PER_STEER_POLICY];
	em_steering_policy_type_t	policy;
	unsigned short	util_threshold;
	unsigned short	rcpi_threshold;	
	unsigned short	interval;
	unsigned short	rcpi_hysteresis;
	bool	sta_traffic_stats;
	bool	sta_link_metric;
	bool	sta_status;
	em_long_string_t	managed_sta_marker;
	bool	independent_scan_report;
	bool	profile_1_sta_disallowed;
	bool	profile_2_sta_disallowed;
} em_policy_t;

typedef em_network_node_t  *(* em_editor_callback_t)(em_network_node_t *, void *);

typedef enum {
	em_cli_type_none,
	em_cli_type_cmd,
	em_cli_type_go,
} em_cli_type_t;

typedef struct {
    void *user_data; 
	em_editor_callback_t	cb_func;
	em_cli_type_t	cli_type;
} em_cli_params_t;

typedef enum {
	em_dev_test_type_ssid,
	em_dev_test_type_channel,
	em_dev_test_type_max
} em_dev_test_type;

typedef enum {
        em_dev_test_status_inprogess,
        em_dev_test_status_idle,
	em_dev_test_status_complete,
	em_dev_test_status_failed,
        em_dev_test_status_max
} em_dev_test_status;

typedef struct{
	int num_iteration[em_dev_test_type_max];
	em_dev_test_type test_type[em_dev_test_type_max];
	int enabled[em_dev_test_type_max];
	int num_of_iteration_completed[em_dev_test_type_max];
	int test_inprogress[em_dev_test_type_max];
	em_dev_test_status test_status[em_dev_test_type_max];
        em_haul_type_t haul_type;
        em_freq_band_t freq_band;
}em_dev_test_info;

#ifndef SSL_KEY
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define SSL_KEY EC_KEY
#else
#define SSL_KEY EVP_PKEY
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif // EM_BASE_H

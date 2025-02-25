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

#ifndef EM_MSG_H
#define EM_MSG_H
#include "em_base.h"

#define EM_MAX_TLV_MEMBERS 64

class em_tlv_member_t {
public:
    em_tlv_type_t m_type;
    em_tlv_requirement_t m_requirement;
    em_short_string_t m_spec;
    bool m_present;
    int m_tlv_length;
public:
    em_tlv_member_t(em_tlv_type_t type, em_tlv_requirement_t requirement, const char *spec,int tlv_length) {
        m_type = type; 
        m_requirement = requirement; 
        snprintf(m_spec, sizeof(m_spec), "%s", spec);
        m_tlv_length = tlv_length; // for tlv size check
        m_present = false;
    }
    em_tlv_member_t() { }
    ~em_tlv_member_t() { }
};
class em_msg_t {
    em_msg_type_t m_type;
    em_profile_type_t m_profile;
    unsigned int m_num_tlv;
    em_tlv_member_t m_tlv_member[EM_MAX_TLV_MEMBERS];	
    unsigned int m_num_errors;
    em_short_string_t m_errors[EM_MAX_TLV_MEMBERS];
    unsigned char *m_buff;
    unsigned int m_len;
public:

    /**
     * @brief Add a value to the message
     * 
     * @param buff The buffer to add the item to
     * @param len In/Out. The current length of the buffer. Updated with the new length
     * @param element The element to add
     * @param element_len The length of the element
     * @return unsigned char* The new buffer pointer
     */
    static unsigned char* add_buff_element(unsigned char *buff, unsigned int *len, unsigned char *element, unsigned int element_len);

    /**
     * @brief Add a TLV to the message
     * 
     * @param buff The buffer to add the TLV to
     * @param len In/Out. The current length of the buffer. Updated with the new length
     * @param tlv_type The type of the TLV
     * @param value The value of the TLV
     * @param value_len The length of the value
     * @return unsigned char* The new buffer pointer
     */
    static unsigned char* add_tlv(unsigned char *buff, unsigned int *len, em_tlv_type_t tlv_type, unsigned char *value, unsigned int value_len);

    /**
     * @brief Add an EOM TLV to the message
     * 
     * @param buff The buffer to add the TLV to
     * @param len In/Out. The current length of the buffer. Updated with the new length
     * @return unsigned char* The new buffer pointer
     */
    inline static unsigned char* add_eom_tlv(unsigned char *buff, unsigned int *len) {
        return add_tlv(buff, len, em_tlv_type_eom, NULL, 0);
    }

    /**
     * @brief Add a 1905 header to the message
     * 
     * @param buff The buffer to add the header to
     * @param len In/Out. The current length of the buffer. Updated with the new length
     * @param dst The destination MAC address
     * @param src The source MAC address
     * @param msg_type The message type
     * @return unsigned char* The new buffer pointer
     */
    static unsigned char* add_1905_header(unsigned char *buff, unsigned int *len, mac_addr_t dst, mac_addr_t src, em_msg_type_t msg_type);

    unsigned int validate(char *errors[]);
    bool get_radio_id(mac_address_t *mac);
    bool get_bss_id(mac_address_t *mac);
    bool get_profile(em_profile_type_t *profile);
    bool get_freq_band(em_freq_band_t *band);
    bool get_tlv(em_tlv_t *tlv);
    bool get_profile_type(em_profile_type_t *profile);
    bool get_al_mac_address(unsigned char *mac);
    em_tlv_t *get_tlv(em_tlv_type_t type);
    void autoconfig_search();
    void autoconfig_resp();
    void autoconfig_wsc_m1();
    void autoconfig_wsc_m2();
    void topo_disc();
    void topo_notif();
    void topo_query();
    void topo_resp();
    void topo_vendor();
    void link_metric_query();
    void link_metric_resp();
    void autoconfig_renew();
    void ap_cap_query();
    void ap_cap_rprt();
    void policy_config_req();
    void channel_pref_query();
    void channel_pref_rprt();
    void channel_sel_req();
    void channel_sel_rsp();
    void op_channel_rprt();
    void client_cap_query();
    void client_steering_req();
    void client_steering_btm_rprt();
    void client_assoc_ctrl_req();
    void steering_complete();
    void higher_layer_data();
    void bh_steering_req();
    void bh_steering_rsp();
    void client_cap_rprt();
    void ap_metrics_query();
    void ap_metrics_rsp();
    void sta_link_metrics_query();
    void sta_link_metrics_rsp();
    void unassoc_sta_link_metrics_query();
    void unassoc_sta_link_metrics_rsp();
    void beacon_metrics_query();
    void beacon_metrics_rsp();
    void combined_infra_metrics();
    void channel_scan_req();
    void qos_mgmt_notif();
    void anticipated_channel_usage_rprt();
    void anticipated_channel_pref();
    void agent_list();
    void failed_conn();
    void dpp_bootstrap_uri_notif();
    void i1905_encap_eapol();
    void chirp_notif();
    void bss_config_res();
    void bss_config_rsp();
    void bss_config_req();
    void channel_scan_rprt();
    void dpp_cce_ind();
    void i1905_rekey_req();
    void i1905_decrypt_fail();
    void cac_term();
    void client_disassoc_stats();
    void svc_prio_req();
    void err_rsp();
    void assoc_status_notif();
    void tunneled();
    void bh_sta_cap_query();
    void bh_sta_cap_rprt();
    void proxied_encap_dpp();
    void direct_encap_dpp();
    void reconfig_trigger();
    void cac_req();
    void ap_mld_config_req();
    void ap_mld_config_rsp();
    void i1905_ack();
    void set_m1(unsigned char *tlvs, unsigned int len);
    bool get_client_mac_info(mac_address_t *mac);

    em_msg_t(em_msg_type_t type, em_profile_type_t profile, unsigned char *tlvs, unsigned int len);
    em_msg_t(unsigned char *tlvs, unsigned int len);
    em_msg_t() {}
    ~em_msg_t();
};
#endif

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

#pragma once
#include "em_base.h"
#include "em_crypto.h"
#include "em_msg.h"


class em_testValidation_t {

    em_tlv_t *tlv;
    em_msg_type_t  m_type;
    em_profile_type_t m_profile;
    em_enum_type_t profile;
    em_dpp_chirp_value_t    chirp;

public:

    int test_autoconfig_resp_msg(unsigned char *buff,int i,unsigned int len);
    int test_autoconfig_search_msg(unsigned char *buff,int i,unsigned int len);
    int test_autoconfig_wsc_m1(unsigned char *buff,int i ,unsigned int len);
    int test_autoconfig_wsc_m2(unsigned char *buff,int i,unsigned int len);
    int test_topo_disc(unsigned char *buff,int i,unsigned int len);
    int test_topo_notif(unsigned char *buff,int i,unsigned int len);
    int test_topo_query(unsigned char *buff,int i,unsigned int len);
    int test_topo_resp(unsigned char *buff,int i,unsigned int len);
    int test_topo_vendor(unsigned char *buff,int i,unsigned int len);
    int test_link_metric_query(unsigned char *buff,int i,unsigned int len);
    int test_link_metric_resp(unsigned char *buff,int i,unsigned int len);
    int test_autoconfig_renew(unsigned char *buff,int i,unsigned int len);
    int test_ap_cap_query(unsigned char *buff,int i,unsigned int len);
    int test_ap_cap_rprt(unsigned char *buff,int i,unsigned int len);
    int test_policy_config_req(unsigned char *buff,int i,unsigned int len);
    int test_channel_pref_query(unsigned char *buff,int i,unsigned int len);
    int test_channel_pref_rprt(unsigned char *buff,int i,unsigned int len);
    int test_channel_sel_req(unsigned char *buff,int i,unsigned int len);
    int test_channel_sel_rsp(unsigned char *buff,int i,unsigned int len);
    int test_op_channel_rprt(unsigned char *buff,int i,unsigned int len);
    int test_client_cap_query(unsigned char *buff,int i,unsigned int len);
    int test_client_steering_req(unsigned char *buff,int i,unsigned int len);
    int test_client_steering_btm_rprt(unsigned char *buff,int i,unsigned int len);
    int test_client_assoc_ctrl_req(unsigned char *buff,int i,unsigned int len);
    int test_steering_complete(unsigned char *buff,int i,unsigned int len);
    int test_higher_layer_data(unsigned char *buff,int i,unsigned int len);
    int test_bh_steering_req(unsigned char *buff,int i,unsigned int len);
    int test_bh_steering_rsp(unsigned char *buff,int i,unsigned int len);
    int test_client_cap_rprt(unsigned char *buff,int i,unsigned int len);
    int test_ap_metrics_query(unsigned char *buff,int i,unsigned int len);
    int test_ap_metrics_rsp(unsigned char *buff,int i,unsigned int len);
    int test_sta_link_metrics_query(unsigned char *buff,int i,unsigned int len);
    int test_sta_link_metrics_rsp(unsigned char *buff,int i,unsigned int len);
    int test_unassoc_sta_link_metrics_query(unsigned char *buff,int i,unsigned int len);
    int test_unassoc_sta_link_metrics_rsp(unsigned char *buff,int i,unsigned int len);
    int test_beacon_metrics_query(unsigned char *buff,int i,unsigned int len);
    int test_beacon_metrics_rsp(unsigned char *buff,int i,unsigned int len);
    int test_combined_infra_metrics(unsigned char *buff,int i,unsigned int len);
    int test_channel_scan_req(unsigned char *buff,int i,unsigned int len);
    int test_qos_mgmt_notif(unsigned char *buff,int i,unsigned int len);
    int test_anticipated_channel_usage_rprt(unsigned char *buff,int i,unsigned int len);
    int test_anticipated_channel_pref(unsigned char *buff,int i,unsigned int len);
    int test_agent_list(unsigned char *buff,int i,unsigned int len);
    int test_failed_conn(unsigned char *buff,int i,unsigned int len);
    int test_dpp_bootstrap_uri_notif(unsigned char *buff,int i,unsigned int len);
    int test_i1905_encap_eapol(unsigned char *buff,int i,unsigned int len);
    int test_chirp_notif(unsigned char *buff,int i,unsigned int len);
    int test_bss_config_res(unsigned char *buff,int i,unsigned int len);
    int test_bss_config_rsp(unsigned char *buff,int i,unsigned int len);
    int test_bss_config_req(unsigned char *buff,int i,unsigned int len);
    int test_channel_scan_rprt(unsigned char *buff,int i,unsigned int len);
    int test_dpp_cce_ind(unsigned char *buff,int i,unsigned int len);
    int test_i1905_rekey_req(unsigned char *buff,int i,unsigned int len);
    int test_i1905_decrypt_fail(unsigned char *buff,int i,unsigned int len);
    int test_cac_term(unsigned char *buff,int i,unsigned int len);
    int test_client_disassoc_stats(unsigned char *buff,int i,unsigned int len);
    int test_svc_prio_req(unsigned char *buff,int i,unsigned int len);
    int test_err_rsp(unsigned char *buff,int i,unsigned int len);
    int test_assoc_status_notif(unsigned char *buff,int i,unsigned int len);
    int test_tunneled(unsigned char *buff,int i,unsigned int len);
    int test_bh_sta_cap_query(unsigned char *buff,int i,unsigned int len);
    int test_bh_sta_cap_rprt(unsigned char *buff,int i,unsigned int len);
    int test_proxied_encap_dpp(unsigned char *buff,int i,unsigned int len);
    int test_direct_encap_dpp(unsigned char *buff,int i,unsigned int len);
    int test_reconfig_trigger(unsigned char *buff,int i,unsigned int len);
    int test_cac_req(unsigned char *buff,int i,unsigned int len);
    int test_1905_ack(unsigned char *buff,int i,unsigned int len);

    void test_validation(em_msg_type_t type,em_profile_type_t profile,unsigned char *buff,unsigned int sz);

    em_testValidation_t(unsigned char *buff, unsigned int &len);
    em_testValidation_t();
    ~em_testValidation_t();
};

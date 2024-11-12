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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/rand.h>
#include "em.h"
#include "em_capability.h"
#include "em_cmd.h"
#include "em_msg.h"
#include "dm_easy_mesh.h"
#include "em_cmd_exec.h"
#include "em_cmd_client_cap.h"

int em_capability_t::create_ap_cap_report_msg(unsigned char *buff)
{
    unsigned short  msg_type = em_msg_type_ap_cap_rprt;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    short msg_id = get_current_cmd()->get_data_model()->get_msg_id();

    memcpy(tmp, (unsigned char *)get_peer_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //AP Capability TLV 17.2.6
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_cap;
    sz = create_ap_cap_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // AP radio basic capabilities 17.2.7
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_radio_basic_cap;
    sz = create_ap_radio_basic_cap(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // AP HT capabilities 17.2.8
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ht_cap;
    sz = create_ht_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // AP VHT capabilities 17.2.9
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_vht_cap;
    sz = create_vht_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // AP HE capabilities 17.2.10
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_he_cap;
    sz = create_he_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // AP WiFi6 capabilities 17.2.72
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_wifi6_cap;
    sz = create_wifi6_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // AP Channel Scan capabilities 17.2.38
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_channel_scan_cap;
    sz = create_channelscan_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);
/*
    // 1905 layer security capability tlv 17.2.67
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_1905_layer_security_cap;
    tlv->len = htons(sizeof(em_ieee_1905_security_cap_t));
    memcpy(tlv->value,get_ieee_1905_security_cap(), sizeof(em_ieee_1905_security_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ieee_1905_security_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ieee_1905_security_cap_t));
*/
    // CAC capabilities 17.2.46
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_cac_cap;
    sz = create_cac_cap_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // AP profile 2 capabilities 17.2.48
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_profile_2_ap_cap;
    sz = create_prof_2_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // Metric collection Interval capability tlv 17.2.59
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_metric_cltn_interval;
    sz = create_metric_col_int_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // Device Inventory tlv 17.2.76
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_device_inventory;
    sz = create_device_inventory_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //      One AP radio advanced capability tlv 17.2.52
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_radio_advanced_cap;
    sz = create_radioad_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    return len;
}



int em_capability_t::send_client_cap_query()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_client_cap_query;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm;
    em_cmd_t *pcmd = get_current_cmd();
    em_cmd_params_t *evt_param = &pcmd->m_param;

    dm = get_data_model();

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // One Client Info TLV (see section 17.2.18). 
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_client_info;
    dm_easy_mesh_t::string_to_macbytes(evt_param->args[1], tlv->value);
    dm_easy_mesh_t::string_to_macbytes(evt_param->args[2], tlv->value + sizeof(mac_address_t));
    tlv->len = htons(2*sizeof(mac_address_t));

    tmp += (sizeof(em_tlv_t) + 2*sizeof(mac_address_t));
    len += (sizeof(em_tlv_t) + 2*sizeof(mac_address_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));
    if (em_msg_t(em_msg_type_client_cap_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Channel Selection Request msg failed validation in tnx end\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Channel Selection Request msg failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    m_cap_query_tx_cnt++;
    printf("%s:%d: Capability Query (%d) Send Successful\n", __func__, __LINE__, m_cap_query_tx_cnt);

    return len;
}

short em_capability_t::create_client_cap_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid)
{
    short len = 0;
    unsigned char *tmp = buff;
    unsigned char cap[16]; // replace this with cap from dm
    unsigned char res = 0;

    memcpy(tmp, &res, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    len += sizeof(unsigned char);

    memcpy(tmp, &cap, sizeof(cap));
    tmp += sizeof(cap);
    len += sizeof(cap);

    return len;
}

short em_capability_t::create_client_info_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid)
{
    short len = 0;
    unsigned char *tmp = buff;

    memcpy(tmp, bssid, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, sta, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    return len;
}

short em_capability_t::create_error_code_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid)
{
    short len = 0;
    unsigned char *tmp = buff;
    unsigned char reason = 0;

    memcpy(tmp, &reason, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    len += sizeof(unsigned char);

    memcpy(tmp, sta, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    return len;
}

int em_capability_t::send_client_cap_report_msg(mac_address_t sta, bssid_t bss)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_client_cap_rprt;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    short msg_id = em_msg_type_client_cap_rprt;
    dm_easy_mesh_t *dm = get_data_model();
    mac_address_t ctrl_mac = {0xe4, 0x5f, 0x01, 0x40, 0x70, 0x5b};

    //memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t)); 
    memcpy(tmp, ctrl_mac, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //Client Info  TLV 17.2.18
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_client_info;
    sz = create_client_info_tlv(tlv->value, sta, bss);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //Client Capability Report TLV 17.2.19
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_client_cap_report;
    sz = create_client_cap_tlv(tlv->value, sta, bss);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //Error code  TLV 17.2.36
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_error_code;
    sz = create_error_code_tlv(tlv->value, sta, bss);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_client_cap_rprt, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d: Client capability report validation failed\n", __func__, __LINE__);
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: CLient Capablity report send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    return len;
}

void em_capability_t::handle_client_cap_report(unsigned char *buff, unsigned int len)
{
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_raw_hdr_t *hdr = (em_raw_hdr_t *)buff;

    printf("%s:%d: Enter\n", __func__, __LINE__);

    if (em_msg_t(em_msg_type_client_cap_rprt, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d:Client Capability query message validation failed\n");
        return;
    }

    cmdu = (em_cmdu_t *)(buff + sizeof(em_raw_hdr_t));
    tlv = (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    set_state(em_state_ctrl_sta_cap_confirmed);
}

void em_capability_t::handle_client_cap_query(unsigned char *buff, unsigned int len)
{
    mac_address_t sta;
    bssid_t bss;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_raw_hdr_t *hdr = (em_raw_hdr_t *)buff;

    if (em_msg_t(em_msg_type_client_cap_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d:Client Capability query message validation failed\n");
        return;
    }

    cmdu = (em_cmdu_t *)(buff + sizeof(em_raw_hdr_t));
    tlv = (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    memcpy(bss, tlv->value, sizeof(bssid_t));
    memcpy(sta, tlv->value + sizeof(mac_address_t), sizeof(bssid_t));

    send_client_cap_report_msg(sta, bss);
}

void em_capability_t::process_msg(unsigned char *data, unsigned int len)
{
    em_raw_hdr_t *hdr;
    em_cmdu_t *cmdu;
    unsigned char *tlvs;
    unsigned int tlvs_len;

    hdr = (em_raw_hdr_t *)data;
    cmdu = (em_cmdu_t *)(data + sizeof(em_raw_hdr_t));

    switch (htons(cmdu->type)) {
        case em_msg_type_client_cap_rprt:
            if (get_service_type() == em_service_type_ctrl) {
                handle_client_cap_report(data, len);
            }
            break;

        case em_msg_type_client_cap_query:
            if (get_service_type() == em_service_type_agent) {
                handle_client_cap_query(data, len);
            }
            break;

        default:
            break;
    }
}

void em_capability_t::process_state()
{
    mac_addr_str_t mac_str;
    dm_easy_mesh_t::macbytes_to_string(get_radio_interface_mac(),mac_str);

    switch (get_state()) {
        case em_state_agent_ap_cap_report:
            break;

        case em_state_agent_client_cap_report:
            break;

        case em_state_ctrl_sta_cap_pending:
            if (get_service_type() == em_service_type_ctrl) {
                send_client_cap_query();
            }
            break;

        default:
            break;
    }
}

em_capability_t::em_capability_t()
{

}

em_capability_t::~em_capability_t()
{

}

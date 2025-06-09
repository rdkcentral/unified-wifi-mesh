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
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    unsigned short msg_id = get_current_cmd()->get_data_model()->get_msg_id();

    memcpy(tmp, reinterpret_cast<unsigned char *> (get_peer_mac()), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //AP Capability TLV 17.2.6
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_ap_cap;
    sz = create_ap_cap_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // AP radio basic capabilities 17.2.7
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_ap_radio_basic_cap;
    sz = create_ap_radio_basic_cap(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // AP HT capabilities 17.2.8
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_ht_cap;
    sz = create_ht_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // AP VHT capabilities 17.2.9
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_vht_cap;
    sz = create_vht_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // AP HE capabilities 17.2.10
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_he_cap;
    sz = create_he_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // AP WiFi6 capabilities 17.2.72
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_ap_wifi6_cap;
    sz = create_wifi6_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // AP WiFi7 capabilities 17.2.95
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_wifi7_agent_cap;
    sz = create_wifi7_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // AP EHT Operations 17.2.103
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_eht_operations;
    sz = create_eht_operations_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // AP Channel Scan capabilities 17.2.38
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_channel_scan_cap;
    sz = create_channelscan_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
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
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_cac_cap;
    sz = create_cac_cap_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // AP profile 2 capabilities 17.2.48
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_profile_2_ap_cap;
    sz = create_prof_2_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // Metric collection Interval capability tlv 17.2.59
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_metric_cltn_interval;
    sz = create_metric_col_int_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // Device Inventory tlv 17.2.76
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_device_inventory;
    sz = create_device_inventory_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // One AP radio advanced capability tlv 17.2.52
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_ap_radio_advanced_cap;
    sz = create_radioad_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(em_tlv_t));
    len += (sizeof(em_tlv_t));

    return static_cast<int> (len);
}


int em_capability_t::send_client_cap_query()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_client_cap_query;
    size_t len = 0;
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

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // One Client Info TLV (see section 17.2.18). 
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_client_info;
    dm_easy_mesh_t::string_to_macbytes(evt_param->u.args.args[1], tlv->value);
    dm_easy_mesh_t::string_to_macbytes(evt_param->u.args.args[2], tlv->value + sizeof(mac_address_t));
    tlv->len = htons(2*sizeof(mac_address_t));

    tmp += (sizeof(em_tlv_t) + 2*sizeof(mac_address_t));
    len += (sizeof(em_tlv_t) + 2*sizeof(mac_address_t));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));
    if (em_msg_t(em_msg_type_client_cap_query, em_profile_type_3, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        printf("Capability Query msg failed validation in tnx end\n");
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        printf("%s:%d: Capability Query msg failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    m_cap_query_tx_cnt++;
    printf("%s:%d: Capability Query (%d) Send Successful for sta:%s\n", __func__, __LINE__, m_cap_query_tx_cnt, evt_param->u.args.args[2]);

    return static_cast<int> (len);
}

short em_capability_t::create_client_cap_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid)
{
    short len = 0;
    unsigned char *tmp = buff;
    unsigned char res = 0;
    dm_easy_mesh_t *dm;
    dm_sta_t *dm_sta;

    dm = get_data_model();

    dm_sta = reinterpret_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
    while(dm_sta != NULL) {
        if (memcmp(dm_sta->get_sta_info()->id, sta, sizeof(mac_address_t)) == 0) {
            break;
        }
        dm_sta = reinterpret_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
    }

    //TODO; if dm_sta is null break; fill result 0?
    if(dm_sta == NULL) {
        return 0;
    }

    memcpy(tmp, &res, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    len += static_cast<short> (sizeof(unsigned char));

    //frame_body
    memcpy(tmp, &dm_sta->get_sta_info()->frame_body, dm_sta->get_sta_info()->frame_body_len);
    tmp += dm_sta->get_sta_info()->frame_body_len;
    len += static_cast<short> (dm_sta->get_sta_info()->frame_body_len);

    return len;
}

short em_capability_t::create_client_info_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid)
{
    short len = 0;
    unsigned char *tmp = buff;

    memcpy(tmp, bssid, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<short> (sizeof(mac_address_t));

    memcpy(tmp, sta, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<short> (sizeof(mac_address_t));

    return len;
}

short em_capability_t::create_error_code_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid)
{
    short len = 0;
    unsigned char *tmp = buff;
    unsigned char reason = 0;

    memcpy(tmp, &reason, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    len += static_cast<short> (sizeof(unsigned char));

    memcpy(tmp, sta, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<short> (sizeof(unsigned char));

    return len;
}

int em_capability_t::send_client_cap_report_msg(mac_address_t sta, bssid_t bss)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_client_cap_rprt;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    unsigned short msg_id = em_msg_type_client_cap_rprt;
    dm_easy_mesh_t *dm = get_data_model();
    mac_address_t ctrl_mac = {0xe4, 0x5f, 0x01, 0x40, 0x70, 0x5b};
    mac_addr_str_t mac_str;

    //memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t)); 
    memcpy(tmp, ctrl_mac, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //Client Info  TLV 17.2.18
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_client_info;
    sz = create_client_info_tlv(tlv->value, sta, bss);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    //Client Capability Report TLV 17.2.19
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_client_cap_report;
    sz = create_client_cap_tlv(tlv->value, sta, bss);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    //Error code  TLV 17.2.36
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_error_code;
    sz = create_error_code_tlv(tlv->value, sta, bss);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_client_cap_rprt, em_profile_type_3, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        printf("%s:%d: Client capability report validation failed\n", __func__, __LINE__);
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        printf("%s:%d: Client Capablity report send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    dm_easy_mesh_t::macbytes_to_string(sta, mac_str);
    printf("%s:%d: Client Capablity report Send Successful for sta:%s\n", __func__, __LINE__, mac_str);

    return static_cast<int> (len);
}

int em_capability_t::handle_client_cap_report(unsigned char *buff, unsigned int len)
{
    unsigned int tmp_len;
    em_tlv_t *tlv;
    em_sta_info_t sta_info;
    mac_addr_str_t sta_mac_str, bssid_str, radio_mac_str;
    em_long_string_t	key;
    dm_easy_mesh_t  *dm;
    bool found_client_info = false;
    bool found_cap_report = false;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    dm = get_data_model();

    if (em_msg_t(em_msg_type_client_cap_rprt, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d:Client Capability query message validation failed\n",__func__,__LINE__);
        return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_client_info) {
            memset(&sta_info, 0, sizeof(em_sta_info_t));
            memcpy(sta_info.bssid, tlv->value, sizeof(mac_address_t));
            memcpy(sta_info.id, tlv->value + sizeof(mac_address_t), sizeof(mac_address_t));
            memcpy(sta_info.radiomac, get_radio_interface_mac(), sizeof(mac_address_t));
            found_client_info = true;
            break;
        }

        tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    if (found_client_info == false) {
        printf("%s:%d: Could not find client info\n", __func__, __LINE__);
        return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_client_cap_report) {
            if (tlv->value[0] != 0) {
                printf("%s:%d: result code: failure\n", __func__, __LINE__);
                return -1;
            }
            sta_info.associated = true;
            sta_info.frame_body_len = htons(tlv->len) - 1;
            memcpy(sta_info.frame_body, &tlv->value[1], htons(tlv->len) - 1);

            found_cap_report = true;
            break;
        }

        tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    if (found_cap_report == false) {
        printf("%s:%d: Could not find client cap report\n", __func__, __LINE__);
        return -1;
    }

    set_state(em_state_ctrl_sta_cap_confirmed);

    dm_easy_mesh_t::macbytes_to_string(sta_info.id, sta_mac_str);
    dm_easy_mesh_t::macbytes_to_string(sta_info.bssid, bssid_str);
    dm_easy_mesh_t::macbytes_to_string(get_radio_interface_mac(), radio_mac_str);
    snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bssid_str, radio_mac_str);

    if (hash_map_get(dm->m_sta_assoc_map, key) == NULL) {
        hash_map_put(dm->m_sta_assoc_map, strdup(key), new dm_sta_t(&sta_info));
        dm->set_db_cfg_param(db_cfg_type_sta_list_update, "");
    }

    return 0;
}

void em_capability_t::handle_client_cap_query(unsigned char *buff, unsigned int len)
{
    mac_address_t sta;
    bssid_t bss;
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_client_cap_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d:Client Capability query message validation failed\n",__func__,__LINE__);
        return;
    }

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    memcpy(bss, tlv->value, sizeof(bssid_t));
    memcpy(sta, tlv->value + sizeof(mac_address_t), sizeof(bssid_t));

    send_client_cap_report_msg(sta, bss);
    set_state(em_state_agent_configured);
}

void em_capability_t::process_msg(unsigned char *data, unsigned int len)
{
    em_cmdu_t *cmdu;

    cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));

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

void em_capability_t::process_agent_state()
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

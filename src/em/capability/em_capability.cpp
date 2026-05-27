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

int em_capability_t::send_ap_cap_report_msg(unsigned char *dst, unsigned short msg_id)
{
    unsigned char buff[MAX_EM_BUFF_SZ * EM_MAX_RADIO_PER_AGENT] = {0};
    //char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_ap_cap_rprt;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t  *dm;
    unsigned short sz = 0;
    int i = 0;

    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *> (dst);

    dm = get_data_model();

    em_printfout("Sending AP CAP REPORT with dest mac: %s and src[%s] with %d radios and %d bss",
        util::mac_to_string(hdr->src).c_str(),
        util::mac_to_string(dm->get_agent_al_interface_mac()).c_str(),
        dm->get_num_radios(), dm->get_num_bss());

    memcpy(tmp, reinterpret_cast<unsigned char *> (hdr->src), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int>(sizeof(mac_address_t));

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int>(sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<unsigned int>(sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);
    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int>(sizeof(em_cmdu_t));

    // AP Capability TLV 17.2.6
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_ap_cap;
    sz = static_cast<unsigned short>(create_ap_cap_tlv(tlv->value));
    tlv->len = htons(static_cast<uint16_t>(sz));
    tmp += (sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));
    len += static_cast<unsigned int>(sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));

    //AKM Suite
    tlv = reinterpret_cast<em_tlv_t *>(tmp);//
    tlv->type = em_tlv_type_akm_suite;
    sz = static_cast<unsigned short>(create_akm_suite_cap_tlv(tlv->value));
    tlv->len = htons(static_cast<uint16_t>(sz));
    tmp += (sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));
    len += static_cast<unsigned int>(sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));

    //AP WiFi7 capabilities 17.2.95
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_wifi7_agent_cap;
    sz = static_cast<unsigned short>(create_wifi7_tlv(tlv->value));
    tlv->len = htons(static_cast<uint16_t>(sz));
    tmp += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
    len += static_cast<unsigned int>(sizeof(em_tlv_t) + static_cast<size_t>(sz));

    std::vector<em_t *> em_radios;
    get_mgr()->get_all_em_for_al_mac(dm->get_agent_al_interface_mac(), em_radios);
    em_printfout("dm->get_agent_al_interface_mac(): %s, num of em_radios: %d", util::mac_to_string(dm->get_agent_al_interface_mac()).c_str(), em_radios.size());
    for (auto &em : em_radios)
    {
        em_printfout("Radio[%d] : %s",
            i++, util::mac_to_string(em->get_radio_interface_mac()).c_str());

        // AP radio basic capabilities 17.2.7
        tlv = reinterpret_cast<em_tlv_t *>(tmp);
        tlv->type = em_tlv_type_ap_radio_basic_cap;
        sz = static_cast<unsigned short>(em->create_ap_radio_basic_cap(tlv->value));
        tlv->len = htons(static_cast<uint16_t>(sz));
        tmp += (sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));
        len += static_cast<unsigned int>(sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));

        // AP HT capabilities 17.2.8
        tlv = reinterpret_cast<em_tlv_t *>(tmp);
        tlv->type = em_tlv_type_ht_cap;
        sz = static_cast<unsigned short>(em->create_ht_tlv(tlv->value));
        tlv->len = htons(static_cast<uint16_t>(sz));
        tmp += (sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));
        len += (sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));

        // AP VHT capabilities 17.2.9
        tlv = reinterpret_cast<em_tlv_t *>(tmp);
        tlv->type = em_tlv_type_vht_cap;
        sz = static_cast<unsigned short>(em->create_vht_tlv(tlv->value));
        tlv->len = htons(static_cast<uint16_t>(sz));
        tmp += (sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));
        len += (sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));

        // AP HE capabilities 17.2.10
        tlv = reinterpret_cast<em_tlv_t *>(tmp);
        tlv->type = em_tlv_type_he_cap;
        sz = static_cast<unsigned short>(em->create_he_tlv(tlv->value));
        tlv->len = htons(static_cast<uint16_t>(sz));

        tmp += (sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));
        len += (sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));

        // AP WiFi6 capabilities 17.2.72
        tlv = reinterpret_cast<em_tlv_t *>(tmp);
        tlv->type = em_tlv_type_ap_wifi6_cap;
        sz = static_cast<unsigned short>(em->create_wifi6_tlv(tlv->value));
        tlv->len = htons(static_cast<uint16_t>(sz));
        tmp += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
        len += static_cast<unsigned int>(sizeof(em_tlv_t) + static_cast<size_t>(sz));

        // AP radio advanced capability tlv 17.2.52
        sz = static_cast<unsigned short>(em->create_ap_radio_advanced_cap_tlv(tmp + sizeof(em_tlv_t)));
        if (sz > 0) {
            tlv = reinterpret_cast<em_tlv_t *>(tmp);
            tlv->type = em_tlv_type_ap_radio_advanced_cap;
            tlv->len = htons(static_cast<uint16_t>(sz));
            tmp += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
            len += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
        }

        em->set_state(em_state_agent_ap_cap_report);
    }
    em_radios.clear();

    // AP Channel Scan capabilities 17.2.38
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_channel_scan_cap;
    sz = static_cast<unsigned short>(create_channelscan_tlv(tlv->value));
    tlv->len = htons(static_cast<uint16_t>(sz));
    tmp += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t>(sz));

    // 1905 layer security capability tlv 17.2.67
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_1905_layer_security_cap;
    tlv->len = htons(sizeof(em_ieee_1905_security_cap_t));
    memcpy(tlv->value, get_ieee_1905_security_cap(), sizeof(em_ieee_1905_security_cap_t));
    tmp += (sizeof(em_tlv_t) + sizeof(em_ieee_1905_security_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ieee_1905_security_cap_t));

    // CAC capabilities 17.2.46
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_cac_cap;
    sz = static_cast<unsigned short>(create_cac_cap_tlv(tlv->value));
    tlv->len = htons(static_cast<uint16_t>(sz));
    tmp += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t>(sz));

    // AP profile 2 capabilities 17.2.48
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_profile_2_ap_cap;
    sz = static_cast<unsigned short>(create_prof_2_tlv(tlv->value));
    tlv->len = htons(static_cast<uint16_t>(sz));
    tmp += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t>(sz));

    // Metric collection Interval capability tlv 17.2.59
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_metric_cltn_interval;
    sz = static_cast<unsigned short>(create_metric_col_int_tlv(tlv->value));
    tlv->len = htons(static_cast<uint16_t>(sz));
    tmp += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t>(sz));

    // Device Inventory tlv 17.2.76
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_device_inventory;
    sz = static_cast<unsigned short>(create_device_inventory_tlv(tlv->value));
    tlv->len = htons(static_cast<uint16_t>(sz));
    tmp += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t>(sz));

    // AP EHT Operations 17.2.103
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_eht_operations;
    sz = static_cast<unsigned short>(create_eht_operations_tlv(tlv->value));
    tlv->len = htons(static_cast<uint16_t>(sz));
    tmp += (sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));
    len += (sizeof(em_tlv_t) + static_cast<short unsigned int>(sz));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(em_tlv_t));
    len += static_cast<unsigned int>((sizeof(em_tlv_t)));

    /*if (em_msg_t(em_msg_type_ap_cap_rprt, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("Error: AP Capability Report msg validation failed in tnx end");

        return -1;
    }*/

    if (send_frame(buff, len)  < 0) {
        em_printfout("Error: AP Capability Report msg send failed, error: %d", errno);
        return -1;
    }
    set_state(em_state_agent_ap_cap_report);
    em_printfout("AP Capability Report msg sent successfully, len[%d]", len);
    return static_cast<int> (len);
}


int em_capability_t::send_client_cap_query()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_client_cap_query;
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
    cmdu->type = htons(msg_type);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
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
        em_printfout("Error: Client Capability Query msg validation failed in tnx end");
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        em_printfout("Error: Client Capability Query msg send failed, error: %d", errno);
        return -1;
    }

    m_cap_query_tx_cnt++;
    em_printfout("Client Capability Query msg (%d) sent successfully for sta: %s", m_cap_query_tx_cnt, evt_param->u.args.args[2]);

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

int em_capability_t::create_bsta_radio_cap_tlv(uint8_t *buff)
{
    ASSERT_NOT_NULL(buff, -1, "%s:%d: Buffer is null\n", __func__, __LINE__);
    dm_easy_mesh_t *dm = get_data_model();
    ASSERT_NOT_NULL(dm, -1, "%s:%d: Data model is null\n", __func__, __LINE__);

    int len = 0;
    em_interface_name_t name;
    em_bh_sta_radio_cap_t *bsta_radio_cap = reinterpret_cast<em_bh_sta_radio_cap_t*>(buff);

    for (unsigned int j = 0; j < dm->get_num_bss(); j++) {
        auto* bss_info = dm->get_bss_info(j);
        if (!bss_info) continue;

        em_printfout("BSSID %s, vap_mode:%d, vap name: %s, haul type: %d",
            util::mac_to_string(bss_info->bssid.mac).c_str(), bss_info->vap_mode, bss_info->bssid.name,  bss_info->id.haul_type);

        if (bss_info->id.haul_type != em_haul_type_backhaul ||
            bss_info->vap_mode != em_vap_mode_sta) {
            continue;
        }
        memcpy(bsta_radio_cap->ruid, bss_info->ruid.mac, sizeof(mac_address_t));
        len = static_cast <int> (sizeof(mac_address_t) + sizeof(uint8_t)); // RUID + MAC present flag
        if (dm_easy_mesh_t::name_from_mac_address((reinterpret_cast<mac_address_t*>(dm->get_ctl_mac())), name) == 0) {
            em_printfout("MAC address exists on this device.");
            memset(bsta_radio_cap->bsta_addr, 0, sizeof(mac_address_t));
        } else {
            em_printfout("MAC address not found on any interface.");
            memcpy(bsta_radio_cap->bsta_addr, bss_info->sta_mac, sizeof(mac_address_t));
        }
        bsta_radio_cap->bsta_mac_present = 1;
        len += static_cast <int> (sizeof(mac_address_t)); // BSTA MAC
        break;
    }
    if (len) {
        em_printfout("Backhaul STA Radio Capabilities TLV: BSTA: %s of rad: %s",
            util::mac_to_string(bsta_radio_cap->bsta_addr).c_str(),
            util::mac_to_string(bsta_radio_cap->ruid).c_str());
    }
    return len;
}

int em_capability_t::send_client_cap_report_msg(mac_address_t sta, bssid_t bss, unsigned short msg_id)
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
    dm_easy_mesh_t *dm = get_data_model();
    mac_addr_str_t mac_str;

    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
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
        em_printfout("Error: Client Capability Report msg validation failed in tnx end");
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        em_printfout("Error: Client Capability Report msg send failed, error: %d", errno);
        return -1;
    }

    dm_easy_mesh_t::macbytes_to_string(sta, mac_str);
    em_printfout("Client Capability Report msg sent successfully for sta: %s", mac_str);

    return static_cast<int> (len);
}

int em_capability_t::send_ap_cap_query_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t* dm = NULL;

    dm = get_data_model();

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<unsigned int> (sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(em_msg_type_ap_cap_query);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // No Tlv

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_ap_cap_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("Error: AP Capability Query msg validation failed in tnx end");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        em_printfout("Error: AP Capability Query msg send failed, error: %d", errno);
        return -1;
    }
    em_printfout("AP Capability Query msg sent successfully for radio: %s", util::mac_to_string(get_radio_interface_mac()).c_str());

    return 0;
}

int em_capability_t::send_bsta_cap_query_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t* dm = NULL;

    dm = get_data_model();

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<unsigned int> (sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(em_msg_type_bh_sta_cap_query);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // No Tlv

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_bh_sta_cap_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("Error: Backhaul Sta Capability Query msg validation failed in tnx end");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        em_printfout("Error: Backhaul Sta Capability Query msg send failed, error: %d", errno);
        return -1;
    }

    em_printfout("Backhaul Sta Capability Query msg sent successfully for radio: %s", util::mac_to_string(get_radio_interface_mac()).c_str());

    return 0;
}

int em_capability_t::send_bsta_cap_report_msg(unsigned short msg_id)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_bh_sta_cap_rprt;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();

    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
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

    // 17.2.65 Backhaul STA Radio Capabilities TLV
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_bh_sta_radio_cap;

    sz = create_bsta_radio_cap_tlv(tlv->value);
    tlv->len = htons(static_cast<uint16_t> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    em_bss_info_t* bss_info = dm->get_backhaul_bss_info();
    if (bss_info != NULL)
    {
        // 17.2.18 Client Info TLV
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_client_info;
        //here BSSID = mesh backhaul's BSSID
        sz = create_client_info_tlv(tlv->value, bss_info->sta_mac, bss_info->bssid.mac);
        em_printfout("bss_info->sta_mac = %s and bss_info->bssid.mac = %s",
            util::mac_to_string(bss_info->sta_mac).c_str(),
            util::mac_to_string(bss_info->bssid.mac).c_str());
        tlv->len = htons(static_cast<uint16_t> (sz));

        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    }

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_bh_sta_cap_rprt, em_profile_type_3, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        em_printfout("Error: Backhaul Sta Capability Report msg validation failed in tnx end");
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        em_printfout("Error: Backhaul Sta Capability Report msg send failed");
        return -1;
    }

    em_printfout("Backhaul Sta Capability Report msg sent successfully");

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
        em_printfout("Error: Client Capability Report msg validation failed");
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
        em_printfout("Error: Could not find client info");
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
            sta_info.frame_body_len = static_cast<unsigned int>(htons(tlv->len) - 1);
            memcpy(sta_info.frame_body, &tlv->value[1], static_cast<size_t>(sta_info.frame_body_len));

            found_cap_report = true;
            break;
        }

        tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    if (found_cap_report == false) {
        em_printfout("Error: Could not find client cap report");
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
        em_printfout("New client updated to db: %s", key);
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
        em_printfout("Error: Client Capability Query msg validation failed");
        return;
    }

    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));
    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    memcpy(bss, tlv->value, sizeof(bssid_t));
    memcpy(sta, tlv->value + sizeof(mac_address_t), sizeof(bssid_t));

    send_client_cap_report_msg(sta, bss, ntohs(cmdu->id));
    set_state(em_state_agent_configured);
}

int em_capability_t::handle_bsta_cap_query(unsigned char *buff, unsigned int len)
{
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));

    if (em_msg_t(em_msg_type_bh_sta_cap_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("Error: Backhaul Sta Capability Query msg validation failed");
        return -1;
    }

    em_printfout("Backhaul Sta Capability Query msg rcvd");

    send_bsta_cap_report_msg(ntohs(cmdu->id));

    return 0;
}

int em_capability_t::handle_bsta_radio_cap(unsigned char *tlv_buff, unsigned int tlv_len)
{
    if (!tlv_buff)
    {
        return -1;
    }

    if (!tlv_len || ((tlv_len != sizeof(em_bh_sta_radio_cap_t)) && (tlv_len != offsetof(em_bh_sta_radio_cap_t, bsta_addr))))
    {
        em_printfout("Error: Invalid TLV length:%d Must be %d or %d for bsta radio cap TLV",
		     static_cast<int>(tlv_len),
                     static_cast<int>(offsetof(em_bh_sta_radio_cap_t, bsta_addr)),
                     static_cast<int>(sizeof(em_bh_sta_radio_cap_t)));
        return -1;
    }

    em_bh_sta_radio_cap_t *bsta_radio_cap = reinterpret_cast<em_bh_sta_radio_cap_t*>(tlv_buff);
    std::string ruid_str = util::mac_to_string(bsta_radio_cap->ruid);
    em_printfout("Rcvd BSTA Cap, for radio: %s, mac present: %d",
            ruid_str.c_str(),
            bsta_radio_cap->bsta_mac_present);

    if (tlv_len == offsetof(em_bh_sta_radio_cap_t, bsta_addr))
    {
        if (bsta_radio_cap->bsta_mac_present)
        {
            em_printfout("Error: bsta_mac_present is 1 when tlv_len is %d", static_cast<int>(offsetof(em_bh_sta_radio_cap_t, bsta_addr)));
            return -1;
        }
        return 0;
    }

    if (!bsta_radio_cap->bsta_mac_present)
    {
        em_printfout("Error: bsta_mac_present is 0 when tlv_len is %d", static_cast<int>(sizeof(em_bh_sta_radio_cap_t)));
        return -1;
    }

    dm_easy_mesh_t *dm = get_data_model();

    if (!dm) {
        em_printfout("Error: Could not find data model");
        return -1;
    }

    em_device_info_t *dev = dm->get_device_info();
    if (!dev)
    {
        em_printfout("Error: Could not find device in data model");
        return -1;
    }

    em_printfout("Update BSTA Cap for Device id: %s", util::mac_to_string(dev->id.dev_mac).c_str());
    memcpy(dm->m_device.m_device_info.backhaul_sta, bsta_radio_cap->bsta_addr, sizeof(mac_address_t));
    dm->set_db_cfg_param(db_cfg_type_device_list_update, "");
    return 0;
}

int em_capability_t::handle_client_info(unsigned char *tlv_buff, unsigned int tlv_len)
{
    if (!tlv_buff) {
        return -1;
    }

    if (tlv_len != sizeof(em_client_info_t)) {
        em_printfout("Error: Invalid TLV length for client info TLV: received %u, expected %d", tlv_len, static_cast<int>(sizeof(em_client_info_t)));
        return -1;
    }

    const em_client_info_t *client_info = reinterpret_cast<const em_client_info_t *>(tlv_buff);

    dm_easy_mesh_t *dm = get_data_model();

    if (!dm) {
        em_printfout("Error: Could not find data model");
        return -1;
    }

    if (dm->get_colocated() != true) {
        memcpy(dm->m_device.m_device_info.backhaul_mac.mac, client_info->client_mac_addr, sizeof(mac_address_t));
        dm->set_db_cfg_param(db_cfg_type_device_list_update, "");
    }

    return 0;
}

int em_capability_t::process_single_tlv_in_1905_message(unsigned char *pkt_buff, unsigned int pkt_len, em_tlv_type_t tlv_type,
                                      int (em_capability_t::*handler)(unsigned char*, unsigned int))
{
    em_tlv_t *tlv = NULL;
    unsigned int header_len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);

    if (!pkt_buff || !pkt_len || !handler) {
        return -1;
    }

    if (pkt_len <= header_len) {
        return -1;
    }

    em_tlv_t* tlvs_start = reinterpret_cast<em_tlv_t *>(pkt_buff + header_len);
    unsigned int tlvs_len = pkt_len - header_len;

    if (tlvs_len < sizeof(em_tlv_t)) {
            return -1;
    }

    if (tlvs_start->type == em_tlv_type_eom) {
            if (ntohs(tlvs_start->len) != 0) {
                     return -1;
            }
            return 0;
    }

    tlv = em_msg_t::get_first_tlv(tlvs_start, tlvs_len);

    if (!tlv) {
            return -1;
    }

    while (tlv != NULL) {
        if (tlv->type == em_tlv_type_eom) {
            break;
        }

        if (tlv->type == tlv_type) {
            uint16_t tlv_len = ntohs(tlv->len);
            return (this->*handler)(tlv->value, tlv_len);
        }

        tlv = em_msg_t::get_next_tlv(tlv, tlvs_start, tlvs_len);
    }

    return 0;
}

int em_capability_t::handle_bsta_cap_report(unsigned char *pkt_buff, unsigned int pkt_len)
{
    int ret = 0;

    em_printfout("Backhaul Sta Capability report message rcvd");

    ret = process_single_tlv_in_1905_message(pkt_buff, pkt_len,
            em_tlv_type_bh_sta_radio_cap,
            &em_capability_t::handle_bsta_radio_cap);

    if (ret < 0)
        em_printfout("Warning: failed to process bh_sta_radio_cap TLV, continuing");

    ret = process_single_tlv_in_1905_message(pkt_buff, pkt_len,
            em_tlv_type_client_info,
            &em_capability_t::handle_client_info);

    if (ret < 0)
        return ret;

    set_state(em_state_ctrl_configured);
    em_printfout("Cap: Bsta Capability report processed, ctrl configured");

    return ret;
}

int em_capability_t::handle_ap_radio_basic_cap(unsigned char *buff, unsigned int len)
{
	dm_radio_t * radio;
	mac_address_t	ruid;
	unsigned int i, j;
	em_radio_info_t *radio_info;
	bool radio_exists = false;
	bool op_class_exists = false;
	mac_addr_str_t mac_str;
	em_ap_radio_basic_cap_t *radio_basic_cap = reinterpret_cast<em_ap_radio_basic_cap_t *> (buff);
	em_op_class_t *basic_cap_op_class;
	em_op_class_info_t	op_class_info;
	dm_op_class_t *op_class_obj;

	dm_easy_mesh_t *dm = get_data_model();

	memcpy(ruid, radio_basic_cap->ruid, sizeof(mac_address_t));
	dm_easy_mesh_t::macbytes_to_string(ruid, mac_str);
	for (i = 0; i < dm->get_num_radios(); i++) {
		radio = dm->get_radio(i);
		if (memcmp(radio->m_radio_info.intf.mac, ruid, sizeof(mac_address_t)) == 0) {
			radio_exists = true;
			break;
		}
	}
	if (radio_exists == false) {
		em_printfout("Radio does not exist, getting radio at index: %d", dm->get_num_radios());
		radio = dm->get_radio(dm->get_num_radios());
		memset(&radio->m_radio_info, 0, sizeof(em_radio_info_t));	
		dm->set_num_radios(dm->get_num_radios() + 1);
	}

	radio_info = &radio->m_radio_info;
	memcpy(radio_info->intf.mac, ruid, sizeof(mac_address_t));
	radio_info->enabled = true;
	radio_info->number_of_bss = radio_basic_cap->num_bss;
	dm->set_db_cfg_param(db_cfg_type_radio_list_update, "");

	basic_cap_op_class = radio_basic_cap->op_classes;
	if (basic_cap_op_class != NULL) {
		for (i = 0; i < radio_basic_cap->op_class_num; i++) {
			memset(&op_class_info, 0, sizeof(em_op_class_info_t));
			memcpy(op_class_info.id.ruid, ruid, sizeof(mac_address_t));
			op_class_info.id.type = em_op_class_type_capability;
			op_class_info.op_class = static_cast<unsigned int> (basic_cap_op_class->op_class);
			op_class_info.id.op_class = op_class_info.op_class;
			op_class_info.max_tx_power = static_cast<int> (basic_cap_op_class->max_tx_eirp);
			op_class_info.num_channels = static_cast<unsigned int> (basic_cap_op_class->num);
			for (j = 0; j < op_class_info.num_channels; j++) {
				op_class_info.channels[j] = static_cast<unsigned int> (basic_cap_op_class->channels.channel[j]);
			}
			basic_cap_op_class = reinterpret_cast<em_op_class_t *>(reinterpret_cast<unsigned char *> (basic_cap_op_class) + sizeof(em_op_class_t) + op_class_info.num_channels);
 			op_class_obj = &dm->m_op_class[0];
			op_class_obj = &dm->m_op_class[0];
			// now check if the op_class already exists
			for (j = 0; j < dm->get_num_op_class(); j++) {
				op_class_obj = &dm->m_op_class[j];
				if (*op_class_obj == dm_op_class_t(&op_class_info)) {
					op_class_exists = true;
					break;
				}
			}

			if (op_class_exists == true) {
				op_class_exists = false;
			} else {
				op_class_obj = &dm->m_op_class[dm->get_num_op_class()];
				dm->set_num_op_class(dm->get_num_op_class() + 1);
			}
			memcpy(&op_class_obj->m_op_class_info, &op_class_info, sizeof(em_op_class_info_t));
			dm->set_db_cfg_param(db_cfg_type_op_class_list_update, "");
		}
	} else {
		em_printfout("basic_cap_op_class is NULL");
	}

	return 0;
}

int em_capability_t::handle_channel_scan_cap_tlv(unsigned char *buff, unsigned int len)
{
    dm_easy_mesh_t *dm = get_data_model();
    const unsigned char *tmp = buff;
    unsigned int sz = 0;

    if (len < 1) {
        em_printfout("Channel scan cap TLV too short");
        return -1;
    }

    unsigned char num_radios_in_tlv = *tmp++;
    sz++;
    em_printfout("Channel scan cap TLV: num_radios=%d", num_radios_in_tlv);

    // Fixed part of em_channel_scan_cap_radio_t that create_channelscan_tlv advances over.
    static const size_t radio_hdr_sz = sizeof(em_channel_scan_cap_radio_t)
                                       - sizeof(static_cast<em_channel_scan_cap_radio_t *>(nullptr)->op_classes);

    for (unsigned char i = 0; i < num_radios_in_tlv; i++) {
        if (sz + radio_hdr_sz > len) {
            em_printfout("Channel scan cap TLV truncated at radio[%d] header (sz=%u, len=%u)", i, sz, len);
            return -1;
        }

        const em_channel_scan_cap_radio_t *src =
            reinterpret_cast<const em_channel_scan_cap_radio_t *>(tmp);

        unsigned char num_op_classes = src->op_classes_num;

        em_printfout("  Radio[%d] RUID=%s boot_only=%d scan_impact=%d "
                     "min_scan_interval=%u num_op_classes=%d",
            i, util::mac_to_string(src->ruid).c_str(),
            src->boot_only, src->scan_impact, ntohl(src->min_scan_interval), num_op_classes);

        tmp += radio_hdr_sz;
        sz += static_cast<unsigned int>(radio_hdr_sz);

        mac_address_t ruid;
        memcpy(ruid, src->ruid, sizeof(mac_address_t));

        dm_radio_cap_t *radio_cap = dm->get_radio_cap(ruid);
        if (radio_cap == NULL) {
            em_printfout("  Radio[%d]: no DM radio_cap for RUID %s, skipping",
                i, util::mac_to_string(src->ruid).c_str());
            // Skip all op class entries for this radio
            for (unsigned char oi = 0; oi < num_op_classes; oi++) {
                if (sz + 2 > len) {
                    em_printfout("Channel scan cap TLV truncated skipping op_class");
                    return -1;
                }
                tmp++;                   // op_class
                unsigned char nc = *tmp++;
                sz += 2;
                if (sz + nc > len) {
                    em_printfout("Channel scan cap TLV truncated at channel list");
                    return -1;
                }
                tmp += nc;               // channel list
                sz += nc;
            }
            continue;
        }

        em_radio_cap_info_t *cap_info = radio_cap->get_radio_cap_info();
        if (cap_info == NULL) {
            em_printfout("  Radio[%d]: cap_info NULL", i);
            continue;
        }

        // Populate ch_scan to match the fields create_channelscan_tlv reads back out
        memcpy(cap_info->ch_scan.ruid, ruid, sizeof(mac_address_t));
        cap_info->ch_scan.boot_only         = src->boot_only;
        cap_info->ch_scan.scan_impact       = src->scan_impact;
        cap_info->ch_scan.reserved          = 0;
        cap_info->ch_scan.min_scan_interval = ntohl(src->min_scan_interval);
        cap_info->ch_scan.op_classes_num    = 0;

        for (unsigned char oi = 0; oi < num_op_classes; oi++) {
            if (sz + 2 > len) {
                em_printfout("Channel scan cap TLV truncated at op_class[%d]", oi);
                return -1;
            }
            unsigned char op_class = *tmp++;
            unsigned char num_chan  = *tmp++;
            sz += 2;

            em_printfout("    op_class[%d]: op_class=%d num_chan=%d", oi, op_class, num_chan);

            if (sz + num_chan > len) {
                em_printfout("Channel scan cap TLV truncated at channel list");
                return -1;
            }

            if (oi < EM_MAX_OPCLASS) {
                em_scan_cap_op_class_info_t *entry = &cap_info->ch_scan.op_classes[oi];
                entry->op_class = op_class;
                memset(entry->channels.channel, 0, EM_MAX_CHANNELS_IN_LIST);
                unsigned char copy_n = (num_chan <= EM_MAX_CHANNELS_IN_LIST)
                                       ? num_chan : EM_MAX_CHANNELS_IN_LIST;
                entry->num      = copy_n;
                memcpy(entry->channels.channel, tmp, copy_n);
                cap_info->ch_scan.op_classes_num++;
            }
            tmp += num_chan;
            sz += num_chan;
        }
        em_printfout("  Radio[%d]: stored %d op classes", i, cap_info->ch_scan.op_classes_num);
    }
    return 0;
}

int em_capability_t::handle_ap_cap_report(unsigned char *buff, unsigned int len)
{
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));

    em_tlv_t *tlv;
    unsigned int tmp_len;
    dm_easy_mesh_t *dm;

    dm = get_data_model();
    
    tlv =  reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *>(cmdu) + sizeof(em_cmdu_t));
    tmp_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    em_printfout("AP Capability report message rcvd");

    dm_radio_cap_t *dm_radio_cap = dm->get_radio_cap(get_radio_interface_mac());
    if (dm_radio_cap == NULL) {
        em_printfout("handle_wifi6_cap_tlv: radio_cap NULL for MAC %s",
            util::mac_to_string(get_radio_interface_mac()).c_str());
        //check if DM radio cap's radio macs are 0, if not available update only the rmacs
        if (dm->get_num_radios() > 0) {
            em_printfout("handle_wifi6_cap_tlv: update dm_radio_cap's radio mac");
            for (unsigned int i = 0; i < dm->get_num_radios(); i++) {
                dm_radio_cap = dm->get_radio_cap(static_cast<int>(i));
                if (dm_radio_cap != NULL) {
                    memcpy(dm_radio_cap->m_radio_cap_info.ruid.mac, dm->m_radio[i].m_radio_info.id.ruid, sizeof(mac_address_t));
                    em_printfout("handle_wifi6_cap_tlv: dm_radio_cap updated for MAC %s",
                        util::mac_to_string(dm_radio_cap->m_radio_cap_info.ruid.mac).c_str());
                }
            }
        } else {
            em_printfout("handle_wifi6_cap_tlv: No radios in data model, cannot update dm_radio_cap");
            return 0;
        }
    }

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_ap_cap) {
            dm_radio_t *radio = dm->get_radio(get_radio_interface_mac());
            if (radio == NULL) {
                em_printfout("Radio[%s] not found", util::mac_to_string(get_radio_interface_mac()).c_str());
                return -1;
            }
            em_radio_info_t *radio_info = radio->get_radio_info();
            em_ap_capability_t *ap_cap = reinterpret_cast<em_ap_capability_t *>(tlv->value);

            if ((ap_cap == NULL) || (radio_info == NULL)){
                em_printfout("No data Found");
            }

            radio_info->unassociated_sta_link_mterics_nonopclass_inclusion_policy = ap_cap->unassociated_client_link_metrics_non_op_channels;
            radio_info->unassociated_sta_link_mterics_opclass_inclusion_policy = ap_cap->unassociated_client_link_metrics_op_channels;
            radio_info->support_rcpi_steering = ap_cap->rcpi_steering;
        } else if (tlv->type == em_tlv_type_ap_radio_basic_cap){
            em_printfout("Received AP Radio Basic Capability TLV");
            handle_ap_radio_basic_cap(tlv->value, htons(tlv->len));
        } else if (tlv->type == em_tlv_type_ht_cap){
            em_printfout("Received HT Capability TLV");
            em_ap_ht_cap_t *ht_cap = reinterpret_cast<em_ap_ht_cap_t *>(tlv->value);
            dm_radio_cap_t *radio_cap = dm->get_radio_cap(ht_cap->ruid);

            if ((ht_cap != NULL) && (radio_cap != NULL)){
                em_radio_cap_info_t *cap_info = radio_cap->get_radio_cap_info();
                if ((cap_info == NULL)){
                    em_printfout("No data Found");
                }
                memcpy(&cap_info->ht_cap, ht_cap, sizeof(em_ap_ht_cap_t));

                em_printfout("HT Capabilities MCS Set for RUID %s",
                    util::mac_to_string(ht_cap->ruid).c_str());
                em_printfout("\t\tHT 40MHz Support: %d",
                    cap_info->ht_cap.ht_sprt_40mhz);
                em_printfout("\t\tGI 40MHz Support: %d",
                    cap_info->ht_cap.gi_sprt_40mhz);
                em_printfout("\t\tGI 20MHz Support: %d",
                    cap_info->ht_cap.gi_sprt_20mhz);
                em_printfout("\t\tmax_sprt_rx_streams:%d", cap_info->ht_cap.max_sprt_rx_streams);
                em_printfout("\t\tmax_sprt_tx_streams:%d", cap_info->ht_cap.max_sprt_tx_streams);
                em_printfout("HT Capabilities updated for radio %s", util::mac_to_string(ht_cap->ruid).c_str());
            }
        }
        else if (tlv->type == em_tlv_type_vht_cap){
            em_printfout("Received VHT Capability TLV");
            em_ap_vht_cap_t *vht_cap = reinterpret_cast<em_ap_vht_cap_t *>(tlv->value);
            dm_radio_cap_t *radio_cap = dm->get_radio_cap(vht_cap->ruid);
            if ((vht_cap != NULL) && (radio_cap != NULL)){
                em_radio_cap_info_t *cap_info = radio_cap->get_radio_cap_info();
                if ((cap_info == NULL)){
                    em_printfout("No data Found");
                    return 0;
                }
                memcpy(&cap_info->vht_cap, vht_cap, sizeof(em_ap_vht_cap_t));
            }
        }
        else if (tlv->type == em_tlv_type_he_cap){
            em_printfout("Received HE Capability TLV");
            em_ap_he_cap_t *he_cap = reinterpret_cast<em_ap_he_cap_t *>(tlv->value);
            dm_radio_cap_t *radio_cap = dm->get_radio_cap(he_cap->ruid);

            if ((he_cap != NULL) && (radio_cap != NULL)){
                em_radio_cap_info_t *cap_info = radio_cap->get_radio_cap_info();

                if ((cap_info == NULL)){
                    em_printfout("No data Found");
                    return 0;
                }
                memcpy(&cap_info->he_cap, he_cap, sizeof(em_ap_he_cap_t));
            }
        }
        else if (tlv->type == em_tlv_type_ap_wifi6_cap){
            em_printfout("Received wifi6 Capability TLV");
            handle_wifi6_cap_tlv(tlv->value);
        }
        else if (tlv->type == em_tlv_type_wifi7_agent_cap){
            em_printfout("Received wifi7 Capability TLV");
            handle_wifi7_agent_cap_tlv(tlv->value);
        }
        else if (tlv->type == em_tlv_eht_operations){
            handle_eht_operations_tlv(tlv->value, ntohs(tlv->len));
        }
        else if (tlv->type == em_tlv_type_channel_scan_cap){
            em_printfout("Received Channel Scan Capabilities TLV (0xA5)");
            handle_channel_scan_cap_tlv(tlv->value, ntohs(tlv->len));
        }
        else if (tlv->type == em_tlv_type_1905_layer_security_cap){
        }
        else if (tlv->type == em_tlv_type_cac_cap){
            em_cac_cap_t *cac = reinterpret_cast<em_cac_cap_t *>(tlv->value);
            for (int idx = 0; idx < cac->radios_num; idx++)
            {
                dm_radio_cap_t *radio_cap = dm->get_radio_cap(cac->radios[idx].ruid);
                if ((cac != NULL) && (radio_cap != NULL)){
                    em_radio_cap_info_t *cap_info = radio_cap->get_radio_cap_info();
                    if ((cap_info == NULL)){
                        em_printfout("No data Found");
                        return 0;
                    }
                    memcpy(&cap_info->cac_cap, &cac->radios[0], sizeof(em_cac_cap_t));
                }
            }
        } else if (tlv->type == em_tlv_type_profile_2_ap_cap){
            em_profile_2_ap_cap_t *prof = reinterpret_cast<em_profile_2_ap_cap_t *>(tlv->value);
            dm_radio_cap_t *radio_cap = dm->get_radio_cap(get_radio_interface_mac());
            if (radio_cap != NULL){
            em_radio_cap_info_t *cap_info = radio_cap->get_radio_cap_info();


            if ((prof == NULL) || (cap_info == NULL)){
                em_printfout("No data Found");
                return 0;
            }

            memcpy(&cap_info->prof_2_ap_cap, &prof, sizeof(em_profile_2_ap_cap_t));
            }
        }
        else if (tlv->type == em_tlv_type_metric_cltn_interval){
        } else if (tlv->type == em_tlv_type_device_inventory) {
            //TBD: Address handling of device inventory TLV appropriately
        } else if (tlv->type == em_tlv_type_ap_radio_advanced_cap){
            uint16_t value_len = ntohs(tlv->len);

            if (value_len % sizeof(em_ap_radio_advanced_cap_t) != 0) {
                em_printfout("Invalid TLV length for advanced cap");
                return -1;
            }

            uint16_t count = value_len / sizeof(em_ap_radio_advanced_cap_t);
            uint8_t *adv = tlv->value;
            for (uint16_t i = 0; i < count; ++i) {
                em_ap_radio_advanced_cap_t *ad =
                    reinterpret_cast<em_ap_radio_advanced_cap_t *>(adv);
                    
                dm_radio_cap_t *radio_cap = dm->get_radio_cap(ad->ruid);

                if (radio_cap) {
                    em_radio_cap_info_t *cap_info = radio_cap->get_radio_cap_info();
                    if (cap_info) {
                        memcpy(&cap_info->radio_ad_cap, ad, sizeof(em_ap_radio_advanced_cap_t));
                    }
                 } else {
                    em_printfout("Unknown RUID: %s",
                        util::mac_to_string(ad->ruid).c_str());
                }

                adv += sizeof(em_ap_radio_advanced_cap_t);
            }
        }

        tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    /*if (em_msg_t(em_msg_type_ap_cap_rprt, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("Error: AP Capability Report msg validation failed");
        return -1;
    }*/

    em_printfout("AP Capability Report msg rcvd for radio: %s", util::mac_to_string(get_radio_interface_mac()).c_str());

    return 0;
}

void em_capability_t::process_msg(unsigned char *data, unsigned int len)
{
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));
    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(data);

    switch (htons(cmdu->type)) {
        case em_msg_type_ap_cap_query:
            {
                std::vector<em_t *> em_radios;
                get_mgr()->get_all_em_for_al_mac(hdr->dst, em_radios);
                for (auto &em : em_radios){
                    em_printfout("em_msg_type_ap_cap_query received, state: %s", em_t::state_2_str(em->get_state()));
                    if ((em->get_service_type() == em_service_type_agent) && (em->get_state() < em_state_agent_topo_synchronized)){
                        em_printfout("radio %s is not configured, ignoring", util::mac_to_string(em->get_radio_interface_mac()).c_str());
                        em_radios.clear();
                        return;
                    }
                }
                em_radios.clear();
                em_printfout("All radios are configured for al_mac:%s, sending AP capability response", util::mac_to_string(hdr->dst).c_str());
                if ((get_service_type() == em_service_type_agent)){
                    send_ap_cap_report_msg(data, ntohs(cmdu->id));
                }
            }
            break;
            case em_msg_type_ap_cap_rprt:
                if (get_service_type() == em_service_type_ctrl)
                {
                    if (handle_ap_cap_report(data, len) == 0){
                        set_state(em_state_ctrl_ap_cap_report_received);
                        std::vector<em_t *> em_radios;
                        dm_easy_mesh_t *dm = get_data_model();
                        em_printfout("AP capability report handled successfully by em radio:%s agent al_mac:%s src_mac:%s",
                                     util::mac_to_string(get_radio_interface_mac()).c_str(), util::mac_to_string(dm->get_agent_al_interface_mac()).c_str(),
                                     util::mac_to_string(hdr->src).c_str());
                        get_mgr()->get_all_em_for_al_mac(hdr->src, em_radios);
                        for (auto &em : em_radios)
                        {
                            em->set_state(em_state_ctrl_ap_cap_report_received);
                            em_printfout("em_msg_type_ap_cap_rprt handle success, state: %s", em_t::state_2_str(em->get_state()));
                        }
                        em_radios.clear();
                    } else {
                        em_printfout("em_msg_type_ap_cap_rprt handle failed");
                    }
                }
                break;
            case em_msg_type_client_cap_rprt:
                if (get_service_type() == em_service_type_ctrl){
                    handle_client_cap_report(data, len);
                }
                break;

            case em_msg_type_client_cap_query:
                if (get_service_type() == em_service_type_agent){
                    handle_client_cap_query(data, len);
                }
                break;

            case em_msg_type_bh_sta_cap_query:
                handle_bsta_cap_query(data, len);
                break;

            case em_msg_type_bh_sta_cap_rprt:
                handle_bsta_cap_report(data, len);
                break;

            default:
                break;
            }
}

void em_capability_t::process_ctrl_state()
{
    switch (get_state()) {
        case em_state_ctrl_ap_cap_query_pending:
            {
                std::vector<em_t *> em_radios;
                dm_easy_mesh_t *dm = get_data_model();
                get_mgr()->get_all_em_for_al_mac(dm->get_agent_al_interface_mac(), em_radios);
                for (auto &em : em_radios)
                {
                    if (em->get_state() != em_state_ctrl_ap_cap_query_pending){
                        em_printfout("radio %s is not in AP Capability query pending state, ignoring",
                                     util::mac_to_string(em->get_radio_interface_mac()).c_str());
                        em_radios.clear();
                        return;
                    }
                }
                if (this == em_radios.front()){
                    em_printfout("Sending the AP query message to agent al_mac:%s on radio: %s",
                        util::mac_to_string(dm->get_agent_al_interface_mac()).c_str(),
                        util::mac_to_string(get_radio_interface_mac()).c_str());
                    send_ap_cap_query_msg();
                }
                em_radios.clear();
            }
            break;
        case em_state_ctrl_bsta_cap_pending:
            send_bsta_cap_query_msg();
            break;

        case em_state_ctrl_sta_cap_pending:
            send_client_cap_query();
            break;

        default:
            printf("%s:%d: unhandled case %s\n", __func__, __LINE__, em_t::state_2_str(get_state()));
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

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
#include <algorithm>
#include <memory>
#include <vector>
#include "em.h"
#include "em_msg.h"
#include "em_cmd.h"
#include "em_cmd_exec.h"

int em_steering_t::send_client_assoc_ctrl_req_msg()
{
    em_cmd_t *pcmd = get_current_cmd();
    dm_easy_mesh_t *dm = get_data_model();

    if (!pcmd || !dm)
        return -1;

    em_cmd_client_assoc_params_t *assoc_param = &pcmd->m_param.u.client_assoc_params;

    if (assoc_param->sta_count == 0 || assoc_param->sta_count > MAX_STA_LIST) {
        em_printfout("ERROR: Invalid sta_count=%u (max %u)", assoc_param->sta_count, MAX_STA_LIST);
        set_state(em_state_ctrl_configured);
        return -1;
    }

    if (assoc_param->assoc_control != ASSOC_CONTROL_BLOCK && assoc_param->assoc_control != ASSOC_CONTROL_UNBLOCK) {
        em_printfout("ERROR: Invalid assoc_control=%u. Allowed: 0 (Block), 1 (Unblock)",
                 assoc_param->assoc_control);
        set_state(em_state_ctrl_configured);
        return -1;  // Reject request
    }

    for (unsigned int j = 0; j < dm->m_num_bss; j++) {
        if ((memcmp(assoc_param->bssid, dm->m_bss[j].m_bss_info.bssid.mac, sizeof(mac_address_t)) == 0) &&
         (memcmp(dm->m_bss[j].m_bss_info.ruid.mac, get_radio_interface_mac(), sizeof(mac_address_t)) == 0) &&
         (dm->m_bss[j].m_bss_info.vap_mode == em_vap_mode_ap)) {

            em_client_assoc_ctrl_req_t assoc_ctrl;
            memset(&assoc_ctrl, 0, sizeof(assoc_ctrl));

            memcpy(&assoc_ctrl.bssid, &assoc_param->bssid, sizeof(bssid_t));

            assoc_ctrl.assoc_control  = assoc_param->assoc_control;
            assoc_ctrl.validity_period = htons(assoc_param->validity_period);
            assoc_ctrl.sta_count = assoc_param->sta_count;
            for (uint8_t i = 0; i < assoc_param->sta_count; i++) {
                memcpy(&assoc_ctrl.sta_list[i], &assoc_param->sta_list[i], sizeof(mac_address_t));
            }
            send_client_assoc_ctrl_req_msg(&assoc_ctrl);
            break;
        }
    }

    return 0;
}

int em_steering_t::send_persisted_assoc_ctrl_req(const unsigned char *bssid, unsigned char assoc_control,
            unsigned short validity_period, unsigned char sta_count, const mac_address_t *sta_list)
{
    em_client_assoc_ctrl_req_t assoc_ctrl;

    if ((bssid == NULL) || (sta_list == NULL) || (sta_count == 0) || (sta_count > MAX_STA_LIST)) {
        return -1;
    }

    if ((assoc_control != ASSOC_CONTROL_BLOCK) && (assoc_control != ASSOC_CONTROL_UNBLOCK)) {
        return -1;
    }

    memset(&assoc_ctrl, 0, sizeof(assoc_ctrl));
    memcpy(assoc_ctrl.bssid, bssid, sizeof(bssid_t));
    assoc_ctrl.assoc_control = assoc_control;
    assoc_ctrl.validity_period = htons(validity_period);
    assoc_ctrl.sta_count = sta_count;
    memcpy(assoc_ctrl.sta_list, sta_list, static_cast<size_t> (sta_count) * sizeof(mac_address_t));

    return send_client_assoc_ctrl_req_msg(&assoc_ctrl);
}

int em_steering_t::send_client_assoc_ctrl_req_msg(em_client_assoc_ctrl_req_t *assoc_ctrl)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_client_assoc_ctrl_req;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm;

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

    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_client_assoc_ctrl_req;

    size_t tlv_value_len = sizeof(bssid_t) + sizeof(unsigned char) + sizeof(unsigned short) + sizeof(unsigned char) +
         (static_cast<size_t>(assoc_ctrl->sta_count) * sizeof(mac_address_t));

    memcpy(tlv->value, assoc_ctrl, tlv_value_len);
    tlv->len = htons(tlv_value_len);

    tmp += (sizeof (em_tlv_t) + tlv_value_len);
    len += (sizeof (em_tlv_t) + tlv_value_len);

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_client_assoc_ctrl_req, em_profile_type_3, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        printf("Client Assoc Control Request msg validation failed\n");
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        printf("%s:%d: Client Assoc Control Request msg send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    m_client_assoc_ctrl_req_tx_cnt++;
    m_client_assoc_ctrl_req_msg_id= ntohs(cmdu->id);
    em_printfout("Client Assoc Control Request (%d) Send Successful, msg_id:%u\n", m_client_assoc_ctrl_req_tx_cnt, m_client_assoc_ctrl_req_msg_id);

    return static_cast<int> (len);
}

int em_steering_t::send_client_steering_req_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_client_steering_req;
    short sz = 0;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm;

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

    // 17.2.29 Steering Request TLV/ Profile-2 Steering Request TLV 17.2.57
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_steering_request;
    sz = create_btm_request_tlv(tlv->value);
    tlv->len = htons(static_cast<short unsigned int> (sz));

	tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
	len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_client_steering_req, em_profile_type_2, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        printf("Client Steering Request msg validation failed\n");
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        printf("%s:%d: Client Steering Request msg send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    m_client_steering_req_tx_cnt++;
    printf("%s:%d: Client Steering Request (%d) Send Successful\n", __func__, __LINE__, m_client_steering_req_tx_cnt);

    return static_cast<int> (len);
}

int em_steering_t::send_btm_report_msg(mac_address_t sta, bssid_t bss)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_client_steering_btm_rprt;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
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
    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // 17.2.30 Steering BTM Report TLV format
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_steering_btm_rprt;
    sz = create_btm_report_tlv(tlv->value);
    tlv->len = htons(static_cast<short unsigned int> (sz));

	tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
	len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(em_tlv_t));
    len += (sizeof(em_tlv_t));

    if (em_msg_t(em_msg_type_client_steering_btm_rprt, em_profile_type_3, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        printf("%s:%d: Steering BTM report validation failed\n", __func__, __LINE__);
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        printf("%s:%d: Steering BTM report send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    printf("%s:%d: Steering BTM report send success\n", __func__, __LINE__);

    return static_cast<int> (len);
}

int em_steering_t::send_1905_ack_message(mac_addr_t sta_mac, unsigned short msg_id, unsigned char reason, unsigned char *dst)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_1905_ack;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();
    mac_address_t zero_mac = {0};

    if (memcmp(dm->get_ctrl_al_interface_mac(), zero_mac, sizeof(mac_address_t)) != 0) {
        memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    } else if (dst != nullptr) {
        memcpy(tmp, const_cast<unsigned char *> (dst), sizeof(mac_address_t));
    } else {
        printf("%s:%d: no valid destination MAC address available\n", __func__, __LINE__);
        return 0;
    }
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

    if (reason != 0) {
        //17.2.36 Error Code TLV format
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_error_code;
        sz = create_error_code_tlv(tlv->value, reason, sta_mac);
        tlv->len = htons(static_cast<short unsigned int> (sz));

        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    }

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(em_tlv_t));
    len += (sizeof(em_tlv_t));

    if (em_msg_t(em_msg_type_1905_ack, em_profile_type_3, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        printf("%s:%d: 1905 ACK validation failed\n", __func__, __LINE__);
        return 0;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        printf("%s:%d: 1905 ACK send failed, error:%d\n", __func__, __LINE__, errno);
        return 0;
    }
    printf("%s:%d: 1905 ACK send success\n", __func__, __LINE__);

    return static_cast<int> (len);
}

int em_steering_t::send_consolidated_1905_ack_message(const std::vector<const unsigned char*>& sta_list,
    unsigned short msg_id, unsigned char reason, unsigned char *dst)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_1905_ack;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();
    mac_address_t zero_mac = {0};

    if (sta_list.empty()) {
        em_printfout("%s:%d: Empty STA list provided", __func__, __LINE__);
        return -1;
    }

    if (memcmp(dm->get_ctrl_al_interface_mac(), zero_mac, sizeof(mac_address_t)) != 0) {
        memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    } else if (dst != nullptr) {
        memcpy(tmp, const_cast<unsigned char *> (dst), sizeof(mac_address_t));
    } else {
        em_printfout("%s:%d: no valid destination MAC address available", __func__, __LINE__);
        return 0;
    }
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

    // Add Error Code TLVs (only needed when reason != 0)
    if (reason != 0) {
        for (const auto *sta_mac : sta_list) {
            const short err_sz = static_cast<short>(sizeof(unsigned char) + sizeof(mac_address_t));
            if (len + sizeof(em_tlv_t) + static_cast<size_t>(err_sz) + sizeof(em_tlv_t) > MAX_EM_BUFF_SZ) {
               em_printfout("%s:%d: Buffer overflow - too many STAs in single message", __func__, __LINE__);
               return -1;
            }
            // 17.2.36 Error Code TLV format
            tlv = reinterpret_cast<em_tlv_t *>(tmp);
            tlv->type = em_tlv_type_error_code;
            sz = create_error_code_tlv(tlv->value, reason, sta_mac);
            tlv->len = htons(static_cast<short unsigned int>(sz));
            tmp += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
            len += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
        }
    }

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(em_tlv_t));
    len += (sizeof(em_tlv_t));

    if (em_msg_t(em_msg_type_1905_ack, em_profile_type_3, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        em_printfout("%s:%d: Consolidated 1905 ACK validation failed", __func__, __LINE__);
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        em_printfout("%s:%d: Consolidated 1905 ACK send failed, error:%d", __func__, __LINE__, errno);
        return -1;
    }
    em_printfout("%s:%d: Consolidated 1905 ACK send success for %zu STAs", __func__, __LINE__, sta_list.size());

    return static_cast<int> (len);
}

short em_steering_t::create_btm_request_tlv(unsigned char *buff)
{
    size_t len = 0;
    em_steering_req_t *req = reinterpret_cast<em_steering_req_t *> (buff);
    em_cmd_steer_params_t *params = &get_current_cmd()->m_param.u.steer_params;

    memcpy(&req->bssid, get_data_model()->m_bss[0].m_bss_info.bssid.mac, sizeof(bssid_t));
    req->req_mode                           = static_cast<unsigned char>(params->request_mode) & 0x01;
    req->btm_dissoc_imminent                = params->disassoc_imminent;
    req->btm_abridged                       = params->btm_abridged;
    req->btm_link_removal_imminent = params->link_removal_imminent;
    if(params->request_mode == 1)
    {
        //ignore this
    req->steering_opportunity_window        = 0;
    } else {
        req->steering_opportunity_window    = static_cast<short unsigned int> (params->steer_opportunity_win);
    }
    req->btm_dissoc_timer                   = htons(static_cast<uint16_t> (params->btm_disassociation_timer));
    req->sta_list_count                     = 1;
    memcpy(req->sta_mac_addr, params->sta_mac, sizeof(mac_addr_t));
    req->target_bssid_list_count            = 1;
    memcpy(req->target_bssids, params->target, sizeof(mac_addr_t));
    req->target_bss_op_class                = static_cast<unsigned char> (params->target_op_class);
    req->target_bss_channel_num             = static_cast<unsigned char> (params->target_channel);

    len += sizeof(em_steering_req_t);

    return static_cast<short> (len);
}

short em_steering_t::create_btm_report_tlv(unsigned char *buff)
{
    short len = 0;
    unsigned char *tmp = buff;
    em_cmd_t *pcmd = get_current_cmd();
    em_cmd_btm_report_params_t  *btm_report_param = &pcmd->m_param.u.btm_report_params;

    memcpy(tmp, &btm_report_param->source, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<short> (sizeof(mac_address_t));

    memcpy(tmp, &btm_report_param->sta_mac, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<short> (sizeof(mac_address_t));

    memcpy(tmp, &btm_report_param->status_code, sizeof(char));
    tmp += sizeof(char);
    len += static_cast<short> (sizeof(char));

    //todo: create bss list dynamically
    /*memcpy(tmp, btm_report_param->target, sizeof(mac_address_t));
    tmp += (sizeof(em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof(em_tlv_t) + sizeof(mac_address_t));*/

    return len;
}

short em_steering_t::create_error_code_tlv(unsigned char *buff, int val, const mac_addr_t sta_mac)
{
    short len = 0;
    unsigned char *tmp = buff;

    memcpy(tmp, &val, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    len += static_cast<short> (sizeof(unsigned char));

    memcpy(tmp, sta_mac, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<short> (sizeof(mac_address_t));

    return len;
}

int em_steering_t::handle_client_steering_req(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_steering_req_t *steer_req;
    mac_addr_str_t mac_str;

    if (em_msg_t(em_msg_type_client_steering_req, em_profile_type_2, buff, len).validate(errors) == 0) {
        printf("%s:%d:Client Steering Request message validation failed\n",__func__,__LINE__);
        return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    steer_req =  reinterpret_cast<em_steering_req_t *> (&tlv->value);
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));

    dm_easy_mesh_t::macbytes_to_string(steer_req->sta_mac_addr, mac_str);
    printf("%s:%d Recived steer req for sta=%s\n", __func__, __LINE__, mac_str);
    
	get_mgr()->io_process(em_bus_event_type_bss_tm_req, reinterpret_cast<unsigned char *> (steer_req), sizeof(em_steering_req_t));

    send_1905_ack_message(steer_req->sta_mac_addr, ntohs(cmdu->id));

    return 0;
}

int em_steering_t::handle_client_steering_report(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_steering_btm_rprt_t *btm_rprt;

    if (em_msg_t(em_msg_type_client_steering_btm_rprt, em_profile_type_2, buff, len).validate(errors) == 0) {
        printf("%s:%d:Client Steering Request message validation failed\n",__func__,__LINE__);
        return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    btm_rprt = reinterpret_cast<em_steering_btm_rprt_t *> (&tlv->value);

    mac_addr_str_t mac_str;
    dm_easy_mesh_t::macbytes_to_string(btm_rprt->sta_mac_addr, mac_str);
    printf("%s:%d Client BTM Report for sta %s, status %d\n", __func__, __LINE__, mac_str, btm_rprt->btm_status_code);

    set_state(em_state_ctrl_configured);

    //send ack for report rcvd
    //send_1905_ack_message(btm_rprt->sta_mac_addr);

    return 0;
}

int em_steering_t::handle_ack_msg(unsigned char *buff, unsigned int len)
{
    std::vector<em_t *> em_radios;
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));
    unsigned short response_msg_id = ntohs(cmdu->id);
    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(buff);
    bool rejected = ack_has_error_code(buff, len);
    get_mgr()->get_all_em_for_al_mac(hdr->src, em_radios);

    for (auto &em : em_radios)
    {
        //check for null em pointer in vector
        if (em == NULL) {
            em_printfout("Warning: Null em pointer in vector, skipping");
            continue;
        }

        if (em->get_state() == em_state_ctrl_acl_cfg_pending) {
            // The radio's own replay step moves it on once every chunk is acknowledged
            if (em->handle_acl_cfg_ack(response_msg_id, rejected)) {
                em_printfout("ACL replay ACK (msg_id:%u) handled for radio %s", response_msg_id,
                        util::mac_to_string(em->get_radio_interface_mac()).c_str());
            }
        } else if ((em->get_state() == em_state_ctrl_client_assoc_ctrl_req_pending) &&
            (response_msg_id == em->get_client_assoc_ctrl_req_msg_id())) {

            // Recorded before the state change that lets orch fini read it
            if (rejected) {
                em->note_cacr_refused(buff, len);
            }
            em->set_state(em_state_ctrl_configured);
            em->clear_client_assoc_ctrl_req_msg_id();
            em_printfout("CACR ACK handled for radio %s", util::mac_to_string(em->get_radio_interface_mac()).c_str());

        } else if (em->get_state() == em_state_ctrl_sta_steer_pending) {

            em->set_state(em_state_ctrl_steer_btm_req_ack_rcvd);
            em_printfout("Steering ACK handled for radio %s", util::mac_to_string(em->get_radio_interface_mac()).c_str());
       }
    }
    em_radios.clear();
    return 0;
}

// True when bssid is one of this agent's AP BSSs that keeps a whitelist (backhaul). Same rule as
// the controller's ACL persistence: the stored mode, or the haul type while the mode is unknown.
static bool is_local_whitelist_bss(dm_easy_mesh_t *dm, const unsigned char *bssid)
{
    for (unsigned int i = 0; (dm != NULL) && (i < dm->get_num_bss()); i++) {
        em_bss_info_t *info = dm->get_bss_info(i);

        if ((info == NULL) || (info->vap_mode != em_vap_mode_ap) ||
                (memcmp(info->bssid.mac, bssid, sizeof(mac_address_t)) != 0)) {
            continue;
        }
        return (info->acl_filter_mode == EM_ACL_MODE_WHITELIST) ||
            ((info->acl_filter_mode == EM_ACL_MODE_UNKNOWN) && (info->id.haul_type == em_haul_type_backhaul));
    }
    return false;
}

int em_steering_t::handle_client_assoc_ctrl_req(unsigned char *buff, unsigned int len)
{
    em_printfout("Received Client Assoc Control Request from Controller");

    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_client_assoc_ctrl_req_t *assoc_ctrl_req;

    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *> (buff);
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));
    unsigned short msg_id = ntohs(cmdu->id);
    dm_easy_mesh_t *dm = get_data_model();

    if (em_msg_t(em_msg_type_client_assoc_ctrl_req, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("Client Association Control Request message validation failed");
        return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    assoc_ctrl_req = reinterpret_cast<em_client_assoc_ctrl_req_t *>(tlv->value);

    const uint16_t assoc_tlv_len = ntohs(tlv->len);
    const size_t fixed_len = sizeof(bssid_t) + sizeof(unsigned char) + sizeof(unsigned short) + sizeof(unsigned char);
    if (assoc_tlv_len < fixed_len) {
        em_printfout("invalid ClientAssocCtrlRequest TLV (tlv_len=%u expected_min=%zu)", assoc_tlv_len, fixed_len);
        return -1;
    }
    const uint8_t sta_count = assoc_ctrl_req->sta_count;
    const size_t expected_len = fixed_len + (static_cast<size_t>(sta_count) * sizeof(mac_address_t));
    if (sta_count == 0 || sta_count > MAX_STA_LIST || assoc_tlv_len < expected_len) {
        em_printfout("invalid ClientAssocCtrlRequest TLV (sta_count=%u tlv_len=%u expected_min=%zu max=%u)",
            sta_count, assoc_tlv_len, expected_len, MAX_STA_LIST);
        return -1;
    }

    // Collect indices of associated and unassociated STAs
    std::vector<uint8_t> associated_sta_indices;

    if ((assoc_ctrl_req->assoc_control == ASSOC_CONTROL_BLOCK) &&
            is_local_whitelist_bss(dm, assoc_ctrl_req->bssid)) {
        // Backhaul whitelist: BLOCK revokes the bSTA's allow entry and disconnects it if it is
        // associated (OneWifi removes the entry, then kicks), so an associated bSTA is the case it
        // exists for, not an error. Rejecting it would leave a revoked agent (e.g. one removed
        // from the network) allowed in the parent's live whitelist.
        send_1905_ack_message(assoc_ctrl_req->sta_list[0], msg_id, 0, hdr->src);
    } else if (assoc_ctrl_req->assoc_control == ASSOC_CONTROL_BLOCK) {

        // Fronthaul: a Block does not apply to an associated STA (Error Code TLV, nothing applied)
        for (uint8_t i = 0; i < sta_count; i++) {
            mac_address_t sta_mac;
            memcpy(sta_mac, assoc_ctrl_req->sta_list[i], sizeof(mac_address_t));

            if (dm->is_sta_associated(assoc_ctrl_req->bssid, sta_mac)) {
                associated_sta_indices.push_back(i);
            }
        }

        if (!associated_sta_indices.empty()) {
            std::vector<const unsigned char*> list;
            for (auto idx : associated_sta_indices) {
                list.push_back(assoc_ctrl_req->sta_list[idx]);
            }
            em_printfout("sending ack with error code tlv");
            send_consolidated_1905_ack_message(list, msg_id, 1, hdr->src);

            // The Error Code TLVs name the STAs not blocked; the others in the request still are
            em_client_assoc_ctrl_req_t unassociated;
            memcpy(&unassociated, assoc_ctrl_req, fixed_len);
            unassociated.sta_count = 0;
            for (uint8_t i = 0; i < sta_count; i++) {
                if (std::find(associated_sta_indices.begin(), associated_sta_indices.end(), i) ==
                        associated_sta_indices.end()) {
                    memcpy(unassociated.sta_list[unassociated.sta_count++], assoc_ctrl_req->sta_list[i],
                        sizeof(mac_address_t));
                }
            }
            if (unassociated.sta_count != 0) {
                get_mgr()->io_process(em_bus_event_type_client_assoc_ctrl_req,
                    reinterpret_cast<unsigned char *> (&unassociated),
                    static_cast<unsigned int> (fixed_len + (unassociated.sta_count * sizeof(mac_address_t))));
            }
            return 0;
        } else {
             // No Error Code TLV needed when all requested STAs are unassociated.
             send_1905_ack_message(assoc_ctrl_req->sta_list[0], msg_id, 0, hdr->src);
        }
    } else if (assoc_ctrl_req->assoc_control == ASSOC_CONTROL_UNBLOCK) {
        std::vector<const unsigned char*> list;
        for (uint8_t i = 0; i < sta_count; i++) {
            list.push_back(assoc_ctrl_req->sta_list[i]);
        }

        send_consolidated_1905_ack_message(list, msg_id, 0, hdr->src);
    } else {
        em_printfout("invalid assoc_control=%u (allowed: 0=Block, 1=Unblock)",
            assoc_ctrl_req->assoc_control);
        return -1;
    }
    // Send the association control request to OneWifi for HAL enforcement
    uint16_t tlv_len = ntohs(tlv->len);
    get_mgr()->io_process(em_bus_event_type_client_assoc_ctrl_req,
        reinterpret_cast<unsigned char *> (assoc_ctrl_req), tlv_len);

    return 0;
}

void em_steering_t::queue_acl_list(const char *bss_key, const unsigned char *bssid,
            unsigned short validity_period, bool blocked)
{
    // A BSS holds at most EM_MAX_ACL_JSON_STAS entries: take them in one pass (a consistent
    // snapshot, no rescan per chunk), on the heap as this runs on the em thread
    std::unique_ptr<mac_address_t[]> macs(new mac_address_t[EM_MAX_ACL_JSON_STAS]);
    std::vector<unsigned short> remaining(EM_MAX_ACL_JSON_STAS);
    unsigned int num, i, start, end;
    unsigned char control = blocked ? ASSOC_CONTROL_BLOCK : ASSOC_CONTROL_UNBLOCK;

    // Expired timed blocks are not returned; a timed block is replayed with only its remaining
    // time, so a re-onboarding never restarts the full period.
    num = get_mgr()->get_bss_acl_macs(bss_key, blocked, 0, EM_MAX_ACL_JSON_STAS, macs.get(),
            remaining.data());

    // The Client Association Control TLV carries at most MAX_STA_LIST STAs and a single period,
    // so queue one request per run of at most MAX_STA_LIST STAs sharing the same period
    for (start = 0; start < num; start = i) {
        unsigned short period = blocked ? remaining[start] : validity_period;
        end = ((num - start) > MAX_STA_LIST) ? (start + MAX_STA_LIST) : num;
        i = start + 1;
        while ((i < end) && (!blocked || (remaining[i] == period))) {
            i++;
        }

        em_acl_cfg_chunk_t chunk;
        memset(&chunk, 0, sizeof(chunk));
        memcpy(chunk.bssid, bssid, sizeof(bssid_t));
        chunk.assoc_control = control;
        chunk.validity_period = period;
        if (blocked && (period != 0)) {
            struct timeval now;
            util::monotonic_now(&now);
            chunk.expiry = now.tv_sec + period;
        }
        chunk.sta_count = static_cast<unsigned char> (i - start);
        memcpy(chunk.sta_list, &macs[start], static_cast<size_t> (chunk.sta_count) * sizeof(mac_address_t));
        m_acl_cfg_chunks.push_back(chunk);
    }
}

int em_steering_t::queue_persisted_acl_cfg()
{
    dm_easy_mesh_t *dm = get_data_model();
    em_2xlong_string_t bss_key;

    if (dm == NULL) {
        em_printfout("Cannot send persisted ACL configuration: data model is unavailable");
        return -1;
    }

    for (unsigned int i = 0; i < dm->m_num_bss; i++) {
        em_bss_info_t *info = &dm->m_bss[i].m_bss_info;

        if ((memcmp(info->ruid.mac, get_radio_interface_mac(), sizeof(mac_address_t)) != 0) ||
                (info->vap_mode != em_vap_mode_ap)) {
            continue;
        }

        dm_bss_t::make_bss_key(info, bss_key, sizeof(bss_key));

        // Whitelist (backhaul): only the allowed list is meaningful, permanent (validity 0).
        // Blacklist (fronthaul): only the blocked list is meaningful, with its validity period.
        // A mode not known yet (row from an older build) follows the haul type, as CACR persistence does.
        bool whitelist = (info->acl_filter_mode == EM_ACL_MODE_WHITELIST) ||
                ((info->acl_filter_mode == EM_ACL_MODE_UNKNOWN) && (info->id.haul_type == em_haul_type_backhaul));
        if (whitelist) {
            // Until this allowed list reaches the agent, its whitelist BSS denies every child
            // STA (including after a VAP recreate), so log the start of that window.
            em_printfout("Sending persisted allowed list to whitelist BSS %s; children are denied until it is acknowledged",
                    bss_key);
            queue_acl_list(bss_key, info->bssid.mac, 0, false);
        } else {
            queue_acl_list(bss_key, info->bssid.mac, 0, true);
        }
    }

    return 0;
}

void em_steering_t::send_unacked_acl_cfg_chunks()
{
    struct timeval now;

    util::monotonic_now(&now);
    for (auto &chunk : m_acl_cfg_chunks) {
        if (chunk.acked) {
            continue;
        }
        // A timed block carries only the time left, so a resend never extends it. Once expired it
        // is dropped: validity 0 would make it permanent.
        if (chunk.expiry != 0) {
            if (chunk.expiry <= now.tv_sec) {
                em_printfout("Blocked ACL chunk for BSS %s (%u STAs) expired before it was acknowledged, dropped",
                        util::mac_to_string(chunk.bssid).c_str(), chunk.sta_count);
                chunk.acked = true;
                continue;
            }
            chunk.validity_period = static_cast<unsigned short> (chunk.expiry - now.tv_sec);
        }
        // A chunk that fails to go out stays unacknowledged and is sent again next round
        if (send_persisted_assoc_ctrl_req(chunk.bssid, chunk.assoc_control, chunk.validity_period,
                chunk.sta_count, chunk.sta_list) <= 0) {
            em_printfout("Failed sending %s ACL chunk for BSS %s (round %u)",
                    (chunk.assoc_control == ASSOC_CONTROL_BLOCK) ? "blocked" : "allowed",
                    util::mac_to_string(chunk.bssid).c_str(), m_acl_cfg_tx_cnt + 1);
            continue;
        }
        if (chunk.num_msg_ids < EM_MAX_ACL_CFG_TX_THRESH) {
            chunk.msg_ids[chunk.num_msg_ids++] = get_client_assoc_ctrl_req_msg_id();
        }
    }
}

void em_steering_t::process_acl_cfg()
{
    unsigned int unacked = 0;

    pthread_mutex_lock(&m_acl_cfg_lock);

    if (!m_acl_cfg_built) {
        if (queue_persisted_acl_cfg() == 0) {
            m_acl_cfg_built = true;
        } else if (++m_acl_cfg_tx_cnt >= EM_MAX_ACL_CFG_TX_THRESH) {
            em_printfout("Persisted ACL configuration failed for radio %s: ACL could not be read",
                    util::mac_to_string(get_radio_interface_mac()).c_str());
            m_acl_cfg_chunks.clear();
            m_acl_cfg_tx_cnt = 0;
            set_state(em_state_ctrl_acl_cfg_failed);
            pthread_mutex_unlock(&m_acl_cfg_lock);
            return;
        } else {
            pthread_mutex_unlock(&m_acl_cfg_lock);
            return;
        }
    }

    for (const auto &chunk : m_acl_cfg_chunks) {
        if (!chunk.acked) {
            unacked++;
        }
    }

    if (unacked == 0) {
        em_printfout("Persisted ACL configuration acknowledged for radio %s (%zu chunks)",
                util::mac_to_string(get_radio_interface_mac()).c_str(), m_acl_cfg_chunks.size());
        m_acl_cfg_chunks.clear();
        m_acl_cfg_tx_cnt = 0;
        m_acl_cfg_built = false;
        set_state(em_state_ctrl_acl_cfg_configured);
    } else if (m_acl_cfg_tx_cnt >= EM_MAX_ACL_CFG_TX_THRESH) {
        // Bounded: hand the radio back (orch fini moves acl_cfg_failed to configured). The next
        // onboarding of this agent replays the whole ACL again.
        for (const auto &chunk : m_acl_cfg_chunks) {
            if (!chunk.acked) {
                em_printfout("Persisted %s ACL chunk for BSS %s (%u STAs) not acknowledged after %u tries",
                        (chunk.assoc_control == ASSOC_CONTROL_BLOCK) ? "blocked" : "allowed",
                        util::mac_to_string(chunk.bssid).c_str(), chunk.sta_count, m_acl_cfg_tx_cnt);
            }
        }
        em_printfout("Persisted ACL configuration failed for radio %s: %u of %zu chunks unacknowledged",
                util::mac_to_string(get_radio_interface_mac()).c_str(), unacked, m_acl_cfg_chunks.size());
        m_acl_cfg_chunks.clear();
        m_acl_cfg_tx_cnt = 0;
        m_acl_cfg_built = false;
        set_state(em_state_ctrl_acl_cfg_failed);
    } else {
        send_unacked_acl_cfg_chunks();
        m_acl_cfg_tx_cnt++;
    }

    pthread_mutex_unlock(&m_acl_cfg_lock);
}

void em_steering_t::reset_acl_cfg()
{
    pthread_mutex_lock(&m_acl_cfg_lock);
    m_acl_cfg_chunks.clear();
    m_acl_cfg_tx_cnt = 0;
    m_acl_cfg_built = false;
    pthread_mutex_unlock(&m_acl_cfg_lock);
}

bool em_steering_t::handle_acl_cfg_ack(unsigned short msg_id, bool rejected)
{
    bool found = false;

    pthread_mutex_lock(&m_acl_cfg_lock);
    for (auto &chunk : m_acl_cfg_chunks) {
        for (unsigned int i = 0; (i < chunk.num_msg_ids) && !found; i++) {
            found = (chunk.msg_ids[i] == msg_id);
        }
        if (!found) {
            continue;
        }
        if (!chunk.acked && rejected) {
            // Only a fronthaul Block is refused, and only for a listed STA that is associated: the
            // agent blocks the others. Resending would be refused again, so it counts as answered;
            // the stored block stays, for the next replay.
            em_printfout("Agent did not block the associated STA(s) of persisted ACL chunk for BSS %s (msg_id:%u)",
                    util::mac_to_string(chunk.bssid).c_str(), msg_id);
        }
        chunk.acked = true;
        break;
    }
    pthread_mutex_unlock(&m_acl_cfg_lock);

    return found;
}

void em_steering_t::note_cacr_refused(unsigned char *buff, unsigned int len)
{
    const size_t hdr_len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    // Error Code TLV value: reason code, then the STA MAC (create_error_code_tlv)
    const size_t err_len = sizeof(unsigned char) + sizeof(mac_address_t);
    unsigned char *tmp;
    size_t left;

    pthread_mutex_lock(&m_acl_cfg_lock);
    m_cacr_num_refused = 0;
    if (len > hdr_len) {
        tmp = buff + hdr_len;
        left = len - hdr_len;
        while (left >= sizeof(em_tlv_t)) {
            em_tlv_t *tlv = reinterpret_cast<em_tlv_t *> (tmp);
            size_t tlv_len = sizeof(em_tlv_t) + ntohs(tlv->len);

            if ((tlv->type == em_tlv_type_eom) || (tlv_len > left)) {
                break;
            }
            if ((tlv->type == em_tlv_type_error_code) && (ntohs(tlv->len) >= err_len) &&
                    (m_cacr_num_refused < MAX_STA_LIST)) {
                memcpy(m_cacr_refused[m_cacr_num_refused++], tlv->value + sizeof(unsigned char),
                    sizeof(mac_address_t));
            }
            tmp += tlv_len;
            left -= tlv_len;
        }
    }
    pthread_mutex_unlock(&m_acl_cfg_lock);
}

unsigned int em_steering_t::take_cacr_refused(mac_address_t *macs)
{
    unsigned int num;

    pthread_mutex_lock(&m_acl_cfg_lock);
    num = m_cacr_num_refused;
    if (macs != NULL) {
        memcpy(macs, m_cacr_refused, num * sizeof(mac_address_t));
    }
    m_cacr_num_refused = 0;
    pthread_mutex_unlock(&m_acl_cfg_lock);
    return num;
}

bool em_steering_t::ack_has_error_code(unsigned char *buff, unsigned int len)
{
    const size_t hdr_len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    unsigned char *tmp;
    size_t left;

    if (len <= hdr_len) {
        return false;
    }
    tmp = buff + hdr_len;
    left = len - hdr_len;

    while (left >= sizeof(em_tlv_t)) {
        em_tlv_t *tlv = reinterpret_cast<em_tlv_t *> (tmp);
        size_t tlv_len = sizeof(em_tlv_t) + ntohs(tlv->len);

        if ((tlv->type == em_tlv_type_eom) || (tlv_len > left)) {
            break;
        }
        if (tlv->type == em_tlv_type_error_code) {
            return true;
        }
        tmp += tlv_len;
        left -= tlv_len;
    }

    return false;
}

void em_steering_t::process_ctrl_state()
{
    switch (get_state()) {
        case em_state_ctrl_sta_steer_pending:
            send_client_steering_req_msg();
            break;

        case em_state_ctrl_client_assoc_ctrl_req_pending:
            send_client_assoc_ctrl_req_msg();
            break;

        case em_state_ctrl_acl_cfg_pending:
            process_acl_cfg();
            break;

        default:
            break;
    }
}

void em_steering_t::process_agent_state()
{
    switch (get_state()) {
        case em_state_agent_steer_btm_res_pending:
            send_btm_report_msg(get_radio_interface_mac(), get_radio_interface_mac());
            break;

        default:
            break;
    }
}

void em_steering_t::process_msg(unsigned char *data, unsigned int len)
{
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));

    switch (htons(cmdu->type)) {
        case em_msg_type_client_steering_req:
            handle_client_steering_req(data, len);
            break;

        case em_msg_type_client_steering_btm_rprt:
            handle_client_steering_report(data, len);
            break;

        case em_msg_type_client_assoc_ctrl_req:
            handle_client_assoc_ctrl_req(data, len);
            break;

        case em_msg_type_1905_ack:
            handle_ack_msg(data, len);
            break;

        default:
            break;
    }
}

em_steering_t::em_steering_t()
{
    m_client_steering_req_tx_cnt = 0;
    m_client_assoc_ctrl_req_tx_cnt = 0;
    m_acl_cfg_tx_cnt = 0;
    m_acl_cfg_built = false;
    m_cacr_num_refused = 0;
    pthread_mutex_init(&m_acl_cfg_lock, NULL);
}

em_steering_t::~em_steering_t()
{
    pthread_mutex_destroy(&m_acl_cfg_lock);
}

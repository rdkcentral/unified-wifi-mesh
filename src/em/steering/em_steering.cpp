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
#include "em_msg.h"
#include "em_cmd.h"
#include "em_cmd_exec.h"

int em_steering_t::send_client_assoc_ctrl_req_msg()
{
    em_cmd_t *pcmd = get_current_cmd();
    dm_easy_mesh_t *dm = get_data_model();

    if (!pcmd || !dm)
        return -1;

    for (unsigned int i = 0; i < pcmd->m_param.u.disassoc_params.num; i++) {
        em_disassoc_params_t *disassoc_param = &pcmd->m_param.u.disassoc_params.params[i];

        for (unsigned int j = 0; j < dm->m_num_bss; j++) {
            if ((memcmp(disassoc_param->bssid, dm->m_bss[j].m_bss_info.bssid.mac, sizeof(bssid_t)) == 0) &&
                (memcmp(dm->m_bss[j].m_bss_info.ruid.mac, get_radio_interface_mac(), sizeof(mac_address_t)) == 0)) {

                em_client_assoc_ctrl_req_t assoc_ctrl;
                memset(&assoc_ctrl, 0, sizeof(assoc_ctrl));

                memcpy(&assoc_ctrl.bssid, &disassoc_param->bssid, sizeof(bssid_t));
                //Current Implementation for One Sta Per Message
                assoc_ctrl.count = 1;
                memcpy(&assoc_ctrl.sta_mac, &disassoc_param->sta_mac, sizeof(mac_address_t));

                if (disassoc_param->disassoc_time > 0) {
                    // BLOCK
                    assoc_ctrl.assoc_control  = 0x00;
                    assoc_ctrl.validity_period = htons(static_cast<uint16_t>(disassoc_param->disassoc_time));
                } else {
                    // UNBLOCK
                    assoc_ctrl.assoc_control  = 0x01;
                    assoc_ctrl.validity_period = 0;
                }

                send_client_assoc_ctrl_req_msg(&assoc_ctrl);
            }
        }
    }

    set_state(em_state_ctrl_configured);
    return 0;
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

    if (assoc_ctrl->count != 1) {
        em_printfout("assoc_ctrl count=%d unsupported", assoc_ctrl->count);
        return -1;
    }

    size_t tlv_value_len = sizeof(em_client_assoc_ctrl_req_t);
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
    printf("%s:%d: Client Assoc Control Request (%d) Send Successful\n", __func__, __LINE__, m_client_assoc_ctrl_req_tx_cnt);

    return static_cast<int> (len);
}

int em_steering_t::send_bh_steering_req_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short msg_type = em_msg_type_bh_steering_req;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm;
    em_bh_steering_req_t *bh_req;
    em_cmd_backhaul_steer_params_t *params;
    mac_addr_str_t sta_str, bssid_str, al_str;

    dm = get_data_model();
    params = &get_current_cmd()->m_param.u.backhaul_steer_params;

    dm_easy_mesh_t::macbytes_to_string(params->sta_mac, sta_str);
    dm_easy_mesh_t::macbytes_to_string(params->target_bssid, bssid_str);
    dm_easy_mesh_t::macbytes_to_string(params->al_mac, al_str);
    em_printfout("Sending BH Steering Request: dst_al=%s sta=%s target_bssid=%s op_class=%d channel=%d",
        al_str, sta_str, bssid_str, params->op_class, params->channel);

    memcpy(tmp, params->al_mac, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, reinterpret_cast<unsigned char *>(&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *>(tmp);
    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_bh_steering_req;
    bh_req = reinterpret_cast<em_bh_steering_req_t *>(tlv->value);
    memcpy(bh_req->bh_sta_mac_addr, params->sta_mac, sizeof(mac_address_t));
    memcpy(bh_req->target_bssid, params->target_bssid, sizeof(bssid_t));
    bh_req->op_class = static_cast<unsigned char>(params->op_class);
    bh_req->channel_numb = static_cast<unsigned char>(params->channel);
    tlv->len = htons(sizeof(em_bh_steering_req_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_bh_steering_req_t));
    len += (sizeof(em_tlv_t) + sizeof(em_bh_steering_req_t));

    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;
    tmp += sizeof(em_tlv_t);
    len += sizeof(em_tlv_t);

    if (em_msg_t(em_msg_type_bh_steering_req, em_profile_type_2, buff, static_cast<unsigned int>(len)).validate(errors) == 0) {
        em_printfout("BH Steering Request msg validation failed");
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int>(len)) < 0) {
        em_printfout("BH Steering Request send failed: errno=%d", errno);
        return -1;
    }

    return static_cast<int>(len);
}

int em_steering_t::handle_bh_steering_rsp(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_bh_steering_resp_t *bh_rsp;
    mac_addr_str_t mac_str;

    if (em_msg_t(em_msg_type_bh_steering_rsp, em_profile_type_2, buff, len).validate(errors) == 0) {
        em_printfout("BH Steering Response validation failed");
        return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    bh_rsp = reinterpret_cast<em_bh_steering_resp_t *>(tlv->value);

    mac_addr_str_t bssid_str;
    dm_easy_mesh_t::macbytes_to_string(bh_rsp->bh_sta_mac_addr, mac_str);
    dm_easy_mesh_t::macbytes_to_string(bh_rsp->target_bssid, bssid_str);
    em_printfout("BH Steering Response received: sta=%s target_bssid=%s result=%d",
        mac_str, bssid_str, bh_rsp->result_code);

    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *>(buff + sizeof(em_raw_hdr_t));
    send_1905_ack_to_agent(ntohs(cmdu->id));

    set_state(em_state_ctrl_configured);
    return 0;
}

int em_steering_t::send_1905_ack_to_agent(unsigned short msg_id)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short msg_type = em_msg_type_1905_ack;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, reinterpret_cast<unsigned char *>(&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *>(tmp);
    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id   = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len  = 0;
    tmp += sizeof(em_tlv_t);
    len += sizeof(em_tlv_t);

    if (em_msg_t(em_msg_type_1905_ack, em_profile_type_3, buff, static_cast<unsigned int>(len)).validate(errors) == 0) {
        em_printfout("ACK (ctrl -> agent) validation failed");
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int>(len)) < 0) {
        em_printfout("ACK (ctrl -> agent) send failed: errno=%d", errno);
        return -1;
    }

    em_printfout("ACK sent to agent (msg_id=0x%04x)", msg_id);
    return static_cast<int>(len);
}

int em_steering_t::handle_bh_steering_req(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_bh_steering_req_t *bh_req;
    em_cmdu_t *cmdu;
    mac_addr_str_t mac_str, bssid_str;

    if (em_msg_t(em_msg_type_bh_steering_req, em_profile_type_2, buff, len).validate(errors) == 0) {
        em_printfout("BH Steering Request validation failed");
        return -1;
    }

    cmdu = reinterpret_cast<em_cmdu_t *>(buff + sizeof(em_raw_hdr_t));
    tlv  = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    bh_req = reinterpret_cast<em_bh_steering_req_t *>(tlv->value);

    dm_easy_mesh_t::macbytes_to_string(bh_req->bh_sta_mac_addr, mac_str);
    dm_easy_mesh_t::macbytes_to_string(bh_req->target_bssid, bssid_str);
    em_printfout("BH Steering Request received: sta=%s target_bssid=%s op_class=%d channel=%d",
        mac_str, bssid_str, bh_req->op_class, bh_req->channel_numb);

    send_1905_ack_message(bh_req->bh_sta_mac_addr, ntohs(cmdu->id));

    get_mgr()->io_process(em_bus_event_type_backhaul_steer,
                          reinterpret_cast<unsigned char *>(bh_req),
                          sizeof(em_bh_steering_req_t));

    // Save context for the timeout callback.
    memcpy(m_bh_steer_pending_sta_mac, bh_req->bh_sta_mac_addr, sizeof(mac_address_t));
    memcpy(m_bh_steer_pending_bssid,   bh_req->target_bssid,    sizeof(bssid_t));

    // Orchestration timeout (EM_MAX_CMD_GEN_TTL) will send the failure response
    // if no result arrives from OneWifi. See em_orch_agent_t::pre_process_cancel().
    set_state(em_state_agent_bh_steer_pending);

    return 0;
}

int em_steering_t::send_bh_steering_rsp_msg(mac_address_t sta_mac, unsigned char *target_bssid,
                                             unsigned char result_code, unsigned char error_reason)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short msg_type = em_msg_type_bh_steering_rsp;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm;
    em_bh_steering_resp_t *bh_rsp;
    mac_addr_str_t sta_str, bssid_str;

    dm = get_data_model();
    dm_easy_mesh_t::macbytes_to_string(sta_mac, sta_str);
    dm_easy_mesh_t::macbytes_to_string(target_bssid, bssid_str);
    em_printfout("Sending BH Steering Response: sta=%s target_bssid=%s result=0x%02x",
        sta_str, bssid_str, result_code);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, reinterpret_cast<unsigned char *>(&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *>(tmp);
    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_bh_steering_rsp;
    bh_rsp = reinterpret_cast<em_bh_steering_resp_t *>(tlv->value);
    memcpy(bh_rsp->bh_sta_mac_addr, sta_mac, sizeof(mac_address_t));
    memcpy(bh_rsp->target_bssid, target_bssid, sizeof(bssid_t));
    bh_rsp->result_code = result_code;
    tlv->len = htons(sizeof(em_bh_steering_resp_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_bh_steering_resp_t));
    len += (sizeof(em_tlv_t) + sizeof(em_bh_steering_resp_t));

    // Include Error Code TLV on failure.
    if (result_code == 0x01) {
        short err_sz;
        tlv = reinterpret_cast<em_tlv_t *>(tmp);
        tlv->type = em_tlv_type_error_code;
        err_sz = create_error_code_tlv(tlv->value, static_cast<int>(error_reason), sta_mac);
        tlv->len = htons(static_cast<unsigned short>(err_sz));
        tmp += (sizeof(em_tlv_t) + static_cast<size_t>(err_sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t>(err_sz));
    }

    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;
    tmp += sizeof(em_tlv_t);
    len += sizeof(em_tlv_t);

    if (em_msg_t(em_msg_type_bh_steering_rsp, em_profile_type_2, buff, static_cast<unsigned int>(len)).validate(errors) == 0) {
        em_printfout("BH Steering Response msg validation failed");
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int>(len)) < 0) {
        em_printfout("BH Steering Response send failed: errno=%d", errno);
        return -1;
    }

    return static_cast<int>(len);
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

short em_steering_t::create_error_code_tlv(unsigned char *buff, int val, mac_addr_t sta_mac)
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
    if (get_state() == em_state_ctrl_bh_steer_pending) {
        set_state(em_state_ctrl_bh_steer_req_ack_rcvd);
    } else {
        set_state(em_state_ctrl_steer_btm_req_ack_rcvd);
    }
    return 0;
}

int em_steering_t::handle_client_assoc_ctrl_req(unsigned char *buff, unsigned int len)
{
    em_printfout("%s:%d: Received Client Assoc Control Request from Controller", __func__, __LINE__);

    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_client_assoc_ctrl_req_t *assoc_ctrl_req;

    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *> (buff);
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));
    unsigned short msg_id = ntohs(cmdu->id);
    dm_easy_mesh_t *dm = get_data_model();

    if (em_msg_t(em_msg_type_client_assoc_ctrl_req, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("%s:%d: Client Association Control Request message validation failed", __func__, __LINE__);
        return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    assoc_ctrl_req = reinterpret_cast<em_client_assoc_ctrl_req_t *> (&tlv->value);

    if (assoc_ctrl_req->assoc_control == 0x00) {  // Block
        mac_address_t sta_mac;
        memcpy(sta_mac, assoc_ctrl_req->sta_mac, sizeof(mac_address_t));
        // Check for associated STAs if blocking
        if (dm->is_sta_associated(assoc_ctrl_req->bssid, sta_mac)) {
            // Send Ack with error
            em_printfout("%s:%d: Sending ack with Error Code TLV", __func__, __LINE__);
            send_1905_ack_message(sta_mac, msg_id, 1, hdr->src);
            return 0;
        }
    }

    send_1905_ack_message(assoc_ctrl_req->sta_mac, msg_id, 0, hdr->src);

    // Send the association control request to OneWifi for HAL enforcement
    uint16_t tlv_len = ntohs(tlv->len);
    get_mgr()->io_process(em_bus_event_type_client_assoc_ctrl_req,
        reinterpret_cast<unsigned char *> (assoc_ctrl_req), tlv_len);

    return 0;
}

void em_steering_t::process_ctrl_state()
{
    switch (get_state()) {
        case em_state_ctrl_sta_steer_pending:
            send_client_steering_req_msg();
            break;

        case em_state_ctrl_sta_disassoc_pending:
            send_client_assoc_ctrl_req_msg();
            break;

        case em_state_ctrl_bh_steer_pending:
            send_bh_steering_req_msg();
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

        case em_state_agent_bh_steer_pending:
            // Waiting for OneWifi result (AssociationStatus callback).
            // Orchestration timeout handles the failure case.
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

        case em_msg_type_bh_steering_req:
            handle_bh_steering_req(data, len);
            break;

        case em_msg_type_bh_steering_rsp:
            handle_bh_steering_rsp(data, len);
            break;

        case em_msg_type_1905_ack:
            handle_ack_msg(data, len);

        default:
            break;
    }
}

bool em_steering_t::handle_bh_steer_result(const bssid_t connected_bssid, int connect_status)
{
    if (get_state() != em_state_agent_bh_steer_pending) {
        return false;
    }

    mac_addr_str_t sta_str, bssid_str;
    dm_easy_mesh_t::macbytes_to_string(m_bh_steer_pending_sta_mac, sta_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<uint8_t *> (connected_bssid), bssid_str);

    bool is_target_bssid = (memcmp(connected_bssid, m_bh_steer_pending_bssid, sizeof(bssid_t)) == 0);

    if (connect_status == wifi_connection_status_connected && is_target_bssid) {
        em_printfout("BH Steering result: STA %s connected to target %s - sending success response",
                     sta_str, bssid_str);
        send_bh_steering_rsp_msg(m_bh_steer_pending_sta_mac, m_bh_steer_pending_bssid, 0x00);
    } else if (connect_status != wifi_connection_status_connected && !is_target_bssid) {
        // Old connection dropping during steer, ignore and keep waiting for target result
        em_printfout("BH Steering: ignoring disconnect from old BSS %s (status=%d), waiting for target",
                     bssid_str, connect_status);
        return false;
    } else {
        unsigned char reason = (connect_status == wifi_connection_status_ap_not_found)
                               ? em_error_code_bh_steer_signal_weak_or_not_found
                               : em_error_code_bh_steer_rejected_by_target_bss;
        em_printfout("BH Steering result: STA %s failed (connect_status=%d bssid=%s) - sending failure response (reason=0x%02x)",
                     sta_str, connect_status, bssid_str, reason);
        send_bh_steering_rsp_msg(m_bh_steer_pending_sta_mac, m_bh_steer_pending_bssid, 0x01, reason);
    }

    set_state(em_state_agent_configured);
    return true;
}

void em_steering_t::handle_bh_steer_timeout()
{
    if (get_state() != em_state_agent_bh_steer_pending) {
        return;
    }
    em_printfout("BH Steering: orchestration timeout expired, sending failure response");
    send_bh_steering_rsp_msg(m_bh_steer_pending_sta_mac, m_bh_steer_pending_bssid,
                             0x01, em_error_code_bh_steer_signal_weak_or_not_found);
    set_state(em_state_agent_configured);
}

em_steering_t::em_steering_t()
{
    m_client_steering_req_tx_cnt = 0;
    m_client_assoc_ctrl_req_tx_cnt = 0;
    memset(m_bh_steer_pending_sta_mac, 0, sizeof(m_bh_steer_pending_sta_mac));
    memset(m_bh_steer_pending_bssid,   0, sizeof(m_bh_steer_pending_bssid));
}

em_steering_t::~em_steering_t()
{
}

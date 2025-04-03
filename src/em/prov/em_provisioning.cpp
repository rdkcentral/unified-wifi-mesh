/**
 * Copyright 2025 Comcast Cable Communications Management, LLC
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
#include <assert.h>
#include "em.h"
#include "em_cmd.h"
#include "em_msg.h"
#include "cjson/cJSON.h"
#include "util.h"
#include "ec_util.h"

int em_provisioning_t::create_cce_ind_cmd(uint8_t *buff)
{
    return 0;
}

int em_provisioning_t::create_cce_ind_msg(uint8_t *buff)
{
    uint16_t  msg_id = em_msg_type_dpp_cce_ind;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    uint8_t *tmp = buff;
    uint16_t enable = 0;
    uint16_t type = htons(ETH_P_1905);

    memcpy(tmp, reinterpret_cast<uint8_t *> (get_peer_mac()), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<uint8_t *> (&type), sizeof(uint16_t));
    tmp += sizeof(uint16_t);
    len += static_cast<unsigned int> (sizeof(uint16_t));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // One DPP CCE Indication tlv 17.2.82
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_dpp_cce_indication;
    //enable = (get_state() == em_state_agent_prov) ? 1:0;
	enable = (get_state() == em_state_agent_configured) ? 1:0;
    memcpy(tlv->value, &enable, sizeof(uint16_t));
    tlv->len = htons(sizeof(uint16_t));

    tmp += (sizeof(em_tlv_t) + sizeof(uint16_t));
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + sizeof(uint16_t));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    return static_cast<int> (len);
}

int em_provisioning_t::send_prox_encap_dpp_msg(em_encap_dpp_t* encap_dpp_tlv, size_t encap_dpp_len, em_dpp_chirp_value_t *chirp, size_t chirp_len)
{
    if (encap_dpp_len == 0 || encap_dpp_tlv == NULL) {
        printf("Encap DPP TLV is empty\n");
        return -1;
    }

    uint8_t buff[MAX_EM_BUFF_SZ];
    unsigned int len = 0;
    uint8_t *tmp = buff;

    //dm_easy_mesh_t *dm = get_data_model();

    //TODO: Decide on addressing.
    //tmp = em_msg_t::add_1905_header(tmp, &len, dm->get_agent_al_interface_mac(), dm->get_ctrl_al_interface_mac(), em_msg_type_proxied_encap_dpp);
    tmp = em_msg_t::add_1905_header(tmp, &len, const_cast<uint8_t *> (get_peer_mac()), get_al_interface_mac(), em_msg_type_proxied_encap_dpp);

    // One 1905 Encap DPP TLV 17.2.79
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_1905_encap_dpp, reinterpret_cast<uint8_t *> (encap_dpp_tlv), static_cast<unsigned int> (encap_dpp_len));

    // Zero or One DPP Chirp value tlv 17.2.83
    if (chirp != NULL && chirp_len > 0) {
        tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_dpp_chirp_value, reinterpret_cast<uint8_t *> (chirp), static_cast<unsigned int> (chirp_len));
    }


    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_proxied_encap_dpp, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Channel Selection Request msg failed validation in tnx end\n");
        //return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Channel Selection Request msg failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    // TODO: If needed, likely not
	//set_state(em_state_ctrl_configured);

    return static_cast<int> (len);
}

int em_provisioning_t::send_chirp_notif_msg(em_dpp_chirp_value_t *chirp, size_t chirp_len)
{

    if (chirp_len == 0 || chirp == NULL) {
        printf("Chirp value is empty\n");
        return -1;
    }

    uint8_t buff[MAX_EM_BUFF_SZ];
    unsigned int len = 0;
    uint8_t *tmp = buff;

    //dm_easy_mesh_t *dm = get_data_model();

    // NOTE: `get_ctrl_al_interface_mac` is really only for co-located so `get_peer_mac` does not work.

    //TODO: Decide on addressing.
    printf("%s:%d: Sending CHIRP NOTIFICATION\n", __func__, __LINE__);
    mac_addr_str_t peer_mac_str = {0}, al_mac_str = {0};
    dm_easy_mesh_t::macbytes_to_string(get_peer_mac(), peer_mac_str);
    dm_easy_mesh_t::macbytes_to_string(get_al_interface_mac(), al_mac_str);
    printf("%s:%d: Peer MAC: %s, AL MAC: %s\n", __func__, __LINE__, peer_mac_str, al_mac_str);
    tmp = em_msg_t::add_1905_header(tmp, &len, get_peer_mac(), get_al_interface_mac(), em_msg_type_chirp_notif);

    // One DPP Chirp value tlv 17.2.83
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_dpp_chirp_value, reinterpret_cast<uint8_t *> (chirp), static_cast<unsigned int> (chirp_len));

    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_chirp_notif, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Channel Selection Request msg failed validation in tnx end\n");
        //return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Channel Selection Request msg failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    // TODO: If needed, likely not
	//set_state(em_state_ctrl_configured);

    return static_cast<int> (len);

}

int em_provisioning_t::create_bss_config_req_msg(uint8_t *buff)
{
    uint16_t  msg_id = em_msg_type_bss_config_req;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    uint8_t *tmp = buff;
    uint16_t type = htons(ETH_P_1905);

    memcpy(tmp, reinterpret_cast<uint8_t *> (get_peer_mac()), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<uint8_t *> (&type), sizeof(uint16_t));
    tmp += sizeof(uint16_t);
    len += static_cast<unsigned int> (sizeof(uint16_t));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // One miltiap profile tlv 17.2.47
    // One supported service tlv 17.2.1
    // One akm suite cap tlv 17.2.78
    // One or more ap radio basic capability tlv 17.2.7
    // zero or more backhaul STA radio capabilities tlv 17.2.65
    // One profile 2 ap capability tlv 17.2.48
    // One or more AO radio advanced capabilities tlv 17.2.52
    // One BSS configuration request tlv 17.2.84

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof(em_tlv_t));

    return static_cast<int> (len);

}

int em_provisioning_t::create_bss_config_rsp_msg(uint8_t *buff)
{
    uint16_t  msg_id = em_msg_type_bss_config_rsp;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    uint8_t *tmp = buff;
    uint16_t type = htons(ETH_P_1905);

    memcpy(tmp, reinterpret_cast<uint8_t *> (get_peer_mac()), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<uint8_t *> (&type), sizeof(uint16_t));
    tmp += sizeof(uint16_t);
    len += static_cast<unsigned int> (sizeof(uint16_t));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // One or more BSS config response tlv 17.2.85
    // Zero or One deafult 802,1Q settings tlv 17.2.49
    // Zero or One traffic separation policy tlv 17.2.50

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    return static_cast<int> (len);

}

int em_provisioning_t::create_bss_config_res_msg(uint8_t *buff)
{
    uint16_t  msg_id = em_msg_type_bss_config_res;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    uint8_t *tmp = buff;
    uint16_t type = htons(ETH_P_1905);

    memcpy(tmp, reinterpret_cast<uint8_t *> (get_peer_mac()), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<uint8_t *> (&type), sizeof(uint16_t)); 
    tmp += sizeof(uint16_t);
    len += static_cast<unsigned int> (sizeof(uint16_t));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // One BSS configuration report tlv 17.2.75
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_dpp_chirp_value;


    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    return static_cast<int> (len);

}

int em_provisioning_t::create_dpp_direct_encap_msg(uint8_t *buff, uint8_t *frame, uint16_t frame_len)
{
    uint16_t  msg_id = em_msg_type_direct_encap_dpp;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    uint8_t *tmp = buff;
    uint16_t type = htons(ETH_P_1905);

    memcpy(tmp, reinterpret_cast<uint8_t *> (get_peer_mac()), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<uint8_t *> (&type), sizeof(uint16_t));
    tmp += sizeof(uint16_t);
    len += static_cast<unsigned int> (sizeof(uint16_t));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // One DPP Message tlv 17.2.86
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_dpp_msg;
    tlv->len = htons(frame_len);
    memcpy(tlv->value, frame, frame_len);

    tmp += (sizeof(em_tlv_t) + frame_len);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + frame_len);

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    return static_cast<int> (len);
}

int em_provisioning_t::handle_cce_ind_msg(uint8_t *buff, unsigned int len)
{
    em_tlv_t    *tlv;
    unsigned int tmp_len;
    int ret = 0;
    unsigned int rq_ctr = 0, rx_ctr = 0;
    //uint8_t msg[MAX_EM_BUFF_SZ]; commented since not used
    //unsigned int sz;  commented since sz not used

    // mandatory need 17.2.82
    rq_ctr = 1;

    printf("%s:%d: Parsing cce ind message\n", __func__, __LINE__);

    tlv = reinterpret_cast<em_tlv_t *> (buff); tmp_len = len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if ((tlv->type == em_tlv_type_dpp_cce_indication) && (htons(tlv->len) == sizeof(uint16_t))) {
            printf("%s:%d: validated cce ind tlv\n", __func__, __LINE__);
            rx_ctr++;
        }

        tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<uint8_t *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    if (rx_ctr != rq_ctr) {
        printf("%s:%d: cce ind message parsing failed\n", __func__, __LINE__);
        return -1;
    }

    // if this is a proxy agent (must be provisioned) , ask onewifi to beacon cce otherwise send presence announcement
    if (get_state() > em_state_agent_configured) {
        //sz = static_cast<unsigned int> (create_cce_ind_cmd(msg)); commented since sz not used
        //ret = send_cmd(msg, sz); // Modify send_cmd
        if (ret > 0) {
            printf("%s:%d: cmd send success\n", __func__, __LINE__);
            //set_state(em_state_agent_auth_req_pending);
        } else {
            printf("%s:%d: cmd send failed, error:%d\n", __func__, __LINE__, errno);
        }
    }

    return ret;

}

void em_provisioning_t::process_msg(uint8_t *data, unsigned int len)
{
    em_cmdu_t *cmdu;

    cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));

    switch (htons(cmdu->type)) {
        case em_msg_type_dpp_cce_ind:
            break;

        case em_msg_type_proxied_encap_dpp:
            handle_proxy_encap_dpp(data, len);
            break;

        case em_msg_type_direct_encap_dpp:
            break;

        case em_msg_type_reconfig_trigger:
            break;

        case em_msg_type_bss_config_req:
            break;

        case em_msg_type_bss_config_rsp:
            break;

        case em_msg_type_bss_config_res:
            break;

        case em_msg_type_chirp_notif:
            handle_dpp_chirp_notif(data, len);
            break;

        case em_msg_type_dpp_bootstrap_uri_notif:
            break;

        default:
            printf("%s:%d: unhandled message type %u\n", __func__, __LINE__, htons(cmdu->type));
            break;
    }
}

int em_provisioning_t::handle_dpp_chirp_notif(uint8_t *buff, unsigned int len)
{
    em_tlv_t    *tlv;
    unsigned int tlv_len;

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        // Can be one or more
        if (tlv->type == em_tlv_type_dpp_chirp_value) {
            // Parse out dest STA mac address and hash value then validate against the hash in the 
            // ec_session dpp uri info public key. 
            // Then construct an Auth request frame and send back in an Encap message
            em_dpp_chirp_value_t* chirp_tlv = reinterpret_cast<em_dpp_chirp_value_t*> (tlv->value);

            if (!m_ec_manager->process_chirp_notification(chirp_tlv, ntohs(tlv->len))){
                //TODO: Fail
                printf("%s:%d: Failed to process chirp notification\n", __func__, __LINE__);
            }
        }

        tlv_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + ntohs(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<uint8_t *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
    }

	return 0;
}

int em_provisioning_t::handle_proxy_encap_dpp(uint8_t *buff, unsigned int len)
{
    em_tlv_t    *tlv;
    unsigned int tlv_len;

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    uint16_t encap_tlv_len, chirp_tlv_len = 0;
    em_encap_dpp_t* encap_tlv = NULL;
    em_dpp_chirp_value_t* chirp_tlv = NULL;

    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {

        if (tlv->type == em_tlv_type_1905_encap_dpp) {
            // Parse out dest STA mac address and hash value then validate against the hash in the 
            // ec_session dpp uri info public key. 
            // Then construct an Auth request frame and send back in an Encap message
            encap_tlv = reinterpret_cast<em_encap_dpp_t*> (tlv->value);
            encap_tlv_len = ntohs(tlv->len);
        }

        // Optional: Can be 0 or 1
        if (tlv->type == em_tlv_type_dpp_chirp_value) {
            chirp_tlv = reinterpret_cast<em_dpp_chirp_value_t*> (tlv->value);
            chirp_tlv_len = ntohs(tlv->len);
        }

        tlv_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + ntohs(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *>(reinterpret_cast<uint8_t *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
    }

    if (m_ec_manager->process_proxy_encap_dpp_msg(encap_tlv, encap_tlv_len, chirp_tlv, chirp_tlv_len) != 0){
        //TODO: Fail
        return -1;
    }

	return 0;
}

cJSON *em_provisioning_t::create_enrollee_bsta_list(ec_connection_context_t *conn_ctx)
{
    dm_easy_mesh_t *dm = get_data_model();
    if (dm == nullptr) {
        printf("%s:%d: Could not get data model handle!\n", __func__, __LINE__);
        return nullptr;
    }

    std::string channelList;
    cJSON *bsta_list_obj = cJSON_CreateObject();
    if (!bsta_list_obj) {
        printf("%s:%d: Failed to allocate for bSTAList object!\n", __func__, __LINE__);
        return nullptr;
    }

    cJSON *b_sta_list_arr = cJSON_CreateArray();
    if (!b_sta_list_arr) {
        printf("%s:%d: Could not allocate for bSTAList array!\n", __func__, __LINE__);
        cJSON_Delete(bsta_list_obj);
        return nullptr;
    }

    if (!cJSON_AddStringToObject(bsta_list_obj, "netRole", "mapBackhaulSta")) {
        printf("%s:%d: Could not add netRole to bSTAList object!\n", __func__, __LINE__);
        cJSON_Delete(b_sta_list_arr);
        return nullptr;
    }

    // XXX: TODO: akm is hard-coded. Should come from em_akm_suite_info_t or equivalent, but
    // not currently populated anywhere in the data model.
    std::string akm = "psk";
    if (!cJSON_AddStringToObject(bsta_list_obj, "akm", util::akm_to_oui(akm).c_str())) {
        printf("%s:%d: Could not add AKM to bSTAList object!\n", __func__, __LINE__);
        cJSON_Delete(b_sta_list_arr);
        return nullptr;
    }

    if (!cJSON_AddNumberToObject(bsta_list_obj, "bSTA_Maximum_Links", 1)) {
        printf("%s:%d: Could not add bSTA_Maximum_Links to bSTAList object!\n", __func__, __LINE__);
        cJSON_Delete(b_sta_list_arr);
        return nullptr;
    }

    if (!cJSON_AddItemToArray(b_sta_list_arr, bsta_list_obj)) {
        printf("%s:%d: Could not add bSTAList object to bSTAList array!\n", __func__, __LINE__);
        cJSON_Delete(b_sta_list_arr);
        return nullptr;
    }

    cJSON *radio_list_arr = cJSON_AddArrayToObject(bsta_list_obj, "RadioList");
    if (!radio_list_arr) {
        printf("%s:%d: Could not add RadioList array to bSTAList object!\n", __func__, __LINE__);
        cJSON_Delete(bsta_list_obj);
        return nullptr;
    }

    for (unsigned int i = 0; i < dm->get_num_radios(); i++) {
        const dm_radio_t *radio = dm->get_radio(i);
        if (!radio)
            continue;

        cJSON *radioListObj = cJSON_CreateObject();
        if (!radioListObj) {
            printf("%s:%d: Failed to create RadioList object!\n", __func__, __LINE__);
            cJSON_Delete(bsta_list_obj);
            return nullptr;
        }

        if (!cJSON_AddStringToObject(
                radioListObj, "RUID",
                util::mac_to_string(radio->m_radio_info.id.ruid, "").c_str())) {
            printf("%s:%d: Could not add RUID to RadioList object!\n", __func__, __LINE__);
            cJSON_Delete(radioListObj);
            cJSON_Delete(bsta_list_obj);
            return nullptr;
        }

        std::string radio_channel_list;
        for (unsigned int j = 0; j < dm->get_num_op_class(); j++) {
            const dm_op_class_t *opclass = dm->get_op_class(j);
            if (opclass == nullptr) continue;
            if (memcmp(opclass->m_op_class_info.id.ruid, radio->m_radio_info.id.ruid, ETH_ALEN) == 0) {
                radio_channel_list += std::to_string(opclass->m_op_class_info.op_class) + "/" +
                                      std::to_string(opclass->m_op_class_info.channel);
                if (j != dm->get_num_op_class() - 1)
                    radio_channel_list += ",";
            }
        }
        channelList += radio_channel_list;

        if (!cJSON_AddStringToObject(radioListObj, "RadioChannelList",
                                     radio_channel_list.c_str())) {
            printf("%s:%d: Could not add RadioChannelList to RadioList object!\n", __func__,
                   __LINE__);
            cJSON_Delete(radioListObj);
            cJSON_Delete(bsta_list_obj);
            return nullptr;
        }

        if (!cJSON_AddItemToArray(radio_list_arr, radioListObj)) {
            printf("%s:%d: Could not add RadioList object to RadioList array!\n", __func__,
                   __LINE__);
            cJSON_Delete(radioListObj);
            cJSON_Delete(bsta_list_obj);
            return nullptr;
        }
    }

    if (!cJSON_AddStringToObject(bsta_list_obj, "channelList", channelList.c_str())) {
        printf("%s:%d: Could not add channelList to bSTAList object!\n", __func__, __LINE__);
        cJSON_Delete(b_sta_list_arr);
        return nullptr;
    }
    return b_sta_list_arr;
}

cJSON *em_provisioning_t::create_configurator_bsta_response_obj(ec_connection_context_t *conn_ctx)
{
    dm_easy_mesh_t *dm = get_data_model();
    ASSERT_NOT_NULL(dm, nullptr, "%s:%d: Failed to get data model handle.\n", __func__, __LINE__);

    cJSON *bsta_configuration_object = cJSON_CreateObject();
    ASSERT_NOT_NULL(bsta_configuration_object, nullptr, "%s:%d: Could not create bSTA Configuration Object\n", __func__, __LINE__);

    if (!cJSON_AddStringToObject(bsta_configuration_object, "wi-fi_tech", "map")) {
        printf("%s:%d: Failed to add \"wi-fi_tech\" to Configuration Object\n", __func__, __LINE__);
        cJSON_Delete(bsta_configuration_object);
    }

    cJSON *discovery_object = cJSON_CreateObject();
    if (discovery_object == nullptr) {
        printf("%s:%d: Failed to create Discovery Object for DPP Configuration Object\n", __func__, __LINE__);
        cJSON_Delete(bsta_configuration_object);
    }
    const em_network_ssid_info_t* network_ssid_info = dm->get_network_ssid_info_by_haul_type(em_haul_type_backhaul);
    ASSERT_NOT_NULL(network_ssid_info, nullptr, "%s:%d: No backhaul BSS found, cannot create bSTA Configuration Object\n", __func__, __LINE__);
    if (!cJSON_AddStringToObject(discovery_object, "SSID", network_ssid_info->ssid)) {
        printf("%s:%d: Could not add \"SSID\" to bSTA Configuration Object\n", __func__, __LINE__);
        cJSON_Delete(bsta_configuration_object);
        cJSON_Delete(discovery_object);
        return nullptr;
    }
    // Find "BSSID" and "RUID" since not contained in `em_network_ssid_info_t`
    // XXX: Note: R5 only - R6 introduces MLDs.
    for (unsigned int i = 0; i < dm->get_num_bss(); i++) {
        const dm_bss_t *bss = dm->get_bss(i);
        if (!bss) continue;
        if (bss->m_bss_info.backhaul_use && strncmp(bss->m_bss_info.ssid, network_ssid_info->ssid, strlen(network_ssid_info->ssid)) == 0) {
            if (!cJSON_AddStringToObject(discovery_object, "BSSID", reinterpret_cast<const char *>(bss->m_bss_info.id.bssid))) {
                printf("%s:%d: Failed to add \"BSSID\" to bSTA Configuration Object\n", __func__, __LINE__);
                cJSON_Delete(bsta_configuration_object);
                cJSON_Delete(discovery_object);
                return nullptr;
            }
            if (!cJSON_AddStringToObject(discovery_object, "RUID", reinterpret_cast<const char *>(bss->m_bss_info.id.ruid))) {
                printf("%s:%d: Failed to add \"RUID\" to bSTA Configuration Object\n", __func__, __LINE__);
                cJSON_Delete(bsta_configuration_object);
                cJSON_Delete(discovery_object);
                return nullptr;
            }
        }
    }

    cJSON *credential_object = cJSON_CreateObject();
    if (credential_object == nullptr) {
        printf("%s:%d: Failed to create credential object for DPP Configuration object.\n", __func__, __LINE__);
        cJSON_Delete(discovery_object);
        cJSON_Delete(bsta_configuration_object);
        return nullptr;
    }

    std::string akm_suites = {};
    bool needs_psk_hex = false;
    for (unsigned int i = 0; i < network_ssid_info->num_akms; i++) {
        if (!akm_suites.empty()) akm_suites += "+";
        akm_suites += util::akm_to_oui(network_ssid_info->akm[i]);

    }
    // "psk_hex" is a conditional field,
    // present only if PSK or AKM or SAE is a selected AKM
    const auto check_needs_psk_hex = [](std::string akm) -> bool {
        // psk || sae
        return akm == util::akm_to_oui("psk")
        || akm == util::akm_to_oui("sae");
    };

    std::vector<std::string> akms = util::split_by_delim(akm_suites, '+');
    for (const auto& akm : akms) {
        if (check_needs_psk_hex(akm)) needs_psk_hex = true;
    }

    if (!cJSON_AddStringToObject(credential_object, "akm", akm_suites.c_str())) {
        printf("%s:%d: Failed to add \"akm\" to bSTA DPP Configuration Object\n", __func__, __LINE__);
        cJSON_Delete(discovery_object);
        cJSON_Delete(bsta_configuration_object);
        cJSON_Delete(credential_object);
        return nullptr;
    }

    if (needs_psk_hex) {
        std::vector<uint8_t> psk = ec_crypto::gen_psk(std::string(network_ssid_info->pass_phrase), std::string(network_ssid_info->ssid));
        if (psk.empty()) {
            printf("%s:%d: Failed to generate PSK\n", __func__, __LINE__);
            cJSON_Delete(discovery_object);
            cJSON_Delete(bsta_configuration_object);
            cJSON_Delete(credential_object);
            return nullptr;
        }

        cJSON_AddStringToObject(credential_object, "psk_hex", ec_util::hash_to_hex_string(psk).c_str());
    }

    if (!cJSON_AddStringToObject(credential_object, "pass", network_ssid_info->pass_phrase)) {
        printf("%s:%d: Failed to add \"pass\" to bSTA DPP Configuration Object", __func__, __LINE__);
        cJSON_Delete(discovery_object);
        cJSON_Delete(credential_object);
        cJSON_Delete(bsta_configuration_object);
        return nullptr;
    }

    if (!cJSON_AddItemToObject(bsta_configuration_object, "discovery", discovery_object)) {
        printf("%s:%d: Failed to add \"discovery\" to bSTA DPP Configuration Object\n", __func__, __LINE__);
        cJSON_Delete(credential_object);
        cJSON_Delete(discovery_object);
        cJSON_Delete(bsta_configuration_object);
    }

    if (!cJSON_AddItemToObject(bsta_configuration_object, "cred", credential_object)) {
        printf("%s:%d: Failed to add \"cred\" to bSTA DPP Configuration Object\n", __func__, __LINE__);
        cJSON_Delete(credential_object);
        cJSON_Delete(bsta_configuration_object);
    }
    return bsta_configuration_object;
}

cJSON *em_provisioning_t::create_ieee1905_response_obj(ec_connection_context_t *conn_ctx)
{
    cJSON* dpp_configuration_object = cJSON_CreateObject();
    ASSERT_NOT_NULL(dpp_configuration_object, nullptr, "%s:%d: Failed to create 1905 DPP Configuration Object.\n", __func__, __LINE__);
    if (!cJSON_AddStringToObject(dpp_configuration_object, "wi-fi_tech", "dpp")) {
        printf("%s:%d: Failed to add \"wi-fi_tech\" to 1905 DPP Configuration Object.\n", __func__, __LINE__);
        cJSON_Delete(dpp_configuration_object);
        return nullptr;
    }

    if (!cJSON_AddNumberToObject(dpp_configuration_object, "dfCounterThreshold", 42)) {
        printf("%s:%d: Failed to add \"dfCounterThreshold\" to 1905 DPP Configuration Object.\n", __func__, __LINE__);
        cJSON_Delete(dpp_configuration_object);
        return nullptr;
    }

    cJSON *credential_object = cJSON_CreateObject();
    if (!credential_object) {
        printf("%s:%d: Failed to create Credential object for 1905 DPP Configuration Object.\n", __func__, __LINE__);
        cJSON_Delete(dpp_configuration_object);
        return nullptr;
    }
    if (!cJSON_AddStringToObject(credential_object, "akm", util::akm_to_oui("dpp").c_str())) {
        printf("%s:%d: Failed to add \"akm\" to 1905 DPP Configuration Object.\n", __func__, __LINE__);
        cJSON_Delete(credential_object);
        cJSON_Delete(dpp_configuration_object);
        return nullptr;
    }

    return dpp_configuration_object;
}

void em_provisioning_t::handle_state_prov_none()
{
    printf("%s:%d: Waiting for CCE indication interface: %s\n", __func__, __LINE__, const_cast<char *> (get_radio_interface_name()));
}

void em_provisioning_t::handle_state_prov()
{

    assert(get_service_type() == em_service_type_ctrl);
}

void em_provisioning_t::handle_state_auth_req_pending()
{
    assert(get_service_type() == em_service_type_agent);
}

void em_provisioning_t::handle_state_auth_rsp_pending()
{
    assert(get_service_type() == em_service_type_ctrl);
}

void em_provisioning_t::handle_state_auth_cnf_pending()
{
    assert(get_service_type() == em_service_type_agent);
}

void em_provisioning_t::handle_state_config_req_pending()
{
    assert(get_service_type() == em_service_type_ctrl);
}

void em_provisioning_t::handle_state_config_rsp_pending()
{
    assert(get_service_type() == em_service_type_agent);
}

void em_provisioning_t::handle_state_config_res_pending()
{
    assert(get_service_type() == em_service_type_ctrl);
}

void em_provisioning_t::process_agent_state()
{
    switch (get_state()) {
/* To be implemented
		case em_state_agent_prov_none:
            handle_state_prov_none();
            break;

        case em_state_agent_prov:
            handle_state_prov();
            break;

        case em_state_agent_auth_req_pending:
            handle_state_auth_req_pending();
            break;

        case em_state_agent_auth_rsp_pending:
            handle_state_auth_rsp_pending();
            break;

        case em_state_agent_auth_cnf_pending:
            handle_state_auth_cnf_pending();
            break;

        case em_state_agent_config_req_pending:
            handle_state_config_req_pending();
            break;

        case em_state_agent_config_rsp_pending:
            handle_state_config_rsp_pending();
            break;

        case em_state_agent_config_res_pending:
            handle_state_config_res_pending();
            break;
*/
        default:
            break; 
    }
}

void em_provisioning_t::process_ctrl_state()
{

}

em_provisioning_t::em_provisioning_t()
{
}

em_provisioning_t::~em_provisioning_t()
{

}


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
    tmp = em_msg_t::add_1905_header(tmp, &len, const_cast<uint8_t *> (get_peer_mac()), get_current_cmd()->get_al_interface_mac(), em_msg_type_proxied_encap_dpp);

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

    //TODO: Decide on addressing.
    //tmp = em_msg_t::add_1905_header(tmp, &len, (uint8_t*)dm->get_agent_al_interface_mac(), (uint8_t*)dm->get_ctrl_al_interface_mac(), em_msg_type_chirp_notif);
    tmp = em_msg_t::add_1905_header(tmp, &len, const_cast<uint8_t *> (get_peer_mac()), get_current_cmd()->get_al_interface_mac(), em_msg_type_chirp_notif);

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

            if (m_ec_manager->process_chirp_notification(chirp_tlv, htons(tlv->len)) != 0){
                //TODO: Fail
            }
        }

        tlv_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<uint8_t *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
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
            encap_tlv_len = htons(tlv->len);
        }

        // Optional: Can be 0 or 1
        if (tlv->type == em_tlv_type_dpp_chirp_value) {
            chirp_tlv = reinterpret_cast<em_dpp_chirp_value_t*> (tlv->value);
            chirp_tlv_len = htons(tlv->len);
        }

        tlv_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *>(reinterpret_cast<uint8_t *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    if (m_ec_manager->process_proxy_encap_dpp_msg(encap_tlv, encap_tlv_len, chirp_tlv, chirp_tlv_len) != 0){
        //TODO: Fail
        return -1;
    }

	return 0;
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


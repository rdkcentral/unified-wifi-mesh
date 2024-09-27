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
#include <assert.h>
#include "em.h"
#include "em_cmd.h"

int em_provisioning_t::create_cce_ind_cmd(unsigned char *buff)
{
    return 0;
}

int em_provisioning_t::create_cce_ind_msg(unsigned char *buff)
{
    unsigned short  msg_id = em_msg_type_dpp_cce_ind;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short enable = 0;
    unsigned short type = htons(ETH_P_1905);

    memcpy(tmp, (unsigned char *)get_peer_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
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

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // One DPP CCE Indication tlv 17.2.82
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_dpp_cce_indication;
    enable = (get_state() == em_state_agent_prov) ? 1:0;
    memcpy(tlv->value, &enable, sizeof(unsigned short));
    tlv->len = htons(sizeof(unsigned short));

    tmp += (sizeof(em_tlv_t) + sizeof(unsigned short));
    len += (sizeof(em_tlv_t) + sizeof(unsigned short));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    return len;
}

int em_provisioning_t::create_chirp_notif_msg(unsigned char *buff, em_chirp_t *chirp, unsigned char *hash_val)
{
    unsigned short  msg_id = em_msg_type_chirp_notif;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);

    memcpy(tmp, (unsigned char *)get_peer_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
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

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // One DPP Chirp value tlv 17.2.83
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_dpp_chirp_value;
    tlv->len = htons(sizeof(em_chirp_t) + chirp->hash_len);
    memcpy(tlv->value, chirp, sizeof(em_chirp_t));
    memcpy(tlv->value + sizeof(em_chirp_t), hash_val, chirp->hash_len);

    tmp += (sizeof(em_tlv_t) + sizeof(em_chirp_t) + chirp->hash_len);
    len += (sizeof(em_tlv_t) + sizeof(em_chirp_t) + chirp->hash_len);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    return len;

}

int em_provisioning_t::create_bss_config_req_msg(unsigned char *buff)
{
    unsigned short  msg_id = em_msg_type_bss_config_req;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);

    memcpy(tmp, (unsigned char *)get_peer_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
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

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // One miltiap profile tlv 17.2.47
    // One supported service tlv 17.2.1
    // One akm suite cap tlv 17.2.78
    // One or more ap radio basic capability tlv 17.2.7
    // zero or more backhaul STA radio capabilities tlv 17.2.65
    // One profile 2 ap capability tlv 17.2.48
    // One or more AO radio advanced capabilities tlv 17.2.52
    // One BSS configuration request tlv 17.2.84

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    return len;

}

int em_provisioning_t::create_bss_config_rsp_msg(unsigned char *buff)
{
    unsigned short  msg_id = em_msg_type_bss_config_rsp;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);

    memcpy(tmp, (unsigned char *)get_peer_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
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

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // One or more BSS config response tlv 17.2.85
    // Zero or One deafult 802,1Q settings tlv 17.2.49
    // Zero or One traffic separation policy tlv 17.2.50

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    return len;

}

int em_provisioning_t::create_bss_config_res_msg(unsigned char *buff)
{
    unsigned short  msg_id = em_msg_type_bss_config_res;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);

    memcpy(tmp, (unsigned char *)get_peer_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
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

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // One BSS configuration report tlv 17.2.75
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_dpp_chirp_value;


    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    return len;

}

int em_provisioning_t::create_dpp_direct_encap_msg(unsigned char *buff, unsigned char *frame, unsigned short frame_len)
{
    unsigned short  msg_id = em_msg_type_direct_encap_dpp;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);

    memcpy(tmp, (unsigned char *)get_peer_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
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

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // One DPP Message tlv 17.2.86
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_dpp_msg;
    tlv->len = htons(frame_len);
    memcpy(tlv->value, frame, frame_len);

    tmp += (sizeof(em_tlv_t) + frame_len);
    len += (sizeof(em_tlv_t) + frame_len);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    return len;
}

int em_provisioning_t::handle_cce_ind_msg(unsigned char *buff, unsigned int len)
{
    em_tlv_t    *tlv;
    int tmp_len, ret = 0;
    unsigned int rq_ctr = 0, rx_ctr = 0;
    unsigned char msg[MAX_EM_BUFF_SZ];
    unsigned int sz;

    // mandatory need 17.2.82
    rq_ctr = 1;

    printf("%s:%d: Parsing cce ind message\n", __func__, __LINE__);

    tlv = (em_tlv_t *)buff; tmp_len = len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if ((tlv->type == em_tlv_type_dpp_cce_indication) && (htons(tlv->len) == sizeof(unsigned short))) {
            printf("%s:%d: validated cce ind tlv\n", __func__, __LINE__);
            rx_ctr++;
        }

        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    if (rx_ctr != rq_ctr) {
        printf("%s:%d: cce ind message parsing failed\n", __func__, __LINE__);
        return -1;
    }

    // if this is a proxy agent (must be provisioned) , ask onewifi to beacon cce otherwise send presence announcement
    if (get_state() > em_state_agent_prov_complete) {
        sz = create_cce_ind_cmd(msg);
        //ret = send_cmd(msg, sz); // Modify send_cmd
        if (ret > 0) {
            printf("%s:%d: cmd send success\n", __func__, __LINE__);
            set_state(em_state_agent_auth_req_pending);
        } else {
            printf("%s:%d: cmd send failed, error:%d\n", __func__, __LINE__, errno);
        }
    }

    return ret;

}

void em_provisioning_t::process_msg(unsigned char *data, unsigned int len)
{
    em_raw_hdr_t *hdr;
    em_cmdu_t *cmdu;
    unsigned char *tlvs;
    unsigned int tlvs_len;

    hdr = (em_raw_hdr_t *)data;
    cmdu = (em_cmdu_t *)(data + sizeof(em_raw_hdr_t));

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

        default:
            break;
    }
}

void em_provisioning_t::handle_state_prov_none()
{
    printf("%s:%d: Waiting for CCE indication interface: %s\n", __func__, __LINE__, (char *)get_radio_interface_name());
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


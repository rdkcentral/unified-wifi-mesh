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

int em_steering_t::send_client_assoc_ctrl_req_msg()
{
    em_cmd_t *pcmd;
    em_disassoc_params_t *disassoc_param;
    unsigned int i, j;
    unsigned int num = 0;
    dm_easy_mesh_t *dm;
    dm_bss_t *bss;
    em_client_assoc_ctrl_req_t assoc_ctrl[MAX_EM_BUFF_SZ];

    dm = get_data_model();

    pcmd = get_current_cmd();
    for (i = 0; i < pcmd->m_param.u.disassoc_params.num; i++) {
        disassoc_param = &pcmd->m_param.u.disassoc_params.params[i];
        for (j = 0; j < dm->m_num_bss; j++) {
            if ((memcmp(disassoc_param->bssid, dm->m_bss[j].m_bss_info.bssid.mac, sizeof(bssid_t)) == 0) &&
                (memcmp(dm->m_bss[j].m_bss_info.ruid.mac, get_radio_interface_mac(), sizeof(mac_address_t)) == 0)) {
                memcpy(assoc_ctrl[num].bssid, disassoc_param->bssid, sizeof(mac_address_t));
                if (disassoc_param->disassoc_time == 0) {
                    assoc_ctrl[num].assoc_control = 0x03;
                } else {
                    assoc_ctrl[num].assoc_control = 0x02;
                    assoc_ctrl[num].validity_period = disassoc_param->disassoc_time;
                }
                assoc_ctrl[num].count = 1;
                memcpy(assoc_ctrl[num].sta_mac, disassoc_param->sta_mac, sizeof(mac_address_t));
                send_client_assoc_ctrl_req_msg(&assoc_ctrl[num]);
                num++;
            }
        }
    }

    set_state(em_state_ctrl_configured);
}

int em_steering_t::send_client_assoc_ctrl_req_msg(em_client_assoc_ctrl_req_t *assoc_ctrl)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_client_assoc_ctrl_req;
    int len = 0;
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

    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_client_assoc_ctrl_req;
    memcpy(tlv->value, assoc_ctrl, sizeof(em_client_assoc_ctrl_req_t));
    tlv->len = htons(sizeof(em_client_assoc_ctrl_req_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_client_assoc_ctrl_req_t));
    len += (sizeof (em_tlv_t) + sizeof(em_client_assoc_ctrl_req_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_client_assoc_ctrl_req, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Client Assoc Control Request msg validation failed\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Client Assoc Control Request msg send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    m_client_assoc_ctrl_req_tx_cnt++;
    printf("%s:%d: Client Assoc Control Request (%d) Send Successful\n", __func__, __LINE__, m_client_assoc_ctrl_req_tx_cnt);

    return len;
}

int em_steering_t::send_client_steering_req_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_client_steering_req;
    int len = 0;
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

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_client_steering_req, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Client Steering Request msg validation failed\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Client Steering Request msg send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    m_client_steering_req_tx_cnt++;
    printf("%s:%d: Client Steering Request (%d) Send Successful\n", __func__, __LINE__, m_client_steering_req_tx_cnt);

    return len;
}

void em_steering_t::process_msg(unsigned char *data, unsigned int len)
{

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

    }
}

void em_steering_t::process_state()
{

}

em_steering_t::em_steering_t()
{
    m_client_steering_req_tx_cnt = 0;
    m_client_assoc_ctrl_req_tx_cnt = 0;
}

em_steering_t::~em_steering_t()
{

}
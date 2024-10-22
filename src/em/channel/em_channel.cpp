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

short em_channel_t::create_channel_pref_tlv(unsigned char *buff)
{
	short len = 0;
	unsigned int i, j;
	em_channel_pref_t	*pref;
	em_channel_pref_op_class_t	*pref_op_class;
	dm_easy_mesh_t *dm;
	dm_op_class_t	*op_class;
	unsigned char *tmp;
	unsigned char pref_bits = 0xee;

	dm = get_data_model();

	pref = (em_channel_pref_t *)buff;
	memcpy(pref->ruid, get_radio_interface_mac(), sizeof(em_radio_id_t));
	pref_op_class = pref->op_classes;
    pref->op_classes_num = 0;

	tmp = (unsigned char *)pref_op_class;
	len += sizeof(em_channel_pref_t);

	for (i = 0; i < dm->m_num_opclass; i++) {
		op_class = &dm->m_op_class[i];
        if (((memcmp(op_class->m_op_class_info.id.ruid, dm->m_device.m_device_info.id.mac, sizeof(em_radio_id_t)) == 0)	&&
					(op_class->m_op_class_info.id.type == em_op_class_type_preference)) == false) {
			continue;		
		}
	
		pref_op_class->op_class = op_class->m_op_class_info.op_class;
		for (j = 0; j < op_class->m_op_class_info.num_anticipated_channels; j++) {	
			pref_op_class->channels.num++;
			memcpy(pref_op_class->channels.channel, (unsigned char *)&op_class->m_op_class_info.anticipated_channel[j], sizeof(unsigned char));
			len += sizeof(em_channel_pref_op_class_t) + sizeof(unsigned char);
			tmp += sizeof(em_channel_pref_op_class_t) + sizeof(unsigned char);
			memcpy(tmp, &pref_bits, sizeof(unsigned char));
			len += sizeof(unsigned char);
			tmp += sizeof(unsigned char);
		}

        pref_op_class = (em_channel_pref_op_class_t *)tmp;
        pref->op_classes_num++;
		
	}
	
	return len;
}

int em_channel_t::send_channel_sel_request_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_channel_sel_req;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    short sz = 0;
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

    // Zero or more Channel Preference TLVs (see section 17.2.13).
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_channel_pref;
    sz = create_channel_pref_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

	// Zero or more Transmit Power Limit TLVs (see section 17.2.15)

	// Zero or more Spatial Reuse Request TLVs (see section 17.2.89).

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));
    if (em_msg_t(em_msg_type_channel_sel_req, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Channel Selection Request msg failed validation in tnx end\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Channel Selection Request msg failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    return len;

}

int em_channel_t::send_channel_sel_response_msg(em_chan_sel_resp_code_type_t code)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_channel_sel_rsp;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    em_channel_sel_rsp_t *resp;
    unsigned char *tmp = buff;
    dm_easy_mesh_t *dm;
    unsigned short type = htons(ETH_P_1905);

    dm = get_data_model();

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
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

    // one or more Channel selection Response TLVs (see section 17.2.16).
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_channel_sel_resp;
    tlv->len = htons(sizeof(em_channel_sel_rsp_t));
    resp = (em_channel_sel_rsp_t *)tlv->value;
    memcpy(resp->ruid, get_radio_interface_mac(), sizeof(em_radio_id_t));
    memcpy(&resp->response_code, (unsigned char *)&code, sizeof(unsigned char));

    tmp += (sizeof(em_tlv_t) + sizeof(em_channel_sel_rsp_t));
    len += (sizeof(em_tlv_t) + sizeof(em_channel_sel_rsp_t));
    
	// Zero or more Spatial Reuse Config Response TLVs (see section 17.2.91)

	// End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));
    if (em_msg_t(em_msg_type_channel_sel_rsp, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Channel Selection Response msg failed validation in tnx end\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Channel Selection Response msg failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    return len;

}

short em_channel_t::create_operating_channel_report_tlv(unsigned char *buff)
{
	short len = 0;
	unsigned int i;
	dm_easy_mesh_t *dm;
	em_op_channel_rprt_t *rprt_op_class;
	em_op_class_ch_rprt_t *rprt_channel;
	dm_op_class_t	*op_class;	
	unsigned char *tmp;

	dm = get_data_model();

	rprt_op_class = (em_op_channel_rprt_t *)buff;
	memcpy(rprt_op_class->ruid, get_radio_interface_mac(), sizeof(em_radio_id_t));
	rprt_op_class->op_classes_num = 0;
	rprt_channel = rprt_op_class->op_classes;
	len += sizeof(em_op_channel_rprt_t);

	for (i = 0; i < dm->m_num_opclass; i++) {
		op_class = &dm->m_op_class[i];
		if ((memcmp(op_class->m_op_class_info.id.ruid, rprt_op_class->ruid, sizeof(em_radio_id_t)) == 0)	&&
			(op_class->m_op_class_info.id.type == em_op_class_type_current)) {
		
			tmp = (unsigned char *)rprt_channel;
			rprt_channel->op_class = op_class->m_op_class_info.op_class;
			rprt_channel->channel = op_class->m_op_class_info.channel;
			len += sizeof(em_op_class_ch_rprt_t);
			tmp += sizeof(em_op_class_ch_rprt_t);

			len += sizeof(unsigned char);	
			tmp += sizeof(unsigned char);	

			rprt_channel = (em_op_class_ch_rprt_t *)tmp;

			rprt_op_class->op_classes_num++;
		}
	}	

	return len;
}

int em_channel_t::send_operating_channel_report_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_op_channel_rprt;
    short sz;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    dm_easy_mesh_t *dm;
    unsigned short type = htons(ETH_P_1905);

    dm = get_data_model();

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
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
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

	// One or more Operating Channel Report TLVs (see section 17.2.17)
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_op_channel_report;
    sz = create_operating_channel_report_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // Zero or more Spatial Reuse Report TLVs (see section 17.2.90)

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));
    if (em_msg_t(em_msg_type_channel_sel_rsp, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Channel Selection Response msg failed validation in tnx end\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Channel Selection Response msg failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    return len;

}

int em_channel_t::send_channel_pref_query_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_channel_pref_query;
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

    if (em_msg_t(em_msg_type_channel_pref_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Channel Preference Query msg failed validation in tnx end\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Channel Preference Query send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    m_channel_pref_query_tx_cnt++;
    printf("%s:%d: Channel Pref Query (%d) Send Successful\n", __func__, __LINE__, m_channel_pref_query_tx_cnt);

    return len;
}

short em_channel_t::create_cac_status_report_tlv(unsigned char *buff)
{
	short len = 0;
	unsigned int i;
	dm_easy_mesh_t *dm;
	dm_op_class_t	*op_class;
	em_cac_status_rprt_avail_t *rprt_avail;
	em_cac_avail_t *avail;
	em_cac_status_rprt_non_occ_t	*rprt_non_occ;
	em_cac_non_occ_t *non_occ;
	em_cac_status_rprt_active_t *rprt_active;
	em_cac_active_t *active;
	unsigned char *tmp = buff;
	em_radio_id_t ruid;

	dm = get_data_model();
	memcpy(ruid, get_radio_interface_mac(), sizeof(em_radio_id_t));

	rprt_avail = (em_cac_status_rprt_avail_t *)tmp;
	rprt_avail->avail_num = 0;
	avail = rprt_avail->avail;	
	len += sizeof(em_cac_status_rprt_avail_t);
	tmp += sizeof(em_cac_status_rprt_avail_t);

	for (i = 0; i < dm->m_num_opclass; i++) {
		op_class = &dm->m_op_class[i];
		if ((memcmp(op_class->m_op_class_info.id.ruid, ruid, sizeof(em_radio_id_t)) == 0)	&&
			(op_class->m_op_class_info.id.type == em_op_class_type_cac_available)) {
		
			avail->op_class = op_class->m_op_class_info.op_class;
			avail->channel = op_class->m_op_class_info.channel;
			avail->mins_since_cac_comp = htons(op_class->m_op_class_info.mins_since_cac_comp);

			len += sizeof(em_cac_avail_t);
			tmp += sizeof(em_cac_avail_t);
			
			avail = (em_cac_avail_t *)tmp;
	
			rprt_avail->avail_num++;
		}
	}	

	rprt_non_occ = (em_cac_status_rprt_non_occ_t *)tmp;
	rprt_non_occ->non_occ_num = 0;
	non_occ = rprt_non_occ->non_occ;	
	len += sizeof(em_cac_status_rprt_non_occ_t);
	tmp += sizeof(em_cac_status_rprt_non_occ_t);

	for (i = 0; i < dm->m_num_opclass; i++) {
		op_class = &dm->m_op_class[i];
		if ((memcmp(op_class->m_op_class_info.id.ruid, ruid, sizeof(em_radio_id_t)) == 0)	&&
			(op_class->m_op_class_info.id.type == em_op_class_type_cac_non_occ)) {
		
			non_occ->op_class = op_class->m_op_class_info.op_class;
			non_occ->channel = op_class->m_op_class_info.channel;
			non_occ->sec_remain_non_occ_dur = htons(op_class->m_op_class_info.sec_remain_non_occ_dur);

			len += sizeof(em_cac_non_occ_t);
			tmp += sizeof(em_cac_non_occ_t);
			
			non_occ = (em_cac_non_occ_t *)tmp;
	
			rprt_non_occ->non_occ_num++;
		}
	}	

	rprt_active = (em_cac_status_rprt_active_t *)tmp;
	rprt_active->active_num = 0;
	active = rprt_active->active;	
	len += sizeof(em_cac_status_rprt_active_t);
	tmp += sizeof(em_cac_status_rprt_active_t);

	for (i = 0; i < dm->m_num_opclass; i++) {
		op_class = &dm->m_op_class[i];
		if ((memcmp(op_class->m_op_class_info.id.ruid, ruid, sizeof(em_radio_id_t)) == 0)	&&
			(op_class->m_op_class_info.id.type == em_op_class_type_cac_active)) {
		
			active->op_class = op_class->m_op_class_info.op_class;
			active->channel = op_class->m_op_class_info.channel;
			active->countdown_cac_comp[2] = (op_class->m_op_class_info.countdown_cac_comp & 0xFF);
            active->countdown_cac_comp[1] = (op_class->m_op_class_info.countdown_cac_comp & 0x0000FF00) >> 8;
            active->countdown_cac_comp[0] = (op_class->m_op_class_info.countdown_cac_comp & 0x00FF0000) >> 16;

			len += sizeof(em_cac_active_t);
			tmp += sizeof(em_cac_active_t);
			
			active = (em_cac_active_t *)tmp;
	
			rprt_active->active_num++;
		}
	}	

	return len;
}

short em_channel_t::create_cac_complete_report_tlv(unsigned char *buff)
{
	short len = 0;
	unsigned int i;
	dm_easy_mesh_t	*dm;
	dm_cac_comp_t *comp;
	em_cac_comp_rprt_t *cac_comp;
	em_cac_comp_rprt_radio_t *cac_comp_radio;
	em_cac_comp_rprt_pair_t *cac_comp_pair;

	dm = get_data_model();

	cac_comp = (em_cac_comp_rprt_t *)buff;
	cac_comp->radios_num = 1;
	cac_comp_radio = cac_comp->radios;

	comp = &dm->m_cac_comp;

	memcpy(cac_comp_radio->ruid, comp->m_cac_comp_info.ruid, sizeof(em_radio_id_t));
	cac_comp_radio->op_class = comp->m_cac_comp_info.op_class;
	cac_comp_radio->channel = comp->m_cac_comp_info.channel;
	cac_comp_radio->status = comp->m_cac_comp_info.status;
	cac_comp_radio->detected_pairs_num = comp->m_cac_comp_info.detected_pairs_num;
	cac_comp_pair = cac_comp_radio->detected_pairs;

	len += sizeof(em_cac_comp_rprt_t);
	len += sizeof(em_cac_comp_rprt_radio_t);

	for (i = 0; i < cac_comp_radio->detected_pairs_num; i++) {
		cac_comp_pair->op_class = comp->m_cac_comp_info.detected_pairs[i].op_class;	
		cac_comp_pair->channel = comp->m_cac_comp_info.detected_pairs[i].channel;	
		len += sizeof(em_cac_comp_rprt_pair_t);
		cac_comp_pair = (em_cac_comp_rprt_pair_t *)((unsigned char *)cac_comp_pair + sizeof(em_cac_comp_rprt_pair_t));	
	}

	return len;
}

short em_channel_t::create_radio_op_restriction_tlv(unsigned char *buff)
{
	short len = 0;
	short op_len = 0;
	unsigned int i, j;
	dm_easy_mesh_t *dm;
	dm_op_class_t *op_class;
	em_radio_op_restriction_t *op_rest;
	em_radio_op_restrict_op_class_t *op_class_rest;
	em_radio_op_restrict_channel_t *chan_rest;

	dm = get_data_model();

	op_rest = (em_radio_op_restriction_t *)buff;

    memcpy(op_rest->ruid, get_radio_interface_mac(), sizeof(em_radio_id_t));
	op_rest->op_classes_num = 0;
	op_class_rest = op_rest->op_classes;
	len += sizeof(em_radio_op_restriction_t);

	for (i = 0; i < dm->m_num_opclass; i++) {
		op_class = &dm->m_op_class[i];
		if ((memcmp(op_class->m_op_class_info.id.ruid, op_rest->ruid, sizeof(em_radio_id_t)) == 0)	&&
			(op_class->m_op_class_info.id.type == em_op_class_type_capability)) {

			op_class_rest->op_class = op_class->m_op_class_info.op_class;
			op_class_rest->channels_num = op_class->m_op_class_info.num_non_op_channels;
			op_len += sizeof(em_radio_op_restrict_op_class_t);
			chan_rest = op_class_rest->channels;
			for (j = 0; j < op_class_rest->channels_num; j++) {
				chan_rest->channel = op_class->m_op_class_info.non_op_channel[j];
				chan_rest = (em_radio_op_restrict_channel_t *)((unsigned char *)chan_rest + sizeof(em_radio_op_restrict_channel_t));	
				op_len += sizeof(em_radio_op_restrict_channel_t);
			}
			len += op_len; 
			op_class_rest = (em_radio_op_restrict_op_class_t *)((unsigned char *)op_class_rest + op_len);
			op_len = 0;
			op_rest->op_classes_num++;
		}

	}	

	return len;
}

int em_channel_t::send_channel_pref_report_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_channel_pref_rprt;
    int len = 0;
    short sz;
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

    // Zero or more Channel Preference TLVs (see section 17.2.13).
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_channel_pref;
    sz = create_channel_pref_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // Zero or more Radio Operation Restriction TLVs (see section 17.2.14).
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_radio_op_restriction;
    sz = create_radio_op_restriction_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // Zero or one CAC Completion Report TLV (see section 17.2.44) [Profile-2].
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_cac_cmpltn_rprt;
    sz = create_cac_complete_report_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // One CAC Status Report TLV (see section 17.2.45) [Profile-2].
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_cac_sts_rprt;
    sz = create_cac_status_report_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_channel_pref_rprt, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Channel Preference Report msg validation failed\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Channel Preference Report send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }
        
    printf("%s:%d: Channel Preference Report send success\n", __func__, __LINE__);

    return len;
}

int em_channel_t::handle_channel_pref_rprt(unsigned char *buff, unsigned int len)
{
	set_state(em_state_ctrl_channel_queried);
	return 0;
}

void em_channel_t::process_msg(unsigned char *data, unsigned int len)
{
    em_raw_hdr_t *hdr;
    em_cmdu_t *cmdu;
    
    hdr = (em_raw_hdr_t *)data;
    cmdu = (em_cmdu_t *)(data + sizeof(em_raw_hdr_t));
    
    switch (htons(cmdu->type)) {
        case em_msg_type_channel_pref_query:
            send_channel_pref_report_msg();
            break; 
    
        case em_msg_type_channel_pref_rprt:
            send_channel_pref_report_msg();
            break; 
    
        default:
            break;
    }
}

void em_channel_t::process_ctrl_state()
{
    switch (get_state()) {
        case em_state_ctrl_channel_query_pending:
            send_channel_pref_query_msg();
            break;

        case em_state_ctrl_channel_select_pending:
            send_channel_sel_request_msg();
            break; 
    }
}

em_channel_t::em_channel_t()
{
    m_channel_pref_query_tx_cnt = 0;
    m_channel_sel_req_tx_cnt = 0;
}

em_channel_t::~em_channel_t()
{

}


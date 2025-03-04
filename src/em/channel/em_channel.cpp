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
#include "em_cmd_exec.h"
#include "util.h"

short em_channel_t::create_channel_pref_tlv_agent(unsigned char *buff)
{
    short len = 0;
    unsigned int i, j;
    em_channel_pref_t	*pref;
    em_channel_pref_op_class_t	*pref_op_class;
    dm_easy_mesh_t *dm;
    dm_op_class_t	*op_class;
    unsigned char *tmp;
    unsigned char pref_bits = 0xee;
    unsigned int num_of_channel = 0;
    em_channels_list_t *channel_list;

    dm = get_data_model();
    pref = (em_channel_pref_t *)buff;
    memcpy(pref->ruid, get_radio_interface_mac(), sizeof(mac_address_t));
    pref_op_class = pref->op_classes;
    pref->op_classes_num = 0;

    tmp = (unsigned char *)pref_op_class;
    len += sizeof(em_channel_pref_t);

    for (i = 0; i < dm->m_num_opclass; i++) {
	op_class = &dm->m_op_class[i];
	if (((memcmp(op_class->m_op_class_info.id.ruid, get_radio_interface_mac(), sizeof(mac_address_t)) == 0) &&
                                        (op_class->m_op_class_info.id.type == em_op_class_type_capability)) == false) {
	    continue;
        }
	
	pref_op_class->op_class = op_class->m_op_class_info.op_class;
	num_of_channel = op_class->m_op_class_info.num_channels;
	channel_list = &pref_op_class->channels;
	len += sizeof(em_channel_pref_op_class_t);
	pref_op_class->num = num_of_channel;
	for (j = 0; j < num_of_channel; j++) {
	    memcpy(channel_list->channel, (unsigned char *)&op_class->m_op_class_info.channels[j], sizeof(unsigned char));
	    channel_list =(em_channels_list_t *)((unsigned char *)channel_list + sizeof(unsigned char));
	    len += sizeof(unsigned char);
	}

	tmp += sizeof(em_channel_pref_op_class_t) + pref_op_class->num;
	memcpy(tmp, &pref_bits, sizeof(unsigned char));
	len += sizeof(unsigned char);
	tmp += sizeof(unsigned char);
        pref_op_class = (em_channel_pref_op_class_t *)tmp;
        pref->op_classes_num++;
		
    }
    return len;
}

short em_channel_t::create_channel_scan_req_tlv(unsigned char *buff)
{
    short len = 0;
	em_channel_scan_req_t *req;
	em_channel_scan_req_op_class_t *req_op_class;
	dm_op_class_t *opclass;
	dm_easy_mesh_t *dm;
	unsigned int i, j;

	dm = get_data_model();

	req = (em_channel_scan_req_t *)buff;
	req->perform_fresh_scan = 0;

	req->num_radios = 1;
	req->num_op_classes = 0;
	memcpy(req->ruid, get_radio_interface_mac(), sizeof(mac_address_t));
	len += sizeof(em_channel_scan_req_t);

	req_op_class = req->op_class;
	for (i = 0; i < dm->get_num_op_class(); i++) {
		opclass = &dm->m_op_class[i];
		if (opclass->m_op_class_info.id.type != em_op_class_type_scan_param) {
			continue;
		}

		req_op_class->op_class = opclass->m_op_class_info.op_class;
		req_op_class->num_channels = opclass->m_op_class_info.num_channels;

		for (j = 0; j < req_op_class->num_channels; j++) {
			req_op_class->channel_list[j] = opclass->m_op_class_info.channels[j];
		}
	
		len += (sizeof(em_channel_scan_req_op_class_t) + req_op_class->num_channels*sizeof(unsigned char));	
		
		req->num_op_classes++;
		req_op_class = (em_channel_scan_req_op_class_t *)((unsigned char *)req_op_class + sizeof(em_channel_scan_req_op_class_t) + req_op_class->num_channels*sizeof(unsigned char));
	}

	return len;
}

short em_channel_t::create_channel_pref_tlv(unsigned char *buff)
{
    short len = 0;
    unsigned int i, j;
    em_channel_pref_t       *pref;
    em_channel_pref_op_class_t      *pref_op_class;
    dm_easy_mesh_t *dm;
    dm_op_class_t   *op_class;
    unsigned char *tmp;
    unsigned char pref_bits = 0xee;
    unsigned int num_of_channel = 0;
    em_channels_list_t *channel_list;
    em_device_info_t *device ;

    dm = get_data_model();
    pref = (em_channel_pref_t *)buff;
    memcpy(pref->ruid, get_radio_interface_mac(), sizeof(mac_address_t));
    pref_op_class = pref->op_classes;
    pref->op_classes_num = 0;
    device = dm->get_device_info();

    tmp = (unsigned char *)pref_op_class;
    len += sizeof(em_channel_pref_t);

    for (i = 0; i < dm->m_num_opclass; i++) {
        op_class = &dm->m_op_class[i];
        if (((memcmp(op_class->m_op_class_info.id.ruid, device->intf.mac, sizeof(mac_address_t)) == 0)     &&
                    (op_class->m_op_class_info.id.type == em_op_class_type_anticipated)) == false) {
            continue;
        }
        
        pref_op_class->op_class = op_class->m_op_class_info.op_class;
        num_of_channel = op_class->m_op_class_info.num_channels;
        channel_list = &pref_op_class->channels;
        len += sizeof(em_channel_pref_op_class_t);
        pref_op_class->num = num_of_channel;
        for (j = 0; j < num_of_channel; j++) {
            memcpy(channel_list->channel, (unsigned char *)&op_class->m_op_class_info.channels[j], sizeof(unsigned char));
            channel_list =(em_channels_list_t *)((unsigned char *)channel_list + sizeof(unsigned char));
            len += sizeof(unsigned char);
        }

        tmp += sizeof(em_channel_pref_op_class_t) + pref_op_class->num;
        memcpy(tmp, &pref_bits, sizeof(unsigned char));
        len += sizeof(unsigned char);
        tmp += sizeof(unsigned char);
        pref_op_class = (em_channel_pref_op_class_t *)tmp;
        pref->op_classes_num++;
    }
    return len;
}

short em_channel_t::create_transmit_power_limit_tlv(unsigned char *buff)
{
    int len = 0;
    em_tx_power_limit_t	*tx_power_limit;

    tx_power_limit = (em_tx_power_limit_t *)buff;
    memcpy(tx_power_limit->ruid, get_radio_interface_mac(), sizeof(mac_address_t));
    
    dm_radio_t* radio = get_data_model()->get_radio(get_radio_interface_mac());
    em_radio_info_t* radio_info = radio->get_radio_info();
    tx_power_limit->tx_power_eirp = (unsigned char)radio_info->transmit_power_limit;

    len += sizeof(em_tx_power_limit_t);

    return len;
}

int em_channel_t::send_channel_scan_request_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_channel_scan_req;
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

	// One Channel Scan Request TLV (see section 17.2.39).
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_channel_scan_req;
    sz = create_channel_scan_req_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));
    if (em_msg_t(em_msg_type_channel_scan_req, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Channel Selection Request msg failed validation in tnx end\n");
        //return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Channel Selection Request msg failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

	set_state(em_state_ctrl_configured);

    return len;

}

short em_channel_t::create_channel_scan_res_tlv(unsigned char *buff, unsigned int index)
{
	unsigned char *tmp = buff, ssid_len, bw_len, i;
    short len = 0;
	char date_time[EM_DATE_TIME_BUFF_SZ];
    dm_easy_mesh_t *dm;
	dm_scan_result_t *scan_res;
	em_neighbor_t *nbr;
	unsigned short param;
	em_channel_scan_result_t *res = (em_channel_scan_result_t *)buff;

    dm = get_data_model();
	scan_res = dm->get_scan_result(index);

	memcpy(res->ruid, get_radio_interface_mac(), sizeof(mac_address_t));	
	memcpy(&res->op_class, &scan_res->m_scan_result.id.op_class, sizeof(unsigned char));
	memcpy(&res->channel, &scan_res->m_scan_result.id.channel, sizeof(unsigned char));
	res->scan_status = scan_res->m_scan_result.scan_status;
	util::get_date_time_rfc3399(date_time, sizeof(date_time));
	memcpy(res->timestamp, date_time, strlen(date_time) + 1);
	res->timestamp_len = strlen(date_time);	
	
	len += sizeof(em_channel_scan_result_t) + strlen(date_time);
	tmp += sizeof(em_channel_scan_result_t) + strlen(date_time);
	
	memcpy(tmp, &scan_res->m_scan_result.util, sizeof(unsigned char));
	len += sizeof(unsigned char);
	tmp += sizeof(unsigned char);

	memcpy(tmp, &scan_res->m_scan_result.noise, sizeof(unsigned char));
	len += sizeof(unsigned char);
	tmp += sizeof(unsigned char);

	param = htons(scan_res->m_scan_result.num_neighbors);
	memcpy(tmp, (unsigned char *)&param, sizeof(unsigned short));
	len += sizeof(unsigned short);
	tmp += sizeof(unsigned short);
	
	for (i = 0; i < scan_res->m_scan_result.num_neighbors; i++) {
		nbr = &scan_res->m_scan_result.neighbor[i];

		memcpy(tmp, nbr->bssid, sizeof(mac_address_t));
		len += sizeof(mac_address_t);
		tmp += sizeof(mac_address_t);

		ssid_len = strlen(nbr->ssid);
		memcpy(tmp, &ssid_len, sizeof(unsigned char));
		len += sizeof(unsigned char);
		tmp += sizeof(unsigned char);

		memcpy(tmp, nbr->ssid, ssid_len);
		len += ssid_len;
		tmp += ssid_len;

		memcpy(tmp, &nbr->signal_strength, sizeof(unsigned char));
		len += sizeof(unsigned char);
		tmp += sizeof(unsigned char);
	
		switch (nbr->bandwidth) {
			case WIFI_CHANNELBANDWIDTH_20MHZ:
				bw_len = strlen("20");
				memcpy(tmp, &bw_len, sizeof(unsigned char));

				len += sizeof(unsigned char);
				tmp += sizeof(unsigned char);

				memcpy(tmp, "20", strlen("20"));
				len += strlen("20");
				tmp += strlen("20");
				break;

			case WIFI_CHANNELBANDWIDTH_40MHZ:
				bw_len = strlen("40");
				memcpy(tmp, &bw_len, sizeof(unsigned char));

				len += sizeof(unsigned char);
				tmp += sizeof(unsigned char);

				memcpy(tmp, "40", strlen("40"));
				len += strlen("40");
				tmp += strlen("40");
				break;

			case WIFI_CHANNELBANDWIDTH_80MHZ:
				bw_len = strlen("80");
				memcpy(tmp, &bw_len, sizeof(unsigned char));

				len += sizeof(unsigned char);
				tmp += sizeof(unsigned char);

				memcpy(tmp, "80", strlen("80"));
				len += strlen("80");
				tmp += strlen("80");
				break;

			case WIFI_CHANNELBANDWIDTH_160MHZ:
				bw_len = strlen("160");
				memcpy(tmp, &bw_len, sizeof(unsigned char));

				len += sizeof(unsigned char);
				tmp += sizeof(unsigned char);

				memcpy(tmp, "160", strlen("160"));
				len += strlen("160");
				tmp += strlen("160");
				break;

			case WIFI_CHANNELBANDWIDTH_320MHZ:
				bw_len = strlen("320");
				memcpy(tmp, &bw_len, sizeof(unsigned char));

				len += sizeof(unsigned char);
				tmp += sizeof(unsigned char);

				memcpy(tmp, "320", strlen("320"));
				len += strlen("320");
				tmp += strlen("320");
				break;

		}	
		
		memcpy(tmp, &nbr->bss_color, sizeof(unsigned char));
		len += sizeof(unsigned char);
		tmp += sizeof(unsigned char);
	
		memcpy(tmp, &nbr->channel_util, sizeof(unsigned char));
		len += sizeof(unsigned char);
		tmp += sizeof(unsigned char);

		param = htons(nbr->sta_count);	
		memcpy(tmp, &param, sizeof(unsigned short));
		len += sizeof(unsigned short);
		tmp += sizeof(unsigned short);
	
	}			

	memcpy(tmp, &scan_res->m_scan_result.aggr_scan_duration, sizeof(unsigned int));
	len += sizeof(unsigned int);
	tmp += sizeof(unsigned int);
	
	memcpy(tmp, &scan_res->m_scan_result.scan_type, sizeof(unsigned char));
	len += sizeof(unsigned char);
	tmp += sizeof(unsigned char);

    return len;
}


int em_channel_t::send_channel_scan_report_msg(unsigned int *last_index)
{
    unsigned char buff[MAX_EM_BUFF_SZ*3]; //Increased size to accommodate if max number of neighbor are present in the message
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_channel_scan_rprt;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    short sz = 0;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
	char date_time[EM_DATE_TIME_BUFF_SZ];
    dm_easy_mesh_t *dm;
	unsigned int i, start_idx = *last_index;
	unsigned char time_len;

    dm = get_data_model();

    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
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

    // One Timestamp TLV (see section 17.2.41).
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_timestamp;
	util::get_date_time_rfc3399(date_time, sizeof(date_time));
	sz = strlen(date_time) + 1;
	time_len = strlen(date_time);
	memcpy(tlv->value, &time_len, sizeof(unsigned char));
	memcpy(tlv->value + 1, date_time, sz);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // One or more Channel Scan Result TLVs (see section 17.2.40).
	for (i = start_idx; i < dm->get_num_scan_results(); i++) {
    	tlv = (em_tlv_t *)tmp;
    	tlv->type = em_tlv_type_channel_scan_rslt;
    	sz = create_channel_scan_res_tlv(tlv->value, i);
    	tlv->len = htons(sz);

    	tmp += (sizeof(em_tlv_t) + sz);
    	len += (sizeof(em_tlv_t) + sz);

		if (len > EM_MAX_CHANNEL_SCAN_RPRT_MSG_LEN) {
			break;	
		}
	}
	
	*last_index = i;

    // Zero or more MLD Structure TLV (see section 17.2.99)

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));
    //if (em_msg_t(em_msg_type_channel_scan_req, em_profile_type_3, buff, len).validate(errors) == 0) {
        //printf("Channel Selection Request msg failed validation in tnx end\n");
        //return -1;
    //}

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Channel Selection Request msg failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    set_state(em_state_ctrl_configured);

    return len;

}

short em_channel_t::create_spatial_reuse_req_tlv(unsigned char *buff)
{
    int len = 0;
    em_spatial_reuse_req_t *spatial_reuse_req;

    spatial_reuse_req = (em_spatial_reuse_req_t *)buff;
    memcpy(spatial_reuse_req->ruid, get_radio_interface_mac(), sizeof(mac_address_t));

    dm_radio_t *radio = get_data_model()->get_radio(get_radio_interface_mac());
    em_radio_info_t *radio_info = radio->get_radio_info();
    spatial_reuse_req->bss_color = radio_info->bss_color;
    spatial_reuse_req->hesiga_spatial_reuse_value15_allowed = radio_info->hesiga_spatial_reuse_value15_allowed;
    spatial_reuse_req->srg_info_valid = radio_info->srg_information_valid;
    spatial_reuse_req->non_srg_offset_valid = (unsigned char)radio_info->non_srg_offset_valid;
    spatial_reuse_req->psr_disallowed = (unsigned char)radio_info->psr_disallowed;
    spatial_reuse_req->non_srg_obsspd_max_offset = (unsigned char)radio_info->non_srg_obsspd_max_offset;
    spatial_reuse_req->srg_obsspd_min_offset = (unsigned char)radio_info->srg_obsspd_min_offset;
    spatial_reuse_req->srg_obsspd_max_offset = (unsigned char)radio_info->srg_obsspd_max_offset;
    memcpy(spatial_reuse_req->srg_bss_color_bitmap, radio_info->srg_bss_color_bitmap, sizeof(spatial_reuse_req->srg_bss_color_bitmap));
    memcpy(spatial_reuse_req->srg_partial_bssid_bitmap, radio_info->srg_partial_bssid_bitmap, sizeof(spatial_reuse_req->srg_partial_bssid_bitmap));

    len += sizeof(em_spatial_reuse_req_t);

    return len;
}

short em_channel_t::create_eht_operations_tlv(unsigned char *buff)
{
    short len = 0;
    int i = 0, j = 0;
    unsigned char *tmp = buff;
    dm_easy_mesh_t  *dm;
    em_eht_operations_bss_t  *eht_ops_bss;

    dm = get_data_model();

    unsigned char num_radios = dm->get_num_radios();
    unsigned char num_bss;

    memcpy(tmp, &num_radios, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    len += sizeof(unsigned char);

    for (i = 0; i < num_radios; i++) {
        memcpy(tmp, dm->get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t));
        tmp += sizeof(mac_address_t);
        len += sizeof(mac_address_t);

        num_bss = dm->get_num_bss();

        memcpy(tmp, &num_bss, sizeof(unsigned char));
        tmp += sizeof(unsigned char);
        len += sizeof(unsigned char);


        for (j = 0; j < dm->get_num_bss(); j++) {
        	if (memcmp(dm->m_bss[j].m_bss_info.ruid.mac, dm->get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t)) != 0) {
            	continue;
        	}

            memcpy(tmp, dm->m_bss[j].m_bss_info.bssid.mac, sizeof(mac_address_t));
            tmp += sizeof(mac_address_t);
            len += sizeof(mac_address_t);

            eht_ops_bss = &dm->m_bss[j].m_bss_info.eht_ops;
            memcpy(tmp, eht_ops_bss, sizeof(em_eht_operations_bss_t));
            tmp += sizeof(em_eht_operations_bss_t);
            len += sizeof(em_eht_operations_bss_t);
        }
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
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_tx_power;
    sz = create_transmit_power_limit_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // Zero or more Spatial Reuse Request TLVs (see section 17.2.89).
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_spatial_reuse_req;
    sz = create_spatial_reuse_req_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // Zero or one EHT Operations TLV (see section 17.2.103)
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_eht_operations;
    sz = create_eht_operations_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

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

int em_channel_t::send_channel_sel_response_msg(em_chan_sel_resp_code_type_t code, unsigned short msg_id)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_channel_sel_rsp;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    em_channel_sel_rsp_t *resp;
    em_prof2_error_t *prof2_error;
    unsigned char *tmp = buff;
    dm_easy_mesh_t *dm;
    unsigned short type = htons(ETH_P_1905);

    dm = get_data_model();

    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
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
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // one or more Channel selection Response TLVs (see section 17.2.16).
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_channel_sel_resp;
    tlv->len = htons(sizeof(em_channel_sel_rsp_t));
    resp = (em_channel_sel_rsp_t *)tlv->value;
    memcpy(resp->ruid, get_radio_interface_mac(), sizeof(mac_address_t));
    memcpy(&resp->response_code, (unsigned char *)&code, sizeof(unsigned char));

    tmp += (sizeof(em_tlv_t) + sizeof(em_channel_sel_rsp_t));
    len += (sizeof(em_tlv_t) + sizeof(em_channel_sel_rsp_t));
    
	// Zero or more Spatial Reuse Config Response TLVs (see section 17.2.91)
	tlv = (em_tlv_t *)tmp;
	tlv->type = em_tlv_type_spatial_reuse_cfg_rsp;
	tlv->len = htons(sizeof(em_spatial_reuse_cfg_rsp_t));
	resp = (em_channel_sel_rsp_t *)tlv->value;
	memcpy(resp->ruid, get_radio_interface_mac(), sizeof(mac_address_t));
    memcpy(&resp->response_code, (unsigned char *)&code, sizeof(unsigned char));


    tmp += (sizeof(em_tlv_t) + sizeof(em_channel_sel_rsp_t));
    len += (sizeof(em_tlv_t) + sizeof(em_channel_sel_rsp_t));

    //Zero or more Profile-2 Error Code TLV (see section 17.2.51)
    tlv = (em_tlv_t *)tmp;
	tlv->type = em_tlv_type_profile_2_error_code;
	tlv->len = htons(sizeof(em_prof2_error_t));
	prof2_error = (em_prof2_error_t *)tlv->value;
    prof2_error->reason_code = em_prof2_error_code_reason_code_reserved;  // reason_code = 0x0

    tmp += (sizeof(em_tlv_t) + sizeof(em_prof2_error_t));
    len += (sizeof(em_tlv_t) + sizeof(em_prof2_error_t));

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
	memcpy(rprt_op_class->ruid, get_radio_interface_mac(), sizeof(mac_address_t));
	rprt_op_class->op_classes_num = 0;
	rprt_channel = rprt_op_class->op_classes;
	len += sizeof(em_op_channel_rprt_t);

	for (i = 0; i < dm->m_num_opclass; i++) {
		op_class = &dm->m_op_class[i];
		if ((memcmp(op_class->m_op_class_info.id.ruid, rprt_op_class->ruid, sizeof(mac_address_t)) == 0)	&&
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

short em_channel_t::create_spatial_reuse_report_tlv(unsigned char *buff)
{
    short len = 0;
    unsigned int i;
    dm_easy_mesh_t *dm;
    em_spatial_reuse_rprt_t *rprt_spatial_reuse;
    unsigned char *tmp;

    dm = get_data_model();

    rprt_spatial_reuse = (em_spatial_reuse_rprt_t *)buff;
    memcpy(rprt_spatial_reuse->ruid, get_radio_interface_mac(), sizeof(mac_address_t));

    dm_radio_t *radio = dm->get_radio(get_radio_interface_mac());
    em_radio_info_t *radio_info = radio->get_radio_info();
    rprt_spatial_reuse->partial_bss_color = radio_info->partial_bss_color;
    rprt_spatial_reuse->bss_color = radio_info->bss_color;
    rprt_spatial_reuse->hesiga_spatial_reuse_value15_allowed = radio_info->hesiga_spatial_reuse_value15_allowed;
    rprt_spatial_reuse->srg_info_valid = radio_info->srg_information_valid;
    rprt_spatial_reuse->non_srg_offset_valid = (unsigned char)radio_info->non_srg_offset_valid;
    rprt_spatial_reuse->psr_disallowed = (unsigned char)radio_info->psr_disallowed;
    rprt_spatial_reuse->non_srg_obsspd_max_offset = (unsigned char)radio_info->non_srg_obsspd_max_offset;
    rprt_spatial_reuse->srg_obsspd_min_offset = (unsigned char)radio_info->srg_obsspd_min_offset;
    rprt_spatial_reuse->srg_obsspd_max_offset = (unsigned char)radio_info->srg_obsspd_max_offset;
    memcpy(rprt_spatial_reuse->srg_bss_color_bitmap, radio_info->srg_bss_color_bitmap, sizeof(rprt_spatial_reuse->srg_bss_color_bitmap));
    memcpy(rprt_spatial_reuse->srg_partial_bssid_bitmap, radio_info->srg_partial_bssid_bitmap, sizeof(rprt_spatial_reuse->srg_partial_bssid_bitmap));
    memcpy(rprt_spatial_reuse->neigh_bss_color_in_use_bitmap, radio_info->neigh_bss_color_in_use_bitmap, sizeof(rprt_spatial_reuse->neigh_bss_color_in_use_bitmap));

    len += sizeof(em_spatial_reuse_rprt_t);
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
    mac_addr_str_t mac_str;

    dm = get_data_model();

    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
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
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_spatial_reuse_rep;
    sz = create_spatial_reuse_report_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // Zero or more EHT Operations TLV (see section 17.2.103)
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_eht_operations;
    sz = create_eht_operations_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));
    if (em_msg_t(em_msg_type_op_channel_rprt, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Operating Channel Report msg failed validation in tnx end\n");   
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d:  Operating Channel Report msg failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }
    dm_easy_mesh_t::macbytes_to_string(get_radio_interface_mac(), mac_str);
    printf("%s:%d Operating Channel Report msg send for %s \n", __func__, __LINE__,mac_str);
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

    // One AP Radio Identifier tlv 17.2.3
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_radio_id;
    memcpy(tlv->value, get_radio_interface_mac(), sizeof(mac_address_t));
    tlv->len = htons(sizeof(mac_address_t));

    tmp += (sizeof(em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof(em_tlv_t) + sizeof(mac_address_t));


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
	mac_address_t ruid;

	dm = get_data_model();
	memcpy(ruid, get_radio_interface_mac(), sizeof(mac_address_t));

	rprt_avail = (em_cac_status_rprt_avail_t *)tmp;
	rprt_avail->avail_num = 0;
	avail = rprt_avail->avail;	
	len += sizeof(em_cac_status_rprt_avail_t);
	tmp += sizeof(em_cac_status_rprt_avail_t);

	for (i = 0; i < dm->m_num_opclass; i++) {
		op_class = &dm->m_op_class[i];
		if ((memcmp(op_class->m_op_class_info.id.ruid, ruid, sizeof(mac_address_t)) == 0)	&&
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
		if ((memcmp(op_class->m_op_class_info.id.ruid, ruid, sizeof(mac_address_t)) == 0)	&&
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
		if ((memcmp(op_class->m_op_class_info.id.ruid, ruid, sizeof(mac_address_t)) == 0)	&&
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

	memcpy(cac_comp_radio->ruid, comp->m_cac_comp_info.ruid, sizeof(mac_address_t));
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

    memcpy(op_rest->ruid, get_radio_interface_mac(), sizeof(mac_address_t));
	op_rest->op_classes_num = 0;
	op_class_rest = op_rest->op_classes;
	len += sizeof(em_radio_op_restriction_t);

	for (i = 0; i < dm->m_num_opclass; i++) {
		op_class = &dm->m_op_class[i];
		if ((memcmp(op_class->m_op_class_info.id.ruid, op_rest->ruid, sizeof(mac_address_t)) == 0)	&&
			(op_class->m_op_class_info.id.type == em_op_class_type_capability)) {

			op_class_rest->op_class = op_class->m_op_class_info.op_class;
			op_class_rest->channels_num = op_class->m_op_class_info.num_channels;
			op_len += sizeof(em_radio_op_restrict_op_class_t);
			chan_rest = op_class_rest->channels;
			for (j = 0; j < op_class_rest->channels_num; j++) {
				chan_rest->channel = op_class->m_op_class_info.channels[j];
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
    unsigned short msg_id = get_current_cmd()->get_data_model()->get_msg_id();
    unsigned short  msg_type = em_msg_type_channel_pref_rprt;
    int len = 0;
    short sz;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm;
    mac_addr_str_t mac_str;

    dm = get_data_model();

    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
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
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // Zero or more Channel Preference TLVs (see section 17.2.13).
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_channel_pref;
    sz = create_channel_pref_tlv_agent(tlv->value);
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

    // Zero or one EHT Operations TLV (see section 17.2.103)
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_eht_operations;
    sz = create_eht_operations_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

/*
    if (em_msg_t(em_msg_type_channel_pref_rprt, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Channel Preference Report msg validation failed\n");
        return -1;
    }
*/
    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Channel Preference Report send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }
        
    printf("%s:%d: Channel Preference Report send success\n", __func__, __LINE__);
    return len;
}

int em_channel_t::send_available_spectrum_inquiry_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_avail_spectrum_inquiry;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    short sz = 0;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm;

    dm = get_data_model();

    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
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

    // Zero or more Channel Preference TLVs (see section 17.2.13).
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_channel_pref;
    sz = create_channel_pref_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

	// One Available Spectrum Inquiry Request TLV (see section 17.2.104)
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_avail_spectrum_inquiry_reg;
    tlv->len = htons(sizeof(em_avail_spectrum_inquiry_req_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_avail_spectrum_inquiry_req_t));
    len += (sizeof(em_tlv_t) + sizeof(em_avail_spectrum_inquiry_req_t));

    // One Available Spectrum Inquiry Response TLV (see section 17.2.105)
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_avail_spectrum_inquiry_rsp;
    tlv->len = htons(sizeof(em_avail_spectrum_inquiry_rsp_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_avail_spectrum_inquiry_rsp_t));
    len += (sizeof(em_tlv_t) + sizeof(em_avail_spectrum_inquiry_rsp_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));
    if (em_msg_t(em_msg_type_avail_spectrum_inquiry, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Available Spectrum Inquiry msg failed validation in tnx end\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Available Spectrum Inquiry msg failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    return len;

}

int em_channel_t::handle_op_channel_report(unsigned char *buff, unsigned int len)
{
    dm_easy_mesh_t *dm;
    unsigned int i = 0, found = 0;
    em_op_class_info_t  *op_class_info;
    em_op_channel_rprt_t *rpt = (em_op_channel_rprt_t *) buff;
    dm = get_data_model();

    for (i = 0; i < dm->m_num_opclass; i++) {
        op_class_info = &dm->m_op_class[i].m_op_class_info;
        if (((memcmp(op_class_info->id.ruid, get_radio_interface_mac(), sizeof(mac_address_t)) == 0) &&
                    (op_class_info->id.type == em_op_class_type_current)) == true) {
            op_class_info->op_class = (unsigned int) rpt->op_classes[0].op_class;
            op_class_info->channel = (unsigned int) rpt->op_classes[0].channel;
            found++;
        }
    }
    if (found == 0) {
        op_class_info = &dm->m_op_class[dm->get_num_op_class()].m_op_class_info;
        op_class_info->id.type = em_op_class_type_current;
        memcpy(op_class_info->id.ruid, get_radio_interface_mac(), sizeof(mac_address_t));
        op_class_info->op_class = (unsigned int) rpt->op_classes[0].op_class;
        op_class_info->id.op_class = op_class_info->op_class;
        op_class_info->channel = (unsigned int) rpt->op_classes[0].channel;
        dm->set_num_op_class(dm->get_num_op_class() + 1);
        dm->set_db_cfg_param(db_cfg_type_op_class_list_update, "");
        dm->set_db_cfg_param(db_cfg_type_radio_list_update, "");
    }
    return 0;
}

int em_channel_t::handle_spatial_reuse_report(unsigned char *buff, unsigned int len)
{
    dm_easy_mesh_t *dm;
    unsigned int i = 0, found = 0;
    em_spatial_reuse_rprt_t *rpt = (em_spatial_reuse_rprt_t *) buff;
    dm = get_data_model();

    dm_radio_t *radio = dm->get_radio(get_radio_interface_mac());
    em_radio_info_t *radio_info = radio->get_radio_info();
    radio_info->partial_bss_color = rpt->partial_bss_color;
    radio_info->bss_color = rpt->bss_color;
    radio_info->hesiga_spatial_reuse_value15_allowed = rpt->hesiga_spatial_reuse_value15_allowed;
    radio_info->srg_information_valid = rpt->srg_info_valid;
    radio_info->non_srg_offset_valid = (unsigned char)rpt->non_srg_offset_valid;
    radio_info->psr_disallowed = (unsigned char)rpt->psr_disallowed;
    radio_info->non_srg_obsspd_max_offset = (unsigned char)rpt->non_srg_obsspd_max_offset;
    radio_info->srg_obsspd_min_offset = (unsigned char)rpt->srg_obsspd_min_offset;
    radio_info->srg_obsspd_max_offset = (unsigned char)rpt->srg_obsspd_max_offset;
    memcpy(radio_info->srg_bss_color_bitmap, rpt->srg_bss_color_bitmap, sizeof(radio_info->srg_bss_color_bitmap));
    memcpy(radio_info->srg_partial_bssid_bitmap, rpt->srg_partial_bssid_bitmap, sizeof(radio_info->srg_partial_bssid_bitmap));
    memcpy(radio_info->neigh_bss_color_in_use_bitmap, rpt->neigh_bss_color_in_use_bitmap, sizeof(radio_info->neigh_bss_color_in_use_bitmap));

    return 0;
}


int em_channel_t::handle_channel_pref_tlv_ctrl(unsigned char *buff, unsigned int len)
{
    em_channel_pref_t   *pref = (em_channel_pref_t *) buff;
    em_channel_pref_op_class_t *channel_pref;
    unsigned int i = 0, j = 0;
	bool match_found = false;
    em_op_class_info_t      op_class_info[EM_MAX_OP_CLASS];
    em_op_class_info_t *pop_class_info;
    dm_easy_mesh_t *dm;

    dm = get_data_model();
    em_device_info_t    *device = dm->get_device_info();

	channel_pref = pref->op_classes;
	memcpy(op_class_info[i].id.ruid, pref->ruid, sizeof(mac_address_t));
	for (i = 0; i < pref->op_classes_num; i++) {
		memcpy(op_class_info[i].id.ruid, device->intf.mac, sizeof(mac_address_t));
		op_class_info[i].id.type = em_op_class_type_preference;
		op_class_info[i].op_class = (unsigned int)channel_pref->op_class;
		op_class_info[i].id.op_class = op_class_info[i].op_class;
		op_class_info[i].num_channels = (unsigned int)channel_pref->num;
		for (j = 0; j < op_class_info[i].num_channels; j++) {
			op_class_info[i].channels[j] = (unsigned int )channel_pref->channels.channel[j];
		}
		channel_pref = (em_channel_pref_op_class_t *)((unsigned char *)channel_pref + sizeof(em_channel_pref_op_class_t) +
				op_class_info[i].num_channels + sizeof(unsigned char));
		//printf("%s:%d op class: %d\tAnticipated Channels: %d\n", __func__, __LINE__, 
				//op_class_info[i].op_class, op_class_info[i].num_anticipated_channels);
	}
	
	for (i = 0; i < pref->op_classes_num; i++) {
		for (j = 0; j < dm->get_num_op_class(); j++) {
			pop_class_info = &dm->m_op_class[j].m_op_class_info;

			if ((memcmp(pop_class_info->id.ruid, op_class_info[i].id.ruid, sizeof(mac_address_t)) == 0) &&
						(pop_class_info->id.type == op_class_info[i].id.type) &&
						(pop_class_info->id.op_class == op_class_info[i].id.op_class)) {
				match_found = true;
				break;
			}
		}

		if (match_found == true) {
			match_found = false;
			continue;
		}
		
		pop_class_info = &dm->m_op_class[dm->get_num_op_class()].m_op_class_info;
		memcpy(pop_class_info, &op_class_info[i], sizeof(em_op_class_info_t));
		dm->set_num_op_class(dm->get_num_op_class() + 1);
		dm->set_db_cfg_param(db_cfg_type_op_class_list_update, "");
		dm->set_db_cfg_param(db_cfg_type_radio_list_update, "");
	}

    return 0;

}

int em_channel_t::handle_eht_operations_tlv_ctrl(unsigned char *buff, unsigned int len)
{
    short tmp_len = 0;
    int i = 0, j = 0, k = 0, l = 0;
    unsigned char *tmp = buff;
    dm_easy_mesh_t  *dm;
    em_eht_operations_bss_t  *eht_ops_bss;
    mac_address_t ruid, bss;
    bool found_radio = false, found_bss = false;

    unsigned char num_radios;
    unsigned char num_bss;

    memcpy(&num_radios, tmp, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    tmp_len += sizeof(unsigned char);

    dm = get_data_model();
//  Remove assert since channnel report is per radio
//  assert(num_radios == dm->get_num_radios());

    for (i = 0; i < num_radios; i++) {
        memcpy(&ruid, tmp, sizeof(mac_address_t));
        tmp += sizeof(mac_address_t);
        tmp_len += sizeof(mac_address_t);

        for (j = 0; j < dm->get_num_radios(); j++) {
            if (memcmp(ruid, dm->m_radio[j].m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) {
                found_radio = true;
                break;
            }

            if (found_radio == false) {
                // do not update anything and retrun error
                return -1;
            }
        }

        found_radio = false;
        memcpy(&num_bss, tmp, sizeof(unsigned char));
        tmp += sizeof(unsigned char);
        tmp_len += sizeof(unsigned char);

        for(k = 0; k < num_bss; k++) {
            memcpy(&bss, tmp, sizeof(mac_address_t));
            tmp += sizeof(mac_address_t);
            tmp_len += sizeof(mac_address_t);

            for(l = 0; l < dm->get_num_bss(); l++) {
                if (memcmp(bss, dm->m_bss[l].m_bss_info.bssid.mac, sizeof(mac_address_t)) == 0) {
                    found_bss = true;
                    break;
                }

                if (found_bss == false) {
                    // do not update anything and retrun error
                    return -1;
                }
            }

            found_bss = false;
            eht_ops_bss = &dm->m_bss[l].get_bss_info()->eht_ops;
            memcpy(eht_ops_bss, tmp, sizeof(em_eht_operations_bss_t));
            tmp += sizeof(em_eht_operations_bss_t);
            tmp_len += sizeof(em_eht_operations_bss_t);

        }
        
    }
    assert(tmp_len == len);

    return 0;
}


int em_channel_t::handle_channel_pref_rprt(unsigned char *buff, unsigned int len)
{
    em_tlv_t    *tlv;
    int tlv_len;

    tlv = (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_channel_pref) {
            handle_channel_pref_tlv_ctrl(tlv->value, htons(tlv->len));
        }
        if (tlv->type == em_tlv_eht_operations) {
            handle_eht_operations_tlv_ctrl(tlv->value, htons(tlv->len));
            break;
        }

        tlv_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

	set_state(em_state_ctrl_channel_queried);
	return 0;
}

int em_channel_t::handle_channel_pref_tlv(unsigned char *buff, op_class_channel_sel *op_class)
{
    em_channel_pref_t *pref = (em_channel_pref_t *) buff;
    em_channel_pref_op_class_t *channel_pref;
    unsigned int i = 0, j = 0;
	em_op_class_info_t op_class_info[EM_MAX_OP_CLASS];
	em_event_t  ev;
	em_bus_event_t *bev;

    channel_pref = pref->op_classes;
    if (pref != NULL) {
		channel_pref = pref->op_classes;
		memcpy(op_class_info[i].id.ruid, pref->ruid, sizeof(mac_address_t));
		for (i = 0; i < pref->op_classes_num; i++) {
			memcpy(op_class_info[i].id.ruid, pref->ruid, sizeof(mac_address_t));
			op_class_info[i].id.type = em_op_class_type_current;
			op_class_info[i].op_class = (unsigned int)channel_pref->op_class;
			op_class_info[i].id.op_class = op_class_info[i].op_class;
			op_class_info[i].num_channels = (unsigned int)channel_pref->num;
			for (j = 0; j < op_class_info[i].num_channels; j++) {
					op_class_info[i].channels[j] = (unsigned int )channel_pref->channels.channel[j];
			}
			channel_pref = (em_channel_pref_op_class_t *)((unsigned char *)channel_pref + sizeof(em_op_class_t) +
							op_class_info[i].num_channels);
		}

		op_class->num = 1;
		for (i = 0; i < pref->op_classes_num; i++) {
			if (get_band() == (dm_easy_mesh_t::get_freq_band_by_op_class(op_class_info[i].op_class))) {
				memcpy(&op_class->op_class_info[0], &op_class_info[i], sizeof(em_op_class_info_t));
				//printf("%s:%d Received channel selection request op_class=%d \n",__func__, __LINE__,op_class_info[i].op_class);
				break;
			}
		}
    }

    return 0;
}

int em_channel_t::handle_eht_operations_tlv(unsigned char *buff, em_eht_operations_t *eht_ops)
{
	short len = 0;
	int i = 0, j = 0, k = 0, l = 0;
	unsigned char *tmp = buff;

	unsigned char num_radios;
	unsigned char num_bss;

	memcpy(&num_radios, tmp, sizeof(unsigned char));
	eht_ops->radios_num = num_radios;
	tmp += sizeof(unsigned char);
	len += sizeof(unsigned char);

	if (num_radios > EM_MAX_RADIO_PER_AGENT) {
		printf("%s:%d Invalid radios count \n", __func__, __LINE__);
		return -1;
	}

	for (i = 0; i < num_radios; i++) {
		memcpy(&eht_ops->radios[i].ruid, tmp, sizeof(mac_address_t));
		tmp += sizeof(mac_address_t);
		len += sizeof(mac_address_t);

		memcpy(&num_bss, tmp, sizeof(unsigned char));
		eht_ops->radios[i].bss_num = num_bss;
		tmp += sizeof(unsigned char);
		len += sizeof(unsigned char);

		if (num_bss > EM_MAX_BSS_PER_RADIO) {
			printf("%s:%d Invalid bss count \n", __func__, __LINE__);
			continue;
		}

		for(j = 0; j < num_bss; j++) {
			memcpy(&eht_ops->radios[i].bss[j], tmp, sizeof(em_eht_operations_bss_t));
			tmp += sizeof(em_eht_operations_bss_t);
			len += sizeof(em_eht_operations_bss_t);
		}
	}

	return 0;
}

int em_channel_t::handle_channel_pref_query(unsigned char *buff, unsigned int len)
{
    em_cmdu_t *cmdu;
    em_bus_event_type_channel_pref_query_params_t params;

    cmdu = (em_cmdu_t *)(buff + sizeof(em_raw_hdr_t));

    memcpy(params.mac, get_radio_interface_mac(), sizeof(mac_address_t));
    params.msg_id = ntohs(cmdu->id);
   
	get_mgr()->io_process(em_bus_event_type_channel_pref_query, (unsigned char *)&params, sizeof(em_bus_event_type_channel_pref_query_params_t)); 

	return 0;
}

int em_channel_t::handle_channel_sel_req(unsigned char *buff, unsigned int len)
{
    em_tlv_t    *tlv;
    int tlv_len;

    op_class_channel_sel op_class;

    tlv = (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_channel_pref) {
            handle_channel_pref_tlv(tlv->value, &op_class);
        }
        if (tlv->type == em_tlv_type_tx_power) {
			memcpy(&op_class.tx_power, tlv->value, sizeof(em_tx_power_limit_t));
        }
        if (tlv->type == em_tlv_type_spatial_reuse_req) {
            memcpy(&op_class.spatial_reuse_req, tlv->value, sizeof(em_spatial_reuse_req_t));
        }
        if (tlv->type == em_tlv_eht_operations) {
            handle_eht_operations_tlv(tlv->value, &op_class.eht_ops);
            break;
        }

        tlv_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

	op_class.freq_band = get_band();
   
	get_mgr()->io_process(em_bus_event_type_channel_sel_req, (unsigned char *)&op_class, sizeof(op_class_channel_sel)); 
    
	printf("%s:%d Received channel selection request \n",__func__, __LINE__);

    return 0;
}

int em_channel_t::handle_channel_sel_rsp(unsigned char *buff, unsigned int len)
{
    set_state(em_state_ctrl_channel_selected);
    return 0;
}

int em_channel_t::handle_operating_channel_rprt(unsigned char *buff, unsigned int len)
{
    em_tlv_t    *tlv;
    int tlv_len;

    tlv = (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_op_channel_report) {
            handle_op_channel_report(tlv->value, htons(tlv->len));
        }
        if (tlv->type == em_tlv_type_spatial_reuse_rep) {
            handle_spatial_reuse_report(tlv->value, htons(tlv->len));
        }
        if (tlv->type == em_tlv_eht_operations) {
            handle_eht_operations_tlv_ctrl(tlv->value, htons(tlv->len));
            break;
        }

        tlv_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }
    set_state(em_state_ctrl_configured);

	return 0;
}

int em_channel_t::handle_channel_scan_req(unsigned char *buff, unsigned int len)
{
    em_tlv_t    *tlv;
    int tlv_len;
	em_channel_scan_req_t *req;
	em_channel_scan_req_op_class_t	*op_class;
	em_scan_params_t	params;
	unsigned int i;

	memset(&params, 0, sizeof(em_scan_params_t));

    tlv = (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_channel_scan_req) {
			req = (em_channel_scan_req_t *)tlv->value;

			memcpy(params.ruid, get_radio_interface_mac(), sizeof(mac_address_t));
			params.num_op_classes = req->num_op_classes;
					
			op_class = req->op_class;
			for (i = 0; i < params.num_op_classes; i++) {
				params.op_class[i].op_class = op_class->op_class;
				params.op_class[i].num_channels = op_class->num_channels;
				memcpy(params.op_class[i].channels, op_class->channel_list, op_class->num_channels);

				op_class = (em_channel_scan_req_op_class_t *)((unsigned char *)op_class + 
							sizeof(em_channel_scan_req_op_class_t) + op_class->num_channels);
			}	
        }

        tlv_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

	if (params.num_op_classes > 0) {
		get_mgr()->io_process(em_bus_event_type_channel_scan_params, (unsigned char *)&params, sizeof(em_scan_params_t)); 
	}

	return 0;
}

void em_channel_t::fill_scan_result(dm_scan_result_t *scan_res, em_channel_scan_result_t *res)
{
	unsigned char *tmp;
	em_neighbor_t *nbr;
	unsigned char ssid_len, bw_len;
	char bandwidth[32] = {0};
	unsigned int i;
	mac_addr_str_t bssid_str;

	scan_res->m_scan_result.scan_status = res->scan_status;
	strncpy(scan_res->m_scan_result.timestamp, res->timestamp, res->timestamp_len + 1);

	tmp = (unsigned char *)res + sizeof(em_channel_scan_result_t) + res->timestamp_len;
	
	memcpy(&scan_res->m_scan_result.util, tmp, sizeof(unsigned char));
	tmp += sizeof(unsigned char);
	
	memcpy(&scan_res->m_scan_result.noise, tmp, sizeof(unsigned char));
	tmp += sizeof(unsigned char);

	memcpy(&scan_res->m_scan_result.num_neighbors, tmp, sizeof(unsigned short));
	scan_res->m_scan_result.num_neighbors = htons(scan_res->m_scan_result.num_neighbors);	
	tmp += sizeof(unsigned short);		

    for (i = 0; i < scan_res->m_scan_result.num_neighbors; i++) {
        nbr = &scan_res->m_scan_result.neighbor[i];

        memcpy(nbr->bssid, tmp, sizeof(mac_address_t));
        tmp += sizeof(mac_address_t);

        memcpy(&ssid_len, tmp, sizeof(unsigned char));
        tmp += sizeof(unsigned char);

        strncpy(nbr->ssid, (char *)tmp, ssid_len + 1);
        nbr->ssid[ssid_len] = '\0';
        tmp += ssid_len;

        memcpy(&nbr->signal_strength, tmp, sizeof(unsigned char));
        tmp += sizeof(unsigned char);

        memcpy(&bw_len, tmp, sizeof(unsigned char));
        tmp += sizeof(unsigned char);

        memcpy(bandwidth, tmp, bw_len);
        tmp += bw_len;

        if (strncmp(bandwidth, "20", strlen("20")) == 0) {
            nbr->bandwidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        } else if (strncmp(bandwidth, "40", strlen("40")) == 0) {
            nbr->bandwidth = WIFI_CHANNELBANDWIDTH_40MHZ;
        } else if (strncmp(bandwidth, "80", strlen("80")) == 0) {
            nbr->bandwidth = WIFI_CHANNELBANDWIDTH_40MHZ;
        } else if (strncmp(bandwidth, "160", strlen("160")) == 0) {
            nbr->bandwidth = WIFI_CHANNELBANDWIDTH_160MHZ;
        } else if (strncmp(bandwidth, "320", strlen("320")) == 0) {
            nbr->bandwidth = WIFI_CHANNELBANDWIDTH_320MHZ;
        }

        memcpy(&nbr->bss_color, tmp, sizeof(unsigned char));
        tmp += sizeof(unsigned char);

        memcpy(&nbr->channel_util, tmp, sizeof(unsigned char));
        tmp += sizeof(unsigned char);

        memcpy(&nbr->sta_count, tmp, sizeof(unsigned short));
		nbr->sta_count = htons(nbr->sta_count);
        tmp += sizeof(unsigned short);

		dm_easy_mesh_t::macbytes_to_string(nbr->bssid, bssid_str);
		//printf("%s:%d: bssid: %s\tssid: %s\trssi: %d\tbandwidth: %s\tutil: %d\tcount: %d\n", __func__, __LINE__,
		//			bssid_str, nbr->ssid, nbr->signal_strength, bandwidth, nbr->channel_util, nbr->sta_count);	
    }

    memcpy(&scan_res->m_scan_result.aggr_scan_duration, tmp, sizeof(unsigned int));
    tmp += sizeof(unsigned int);

    memcpy(&scan_res->m_scan_result.scan_type, tmp, sizeof(unsigned char));
    tmp += sizeof(unsigned char);

}

int em_channel_t::handle_channel_scan_rprt(unsigned char *buff, unsigned int len)
{
	em_tlv_t    *tlv;
    int tlv_len;
	em_channel_scan_result_t *res;
	dm_easy_mesh_t *dm;
	em_scan_result_id_t id;
	dm_scan_result_t *scan_res;

	dm = get_data_model();

    tlv = (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
		if (tlv->type == em_tlv_type_channel_scan_rslt) {
			res = (em_channel_scan_result_t *)tlv->value;;
			
			strncpy(id.net_id, dm->m_network.m_net_info.id, strlen(dm->m_network.m_net_info.id) + 1);	
			memcpy(id.dev_mac, dm->m_device.m_device_info.intf.mac, sizeof(mac_address_t));
            memcpy(id.scanner_mac, res->ruid, sizeof(mac_address_t));
            id.op_class = res->op_class;
            id.channel = res->channel;
			id.scanner_type = em_scanner_type_radio;

			if ((scan_res = dm->find_matching_scan_result(&id)) == NULL) {
				scan_res = dm->create_new_scan_result(&id);
			}

			fill_scan_result(scan_res, res);
		}

        if (tlv->type == em_tlv_type_timestamp) {
       		; 
		}

        tlv_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }
        
	dm->set_db_cfg_param(db_cfg_type_scan_result_list_update, "");


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
	        if (get_service_type() == em_service_type_agent) {
		        handle_channel_pref_query(data, len);
	        }
            break; 
    
        case em_msg_type_channel_pref_rprt:
		if (get_service_type() == em_service_type_ctrl) {
			handle_channel_pref_rprt(data, len);
		}
            break;

        case em_msg_type_channel_sel_rsp:
            handle_channel_sel_rsp(data, len);
            break;

        case em_msg_type_op_channel_rprt:
			if (get_service_type() == em_service_type_ctrl) {
           		handle_operating_channel_rprt(data, len);
			}
            break;
    
	    break;

        case em_msg_type_channel_sel_req:
            if (get_service_type() == em_service_type_agent) {
                handle_channel_sel_req(data, len);
                send_channel_sel_response_msg(em_chan_sel_resp_code_type_accept, htons(cmdu->id));
            }
            break;

        case em_msg_type_avail_spectrum_inquiry:
            if (get_service_type() == em_service_type_agent) {
                send_available_spectrum_inquiry_msg();
            }
            break;

		case em_msg_type_channel_scan_req:
            if (get_service_type() == em_service_type_agent) {
                handle_channel_scan_req(data, len);
            }
			break;

		case em_msg_type_channel_scan_rprt:
			if (get_service_type() == em_service_type_ctrl) {
           		handle_channel_scan_rprt(data, len);
			}
            break;

        default:
            break;
    }
}

void em_channel_t::process_state()
{
	unsigned int last_index = 0;
	dm_easy_mesh_t *dm;

    switch (get_state()) {
		case em_state_agent_channel_pref_query:
			if (get_service_type() == em_service_type_agent) {
				send_channel_pref_report_msg();
				printf("%s:%d channel_pref_report_msg send\n", __func__, __LINE__);
				set_state(em_state_agent_channel_selection_pending);
			}
            break;
        		
        case em_state_agent_channel_report_pending:
            if (get_service_type() == em_service_type_agent) {
                send_operating_channel_report_msg();
                printf("%s:%d operating_channel_report_msg send\n", __func__, __LINE__);
                set_state(em_state_agent_configured);
            }
            break;

		case em_state_agent_channel_scan_result_pending:
            if (get_service_type() == em_service_type_agent) {
				dm = get_data_model();
				while (last_index < dm->get_num_scan_results()) {
                	send_channel_scan_report_msg(&last_index);
				}
                set_state(em_state_agent_configured);
            }
			break;
        default:
            printf("%s:%d: unhandled case %d\n", __func__, __LINE__, get_state());
            break;

    }
}

void em_channel_t::process_ctrl_state()
{
    switch (get_state()) {
        case em_state_ctrl_channel_query_pending:
			if(get_service_type() == em_service_type_ctrl) {
				send_channel_pref_query_msg();
				set_state(em_state_ctrl_channel_pref_report_pending);
			}
            break;

        case em_state_ctrl_channel_select_pending:
        case em_state_ctrl_avail_spectrum_inquiry_pending:
			if(get_service_type() == em_service_type_ctrl) {
				send_channel_sel_request_msg();
			}
            break; 
        
		case em_state_ctrl_channel_scan_pending:
			send_channel_scan_request_msg();
            break; 
        default:
            printf("%s:%d: unhandled case %d\n", __func__, __LINE__, get_state());
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


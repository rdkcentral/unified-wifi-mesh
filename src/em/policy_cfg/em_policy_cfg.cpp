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

short em_policy_cfg_t::create_metrics_rep_policy_tlv(unsigned char *buff)
{
	short len = 0;
	dm_easy_mesh_t *dm = NULL;
	dm_policy_t *policy;
	bool found_match = false;
	unsigned char *tmp = buff;
	unsigned int i = 0;
	em_metric_rprt_policy_t	*metric;
	em_metric_rprt_policy_radio_t *radio_metric;
	mac_address_t broadcast_mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	if (get_current_cmd()->get_type() == em_cmd_type_em_config) {
        dm = get_data_model();
	} else if (get_current_cmd()->get_type() == em_cmd_type_set_policy) {
        dm = get_current_cmd()->get_data_model();
	}

	metric = reinterpret_cast<em_metric_rprt_policy_t *> (tmp);
	for (i = 0; i < dm->get_num_policy(); i++) {
        policy = &dm->m_policy[i];
        if (policy->m_policy.id.type == em_policy_id_type_ap_metrics_rep) {
            found_match = true;
            break;
        }
    }

	if (found_match == false) {
		return 0;
	}	

	found_match = false;
	metric->interval = static_cast<unsigned char> (policy->m_policy.interval);

	for (i = 0; i < dm->get_num_policy(); i++) {
		policy = &dm->m_policy[i];
		if (policy->m_policy.id.type == em_policy_id_type_radio_metrics_rep) {
			if ((memcmp(policy->m_policy.id.radio_mac, broadcast_mac, sizeof(mac_address_t)) == 0) ||
					(memcmp(policy->m_policy.id.radio_mac, get_radio_interface_mac(), sizeof(mac_address_t)) == 0)) {
				found_match = true;
            	break;	
			}
		}
	}

	
	if (found_match == false) {
		return 0;
	}

	metric->radios_num = 1;
	radio_metric = &metric->radios[0];

	memcpy(radio_metric->ruid, get_radio_interface_mac(), sizeof(mac_address_t));
	radio_metric->rcpi_thres = static_cast<unsigned char> (policy->m_policy.rcpi_threshold);
	radio_metric->rcpi_hysteresis = static_cast<unsigned char> (policy->m_policy.rcpi_hysteresis);
	radio_metric->util_thres = static_cast<unsigned char> (policy->m_policy.util_threshold);
	radio_metric->sta_policy = 0;
	if (policy->m_policy.sta_traffic_stats == true) {
		radio_metric->sta_policy |= (1 << 7);	
	}
	if (policy->m_policy.sta_link_metric == true) {
		radio_metric->sta_policy |= (1 << 6);	
	}
	if (policy->m_policy.sta_status == true) {
		radio_metric->sta_policy |= (1 << 5);	
	}

	tmp += 2*sizeof(unsigned char) + metric->radios_num * sizeof(em_metric_rprt_policy_radio_t);
	len += static_cast<short> (2*sizeof(unsigned char) + metric->radios_num * sizeof(em_metric_rprt_policy_radio_t));

	return len;
}

short em_policy_cfg_t::create_steering_policy_tlv(unsigned char *buff)
{
	size_t len = 0;
	dm_easy_mesh_t *dm;
	dm_policy_t *policy;
	bool found_match = false;
	unsigned char *tmp = buff;
	unsigned int i = 0;
	em_steering_policy_sta_t *sta_policy;
	em_steering_policy_radio_t	*radio_policy;
	mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	mac_address_t broadcast_mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	dm = get_data_model();
	
	for (i = 0; i < dm->get_num_policy(); i++) {
		policy = &dm->m_policy[i];
		if (policy->m_policy.id.type == em_policy_id_type_steering_local) {
			found_match = true;
			break;
		}
	}

	//local
	sta_policy = reinterpret_cast<em_steering_policy_sta_t *> (tmp);
	sta_policy->num_sta = 0;
	if (found_match == true) {
		
		found_match = false;

		for (i = 0; i < policy->m_policy.num_sta; i++) {
			if ((memcmp(policy->m_policy.sta_mac[i], null_mac, sizeof(mac_address_t)) != 0) && 
						(memcmp(policy->m_policy.sta_mac[i], broadcast_mac, sizeof(mac_address_t)) != 0)) {
				memcpy(sta_policy->sta_mac[sta_policy->num_sta], policy->m_policy.sta_mac[i], sizeof(mac_address_t));
				sta_policy->num_sta++;
			}

		}
	}

	tmp += sizeof(unsigned char) + sta_policy->num_sta*sizeof(mac_address_t);
	len += sizeof(unsigned char) + sta_policy->num_sta*sizeof(mac_address_t);

	for (i = 0; i < dm->get_num_policy(); i++) {
		policy = &dm->m_policy[i];
		if (policy->m_policy.id.type == em_policy_id_type_steering_btm) {
			found_match = true;
			break;
		}
	}

	//btm
	sta_policy = reinterpret_cast<em_steering_policy_sta_t *> (tmp);
	sta_policy->num_sta = 0;
	if (found_match == true) {
		
		found_match = false;

		for (i = 0; i < policy->m_policy.num_sta; i++) {
			if ((memcmp(policy->m_policy.sta_mac[i], null_mac, sizeof(mac_address_t)) != 0) && 
						(memcmp(policy->m_policy.sta_mac[i], broadcast_mac, sizeof(mac_address_t)) != 0)) {
				memcpy(sta_policy->sta_mac[sta_policy->num_sta], policy->m_policy.sta_mac[i], sizeof(mac_address_t));
				sta_policy->num_sta++;
			}

		}
	}

	tmp += sizeof(unsigned char) + sta_policy->num_sta*sizeof(mac_address_t);
	len += sizeof(unsigned char) + sta_policy->num_sta*sizeof(mac_address_t);

	for (i = 0; i < dm->get_num_policy(); i++) {
		policy = &dm->m_policy[i];
		if (policy->m_policy.id.type == em_policy_id_type_steering_param) {
			if ((memcmp(policy->m_policy.id.radio_mac, broadcast_mac, sizeof(mac_address_t)) == 0) ||
					(memcmp(policy->m_policy.id.radio_mac, get_radio_interface_mac(), sizeof(mac_address_t)) == 0)) {
				found_match = true;
            	break;	
			}
		}
	}

	//radio
	if (found_match == false) {
		*tmp = 0;
		tmp += sizeof(unsigned char);
		len += sizeof(unsigned char);
	} else {
		*tmp = 1;
		tmp += sizeof(unsigned char);
		len += sizeof(unsigned char);

		radio_policy = reinterpret_cast<em_steering_policy_radio_t *> (tmp);
		memcpy(radio_policy->ruid, get_radio_interface_mac(), sizeof(mac_address_t));
		radio_policy->steering_policy = static_cast<unsigned char> (policy->m_policy.policy);
		radio_policy->channel_util_thresh = static_cast<unsigned char> (policy->m_policy.util_threshold);
		radio_policy->rssi_steering_thresh = static_cast<unsigned char> (policy->m_policy.rcpi_threshold);

		tmp += sizeof(em_steering_policy_radio_t);
		len += sizeof(em_steering_policy_radio_t);
	}

	return static_cast<short> (len);
}

short em_policy_cfg_t::create_vendor_policy_cfg_tlv(unsigned char *buff)
{
    size_t len = 0;
    dm_easy_mesh_t *dm;
    dm_policy_t *policy;
    bool found_match = false;
    unsigned char *tmp = buff;
    unsigned int i = 0;

    dm = get_current_cmd()->get_data_model();

    for (i = 0; i < dm->get_num_policy(); i++) {
        policy = &dm->m_policy[i];
        if (policy->m_policy.id.type == em_policy_id_type_ap_metrics_rep) {
            found_match = true;
            break;
        }
    }
    if (found_match == false) {
        return 0;
    }

    strncpy(reinterpret_cast<char *> (tmp), policy->m_policy.managed_sta_marker, strlen(policy->m_policy.managed_sta_marker) + 1);

    tmp += strlen(policy->m_policy.managed_sta_marker);
    len += strlen(policy->m_policy.managed_sta_marker);

    return static_cast<short> (len);
}

int em_policy_cfg_t::send_policy_cfg_request_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_map_policy_config_req;
    size_t len = 0;
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

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(static_cast<uint16_t> (msg_id));
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // Zero or one Steering Policy TLV (see section 17.2.11).
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_steering_policy;
	sz = create_steering_policy_tlv(tlv->value);
	tlv->len = htons(static_cast<short unsigned int> (sz));

	tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));    

	// Zero or one Metric Reporting Policy TLV (see section 17.2.12).
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_metric_reporting_policy;
    sz = create_metrics_rep_policy_tlv(tlv->value);
    tlv->len = htons(static_cast<short unsigned int> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    //em_tlv_vendor_plolicy_cfg
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_vendor_plolicy_cfg;
    sz = create_vendor_policy_cfg_tlv(tlv->value);
    tlv->len = htons(static_cast<short unsigned int> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));
    if (em_msg_t(em_msg_type_map_policy_config_req, em_profile_type_3, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        printf("%s:%d: Policy Cfg Request msg validation failed\n", __func__, __LINE__);
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        printf("%s:%d: Policy Cfg Request msg send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

	printf("%s:%d: Policy Cfg Request Msg Send Success\n", __func__, __LINE__);

    return static_cast<int> (len);

}

int em_policy_cfg_t::handle_policy_cfg_req(unsigned char *buff, unsigned int len)
{
    em_policy_cfg_params_t policy;
    em_tlv_t    *tlv;
    unsigned int tlv_len;
    size_t data_len = 0;
    unsigned int i = 0;
    mac_addr_str_t mac_str;

    memset(&policy, 0, sizeof(em_policy_cfg_t));

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tlv_len > 0)) {
        if (tlv->type == em_tlv_type_steering_policy) {
            em_steering_policy_sta_t *steer_pol_sta = reinterpret_cast<em_steering_policy_sta_t *> (tlv->value);
            policy.steering_policy.local_steer_policy.num_sta = steer_pol_sta->num_sta;
            for(i = 0; i < steer_pol_sta->num_sta; i++) {
                memcpy(policy.steering_policy.local_steer_policy.sta_mac[i], steer_pol_sta->sta_mac, sizeof(mac_address_t));
            }
            data_len += sizeof(steer_pol_sta->num_sta) + (sizeof(mac_addr_t) * steer_pol_sta->num_sta);

            em_steering_policy_sta_t *btm_steer_pol = reinterpret_cast<em_steering_policy_sta_t *> (tlv->value + data_len);
            policy.steering_policy.btm_steer_policy.num_sta = btm_steer_pol->num_sta;
            for(i = 0; i < btm_steer_pol->num_sta; i++) {
                memcpy(policy.steering_policy.btm_steer_policy.sta_mac[i], btm_steer_pol->sta_mac, sizeof(mac_address_t));
            }
            data_len += sizeof(btm_steer_pol->num_sta) + (sizeof(mac_addr_t) * btm_steer_pol->num_sta);

            policy.steering_policy.radio_num = *(tlv->value + data_len);
            data_len += sizeof(unsigned char);

            em_steering_policy_radio_t *radio_steer_pol = reinterpret_cast<em_steering_policy_radio_t *> (tlv->value + data_len);
            for(i = 0; i < policy.steering_policy.radio_num; i++) {
                memcpy(&policy.steering_policy.radio_steer_policy[i], radio_steer_pol, sizeof(em_steering_policy_radio_t));
                radio_steer_pol = reinterpret_cast<em_steering_policy_radio_t *> (tlv->value + data_len);
            }
            data_len += policy.steering_policy.radio_num * sizeof(em_steering_policy_radio_t);
        } else if (tlv->type == em_tlv_type_metric_reporting_policy) {
            em_metric_rprt_policy_t *metrics = reinterpret_cast<em_metric_rprt_policy_t *> (tlv->value);
            policy.metrics_policy.interval = metrics->interval;
            policy.metrics_policy.radios_num = metrics->radios_num;
            data_len += (2 * sizeof(unsigned char));

            for(i = 0; i < metrics->radios_num; i++) {
                em_metric_rprt_policy_radio_t *radio = &metrics->radios[i];
                memcpy(&policy.metrics_policy.radios[i], radio, sizeof(em_metric_rprt_policy_radio_t));

                dm_easy_mesh_t::macbytes_to_string(policy.metrics_policy.radios[i].ruid, mac_str);
                printf("%s:%d Recvd policy for radio %s\n", __func__, __LINE__, mac_str);
            }
            data_len += (metrics->radios_num * sizeof(em_metric_rprt_policy_radio_t));
        } else if (tlv->type == em_tlv_type_dflt_8021q_settings) {
        } else if (tlv->type == em_tlv_type_traffic_separation_policy) {
        } else if (tlv->type == em_tlv_type_channel_scan_rprt_policy) {
        } else if (tlv->type == em_tlv_type_unsucc_assoc_policy) {
        } else if (tlv->type == em_tlv_type_backhaul_bss_conf) {
        } else if (tlv->type == em_tlv_type_qos_mgmt_policy){
        } else if (tlv->type == em_tlv_vendor_plolicy_cfg) {
            em_vendor_policy_t *vendor = reinterpret_cast<em_vendor_policy_t *> (tlv->value);
            snprintf(policy.vendor_policy.managed_client_marker, sizeof(em_string_t), "%s", vendor->managed_client_marker);
            data_len += sizeof(em_vendor_policy_t);
        }

        tlv_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    get_mgr()->io_process(em_bus_event_type_set_policy, reinterpret_cast<unsigned char *> (&policy), sizeof(policy));
    //send_associated_link_metrics_response(sta);
    //set_state(em_state_agent_configured);

    return 0;
}

void em_policy_cfg_t::process_msg(unsigned char *data, unsigned int len)
{
    em_cmdu_t *cmdu;
    
    cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));
    
    switch (htons(cmdu->type)) {
		case em_msg_type_map_policy_config_req:
			handle_policy_cfg_req(data, len);
			break;
        default:
            break;
    }
}

void em_policy_cfg_t::process_state()
{
	if (get_service_type() == em_service_type_ctrl) {
		process_ctrl_state();
	}
}

void em_policy_cfg_t::process_ctrl_state()
{
    switch (get_state()) {
		case em_state_ctrl_set_policy_pending:
        	send_policy_cfg_request_msg();
			set_state(em_state_ctrl_configured);
            break;

        default:
            break;

    }
}

em_policy_cfg_t::em_policy_cfg_t()
{

}

em_policy_cfg_t::~em_policy_cfg_t()
{

}


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

static const unsigned char em_vendor_oui[EM_VENDOR_OUI_SIZE] = {0xd8, 0x9c, 0x8e};

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

	if (get_current_cmd()->get_type() == em_cmd_type_em_config) {
        dm = get_data_model();
	} else if (get_current_cmd()->get_type() == em_cmd_type_set_policy) {
        dm = get_current_cmd()->get_data_model();
	}

    em_printfout("Creating metrics report policy TLV, num policies=%u, num radios=%u",
        dm->get_num_policy(),
        dm->get_num_radios());
    /*Validate policy count */
    unsigned int num_policies = dm->get_num_policy();
    if ((num_policies == 0) || (num_policies > EM_MAX_POLICIES)) {
        em_printfout("Invalid policy count %u\n", num_policies);
        return 0;
    }

    /* Validate bounds for broadcast radio fill */
    if (get_data_model()->get_num_radios() > EM_MAX_RADIO_PER_AGENT) {
        em_printfout("Radio count %u exceeds maximum %u\n", get_data_model()->get_num_radios(), EM_MAX_RADIO_PER_AGENT);
        return 0;
    }

	metric = reinterpret_cast<em_metric_rprt_policy_t *> (tmp);
	for (i = 0; i < dm->get_num_policy(); i++) {
        policy = &dm->m_policy[i];
        if (policy->m_policy.id.type == em_policy_id_type_ap_metrics_rep) {
            found_match = true;
            //use radio from previous
            break;
        }
    }

	if (found_match == false) {
        em_printfout("No matching policy found for metrics report policy TLV in cmd_dm, trying DM");
        policy = nullptr;
        for (i = 0; i < get_data_model()->get_num_policy(); i++) {
            if (get_data_model()->m_policy[i].m_policy.id.type == em_policy_id_type_ap_metrics_rep) {
                policy = &get_data_model()->m_policy[i];
                break;
            }
        }
        if (policy == nullptr) {
            em_printfout("No ap_metrics_rep policy found in DM either, skipping TLV");
            return 0;
        }
	}

	metric->interval = static_cast<unsigned char> (policy->m_policy.interval);

    unsigned int radio_cnt = 0;

    for (i = 0; i < dm->get_num_policy(); i++) {
		policy = &dm->m_policy[i];
		if (policy->m_policy.id.type == em_policy_id_type_radio_metrics_rep) {
            for(unsigned int r = 0; r < get_data_model()->get_num_radios(); r++) {
                if ((memcmp(policy->m_policy.id.radio_mac, get_data_model()->get_radio_info(r)->id.ruid, sizeof(mac_address_t)) == 0)) {
                    radio_metric = &metric->radios[radio_cnt];
                    em_printfout(" Radio %d MAC: %s", radio_cnt, util::mac_to_string(policy->m_policy.id.radio_mac).c_str());
                    memcpy(radio_metric->ruid, policy->m_policy.id.radio_mac, sizeof(mac_address_t));
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
                    radio_cnt++;
                }
            }
    	}
    }
	em_printfout("Num of radios: %d", radio_cnt);

    metric->radios_num = radio_cnt;

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

	if (get_current_cmd()->get_type() == em_cmd_type_em_config) {
		dm = get_data_model();
	} else if (get_current_cmd()->get_type() == em_cmd_type_set_policy) {
		dm = get_current_cmd()->get_data_model();
	} else {
		dm = get_data_model();
	}
	
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

    unsigned int num_radios = 0;

    	for (i = 0; i < dm->get_num_policy(); i++) {
            policy = &dm->m_policy[i];
            if (policy->m_policy.id.type == em_policy_id_type_steering_param) {
                for (unsigned int r = 0; r < get_data_model()->get_num_radios(); r++) {
                    if (memcmp(policy->m_policy.id.radio_mac, get_data_model()->get_radio_info(r)->id.ruid, sizeof(mac_address_t)) == 0) {
                        num_radios++;
                        break;
                    }
                }
            }
        }

	tmp += sizeof(unsigned char) + sta_policy->num_sta*sizeof(mac_address_t);
	len += sizeof(unsigned char) + sta_policy->num_sta*sizeof(mac_address_t);

    //radio
    *tmp = static_cast<unsigned char>(num_radios);
    tmp += sizeof(unsigned char);
    len += sizeof(unsigned char);
    em_printfout("Steering policy: found radio policy with type %d, num_radios=%u",
        policy->m_policy.id.type,
        num_radios);

	for (i = 0; i < dm->get_num_policy(); i++) {
		policy = &dm->m_policy[i];
		if (policy->m_policy.id.type == em_policy_id_type_steering_param) {
            for (unsigned int r = 0; r < get_data_model()->get_num_radios(); r++) {
                if (memcmp(policy->m_policy.id.radio_mac, get_data_model()->get_radio_info(r)->id.ruid, sizeof(mac_address_t)) == 0) {
                    radio_policy = reinterpret_cast<em_steering_policy_radio_t *>(tmp);
                    memcpy(radio_policy->ruid,
                        get_data_model()->get_radio_info(r)->id.ruid,
                        sizeof(mac_address_t));
                    radio_policy->steering_policy = static_cast<unsigned char>(policy->m_policy.policy);
                    radio_policy->channel_util_thresh = static_cast<unsigned char>(policy->m_policy.util_threshold);
                    radio_policy->rssi_steering_thresh = static_cast<unsigned char>(policy->m_policy.rcpi_threshold);
                    tmp += sizeof(em_steering_policy_radio_t);
                    len += sizeof(em_steering_policy_radio_t);
                    break;
                }
            }
		}
	}

	return static_cast<short> (len);
}

short em_policy_cfg_t::create_chan_scan_report_policy_tlv(unsigned char *buff)
{
    size_t len = 0;
    dm_easy_mesh_t *dm;
    unsigned int i;

    if (get_current_cmd()->get_type() == em_cmd_type_set_policy) {
        dm = get_current_cmd()->get_data_model();
    } else {
        dm = get_data_model();
    }

    for (i = 0; i < dm->get_num_policy(); i++) {
        dm_policy_t *policy = &dm->m_policy[i];
        if (policy->m_policy.id.type != em_policy_id_type_channel_scan) {
            continue;
        }
        em_channel_scan_rprt_policy_t *scan_policy =
            reinterpret_cast<em_channel_scan_rprt_policy_t *>(buff);
        scan_policy->rprt_ind_ch_scan =
            policy->m_policy.independent_scan_report ? 1 : 0;
        scan_policy->reserved = 0;
        em_printfout("Found Channel Scan Reporting Policy in DM with rprt_ind_ch_scan=%d",
            scan_policy->rprt_ind_ch_scan);
        len += sizeof(em_channel_scan_rprt_policy_t);
        break;
    }

    return static_cast<short> (len);
}

short em_policy_cfg_t::create_unsucc_assoc_policy_tlv(unsigned char *buff)
{
    size_t len = 0;
    dm_easy_mesh_t *dm;
    unsigned int i;

    if (get_current_cmd()->get_type() == em_cmd_type_set_policy) {
        dm = get_current_cmd()->get_data_model();
    } else {
        dm = get_data_model();
    }

    for (i = 0; i < dm->get_num_policy(); i++) {
        dm_policy_t *policy = &dm->m_policy[i];
        if (policy->m_policy.id.type != em_policy_id_type_unsuccess_assoc) {
            continue;
        }
        em_printfout("Found Unsuccessful Association Policy in DM with report_unassoc_sta=%d, max_reporting_rate=%u",
            policy->m_policy.report_unassoc_sta, policy->m_policy.max_reporting_rate);
        em_unsuccessful_assoc_policy_t *assoc = reinterpret_cast<em_unsuccessful_assoc_policy_t *>(buff);
        assoc->rprt_flag = policy->m_policy.report_unassoc_sta ? 1 : 0;
        assoc->reserved = 0;
        assoc->max_rprt_rate = htonl(policy->m_policy.max_reporting_rate);
        len += sizeof(em_unsuccessful_assoc_policy_t);
        break;
    }

    return static_cast<short> (len);
}

// Encodes a single Backhaul BSS Configuration TLV value for the given entry.
// The caller emits one TLV per entry (spec 17.2.66: "zero or more" TLVs).
short em_policy_cfg_t::create_backhaul_bss_conf_policy_tlv(unsigned char *buff, const em_backhaul_bss_config_policy_t *entry)
{
    static const mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    // Skip TLV if BSSID is all zeros — no meaningful config to send.
    if (memcmp(entry->bssid, null_mac, sizeof(mac_address_t)) == 0) {
        return 0;
    }
    em_bh_bss_config_t *bss_cfg = reinterpret_cast<em_bh_bss_config_t *>(buff);
    memcpy(bss_cfg->bssid, entry->bssid, sizeof(mac_address_t));
    bss_cfg->p1_bsta_disallowed = entry->b_profile_1_sta_disallowed ? 1 : 0;
    bss_cfg->p2_bsta_disallowed = entry->b_profile_2_sta_disallowed ? 1 : 0;
    bss_cfg->reserved = 0;
    return static_cast<short>(sizeof(em_bh_bss_config_t));
}

short em_policy_cfg_t::create_qos_mgt_policy_tlv(unsigned char *buff, dm_policy_t *policy, unsigned int qi)
{
    size_t len = 0;
    unsigned int j;
    unsigned char *tmp = buff;

    unsigned char mscs_num = static_cast<unsigned char>(
        (policy->m_policy.qos_mgt[qi].num_mscs < EM_MAX_MSC_PER_TRAFFIC_SEPAR)
            ? policy->m_policy.qos_mgt[qi].num_mscs : EM_MAX_MSC_PER_TRAFFIC_SEPAR);
    unsigned char scs_num = static_cast<unsigned char>(
        (policy->m_policy.qos_mgt[qi].num_scs < EM_MAX_SCS_PER_TRAFFIC_SEPAR)
            ? policy->m_policy.qos_mgt[qi].num_scs : EM_MAX_SCS_PER_TRAFFIC_SEPAR);

    // Skip TLV if both lists are empty — no meaningful config to send.
    if (mscs_num == 0 && scs_num == 0) {
        return 0;
    }
    em_printfout("Found QoS Management Policy in DM with qi=%u num_mscs=%u, num_scs=%u", qi, mscs_num, scs_num);

    // Wire format is variable-length: [mscs_num][mscs MACs...][scs_num][scs MACs...][20 reserved]
    *tmp++ = mscs_num;
    len += sizeof(unsigned char);
    for (j = 0; j < mscs_num; j++) {
        memcpy(tmp, policy->m_policy.qos_mgt[qi].msc_mac[j], sizeof(mac_address_t));
        tmp += sizeof(mac_address_t);
        len += sizeof(mac_address_t);
    }

    *tmp++ = scs_num;
    len += sizeof(unsigned char);
    for (j = 0; j < scs_num; j++) {
        memcpy(tmp, policy->m_policy.qos_mgt[qi].sc_mac[j], sizeof(mac_address_t));
        tmp += sizeof(mac_address_t);
        len += sizeof(mac_address_t);
    }

    // 20 reserved bytes at the end (spec section 17.2.92).
    memset(tmp, 0, 20);
    len += 20;

    return static_cast<short>(len);
}

short em_policy_cfg_t::create_vendor_policy_cfg_tlv(unsigned char *buff)
{
    size_t len = 0;
    dm_easy_mesh_t *dm;
    dm_policy_t *policy;
    unsigned int i = 0;
    int idx_ap = -1;
    int idx_alarm = -1;
    int idx_filter = -1;

    em_vendor_specific_t *vendor_data = reinterpret_cast<em_vendor_specific_t *> (buff);
    memcpy(reinterpret_cast<char *> (vendor_data->vendor_oui), em_vendor_oui, EM_VENDOR_OUI_SIZE);
    len += sizeof(unsigned char) + EM_VENDOR_OUI_SIZE;

    unsigned char *cursor = reinterpret_cast<unsigned char *> (vendor_data->data);
    unsigned char *payload_start = reinterpret_cast<unsigned char *> (vendor_data->data);
    em_vendor_data_t *data = NULL;

    dm = get_current_cmd()->get_data_model();

    for (i = 0; i < dm->get_num_policy(); i++) {
        if (dm->m_policy[i].m_policy.id.type == em_policy_id_type_ap_metrics_rep) {
            idx_ap = static_cast<int>(i);
        } else if (dm->m_policy[i].m_policy.id.type == em_policy_id_type_alarm_threshold) {
            idx_alarm = static_cast<int>(i);
        } else if (dm->m_policy[i].m_policy.id.type == em_policy_id_type_client_filters) {
            idx_filter = static_cast<int>(i);
        }
        /* If both found, we can stop scanning early */
        if ((idx_ap != -1) && (idx_alarm != -1) && (idx_filter != -1)) {
            break;
        }
    }

    if ((idx_ap == -1) && (idx_alarm == -1) && (idx_filter == -1)) {
        return static_cast<short> (len);
    }

    /* If AP metrics policy exists, append its vendor data */
    if (idx_ap != -1) {
        policy = &dm->m_policy[idx_ap];
        em_printfout(" Vendor Policy cfg TLV for metrics report policy ");

        data = reinterpret_cast<em_vendor_data_t *> (cursor);
        data->attr_id = vendor_ext_attr_id_policy_sta_marker;
        strncpy(reinterpret_cast<char *> (data->vendor_data), policy->m_policy.managed_sta_marker, strlen(policy->m_policy.managed_sta_marker) + 1);

        len += sizeof(data->attr_id) + strlen(policy->m_policy.managed_sta_marker) + 1;
        cursor += sizeof(data->attr_id) + strlen(policy->m_policy.managed_sta_marker) + 1;

        vendor_data->num++;
    }

    if (idx_alarm != -1) {
        policy = &dm->m_policy[idx_alarm];
        em_printfout(" Vendor Policy cfg TLV for link stats alarm policy ");

        data = reinterpret_cast<em_vendor_data_t *> (cursor);
        data->attr_id = vendor_ext_attr_id_policy_alarm;
        memcpy(data->vendor_data,
            &policy->m_policy.link_stats_alarm_cfg,
            sizeof(em_link_stats_alarm_cfg_t));

        len += sizeof(data->attr_id) + sizeof(em_link_stats_alarm_cfg_t);
        cursor += sizeof(data->attr_id) + sizeof(em_link_stats_alarm_cfg_t);

        vendor_data->num++;
    }

    if (idx_filter != -1) {
        policy = &dm->m_policy[idx_filter];
        em_printfout(" Vendor Policy cfg TLV for client filters policy ");

        data = reinterpret_cast<em_vendor_data_t *> (cursor);
        data->attr_id = vendor_ext_attr_id_policy_cfg_client_filter;
        memcpy(data->vendor_data, reinterpret_cast<unsigned char *> (&policy->m_policy.client_filters), sizeof(em_client_filters_cfg_t));
        
        len += sizeof(data->attr_id) + sizeof(em_client_filters_cfg_t);
        cursor += sizeof(data->attr_id) + sizeof(em_client_filters_cfg_t);

        vendor_data->num++;
    }
    em_printfout("vendor data attr cnt: %zu", vendor_data->num);
    em_printfout("client filter Policy cfg TLV length: %zu and total payload: %zu", len, (cursor - payload_start));

    return static_cast<short> (len);
}

int em_policy_cfg_t::send_policy_cfg_request_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ * 4] = {0};
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_map_policy_config_req;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    short sz = 0;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm;

    dm = get_data_model();

    // For UI-triggered set_policy: only include TLVs for policy types that are
    // present in the command dm (i.e., the policies that actually changed).
    // For onboarding (em_config / autoconfig renew): always include all TLVs.
    bool is_set_policy = (get_current_cmd()->get_type() == em_cmd_type_set_policy);
    dm_easy_mesh_t *cmd_dm = is_set_policy ? get_current_cmd()->get_data_model() : nullptr;

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

    // Zero or one Steering Policy TLV (see section 17.2.11).
    if (!is_set_policy || cmd_dm->has_policy_type(em_policy_id_type_steering_local)
            || cmd_dm->has_policy_type(em_policy_id_type_steering_btm)
            || cmd_dm->has_policy_type(em_policy_id_type_steering_param)) {
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_steering_policy;
        sz = create_steering_policy_tlv(tlv->value);
        tlv->len = htons(static_cast<short unsigned int> (sz));
        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    }

    // Zero or one Metric Reporting Policy TLV (see section 17.2.12).
    if (!is_set_policy || cmd_dm->has_policy_type(em_policy_id_type_ap_metrics_rep)
            || cmd_dm->has_policy_type(em_policy_id_type_radio_metrics_rep)) {
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_metric_reporting_policy;
        sz = create_metrics_rep_policy_tlv(tlv->value);
        tlv->len = htons(static_cast<short unsigned int> (sz));
        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    }

    // Zero or one Default 802.1Q Settings TLV (see section 17.2.49).
    if (!is_set_policy || cmd_dm->has_policy_type(em_policy_id_type_default_8021q_settings)) {
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_dflt_8021q_settings;
        sz = create_def_8021q_settings_policy_tlv(tlv->value);
        tlv->len = htons(static_cast<short unsigned int> (sz));
        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    }

    // Zero or one Traffic Separation Policy TLV (see section 17.2.50).
    // Built from SSID/VLAN data; included only during onboarding.
    if (!is_set_policy) {
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_traffic_separation_policy;
        sz = static_cast<short>(create_traffic_separation_policy_tlv(tlv->value));
        tlv->len = htons(static_cast<unsigned short>(static_cast<unsigned int>(sz)));
        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    }

    // Zero or one Channel Scan Reporting Policy TLV (see section 17.2.37).
    if (!is_set_policy || cmd_dm->has_policy_type(em_policy_id_type_channel_scan)) {
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_channel_scan_rprt_policy;
        sz = create_chan_scan_report_policy_tlv(tlv->value);
        tlv->len = htons(static_cast<short unsigned int> (sz));
        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    }

    // Zero or one Unsuccessful Association Policy TLV (see section 17.2.58).
    if (!is_set_policy || cmd_dm->has_policy_type(em_policy_id_type_unsuccess_assoc)) {
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_unsucc_assoc_policy;
        sz = create_unsucc_assoc_policy_tlv(tlv->value);
        tlv->len = htons(static_cast<short unsigned int> (sz));
        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    }

    // Zero or more Backhaul BSS Configuration TLVs (spec 17.2.66): one TLV per BSSID entry.
    dm_easy_mesh_t *bh_dm = is_set_policy ? cmd_dm : dm;
    for (unsigned int pi = 0; pi < bh_dm->get_num_policy(); pi++) {
        dm_policy_t *bh_pol = &bh_dm->m_policy[pi];
        if (bh_pol->m_policy.id.type != em_policy_id_type_backhaul_bss_config) {
            continue;
        }
        for (unsigned int bi = 0; bi < bh_pol->m_policy.num_backhaul_bss_config; bi++) {
            const em_backhaul_bss_config_policy_t *entry = &bh_pol->m_policy.backhaul_bss_config[bi];
            static const mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            if (memcmp(entry->bssid, null_mac, sizeof(mac_address_t)) == 0) {
                continue;
            }
            tlv = reinterpret_cast<em_tlv_t *>(tmp);
            tlv->type = em_tlv_type_backhaul_bss_conf;
            sz = create_backhaul_bss_conf_policy_tlv(tlv->value, entry);
            tlv->len = htons(static_cast<short unsigned int>(sz));
            em_printfout("Sending Backhaul BSS Config TLV: BSSID=%s p1=%d p2=%d",
                util::mac_to_string(entry->bssid).c_str(),
                entry->b_profile_1_sta_disallowed,
                entry->b_profile_2_sta_disallowed);
            tmp += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
            len += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
        }
    }

    // Zero or more QoS Management Policy TLVs (spec 17.2.92): one TLV per entry.
    dm_easy_mesh_t *qos_dm = is_set_policy ? cmd_dm : dm;
    for (unsigned int pi = 0; pi < qos_dm->get_num_policy(); pi++) {
        dm_policy_t *qos_pol = &qos_dm->m_policy[pi];
        if (qos_pol->m_policy.id.type != em_policy_id_type_qos_mgt) {
            continue;
        }
        for (unsigned int qi = 0; qi < qos_pol->m_policy.num_qos_mgt; qi++) {
            tlv = reinterpret_cast<em_tlv_t *>(tmp);
            tlv->type = em_tlv_type_qos_mgmt_policy;
            sz = create_qos_mgt_policy_tlv(tlv->value, qos_pol, qi);
            if (sz > 0) {
                tlv->len = htons(static_cast<short unsigned int>(sz));
                tmp += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
                len += (sizeof(em_tlv_t) + static_cast<size_t>(sz));
            }
        }
    }

    // Vendor-specific TLV (alarm threshold / client filters / managed STA marker).
    if (!is_set_policy || cmd_dm->has_policy_type(em_policy_id_type_alarm_threshold)
            || cmd_dm->has_policy_type(em_policy_id_type_client_filters)
            || cmd_dm->has_policy_type(em_policy_id_type_ap_metrics_rep)) {
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_vendor_specific;
        sz = create_vendor_policy_cfg_tlv(tlv->value);
        tlv->len = htons(static_cast<short unsigned int> (sz));
        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    }

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

	em_printfout("Policy Cfg Request Msg Send Success");

    m_policy_req_msg_id = ntohs(cmdu->id);

    return static_cast<int> (len);

}

int em_policy_cfg_t::handle_policy_cfg_req(unsigned char *buff, unsigned int len)
{
    em_policy_cfg_params_t policy;
    em_tlv_t    *tlv;
    unsigned int tlv_len;
    size_t data_len = 0;
    unsigned int i = 0;
    unsigned char *cursor = NULL;
    em_vendor_data_t *data = NULL;

    // Start from last applied policy so that absent TLVs retain their
    // existing values instead of being zeroed out.
    static em_policy_cfg_params_t last_policy = {};
    policy = last_policy;
    policy.num_bh_bss_cfg = 0;
    policy.num_qos_mgmt = 0;
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    em_printfout("Handling Policy Cfg Request Msg len=%d, tlv_len=%d", len, tlv_len);

    while ((tlv->type != em_tlv_type_eom) && (tlv_len > 0)) {
        if (tlv->type == em_tlv_type_steering_policy) {
            data_len = 0; // reset per-TLV offset
            em_steering_policy_sta_t *steer_pol_sta = reinterpret_cast<em_steering_policy_sta_t *> (tlv->value);
            policy.steering_policy.local_steer_policy.num_sta = steer_pol_sta->num_sta;
            for(i = 0; i < steer_pol_sta->num_sta; i++) {
                memcpy(policy.steering_policy.local_steer_policy.sta_mac[i], steer_pol_sta->sta_mac[i], sizeof(mac_address_t));
            }
            data_len += sizeof(steer_pol_sta->num_sta) + (sizeof(mac_addr_t) * steer_pol_sta->num_sta);

            em_steering_policy_sta_t *btm_steer_pol = reinterpret_cast<em_steering_policy_sta_t *> (tlv->value + data_len);
            policy.steering_policy.btm_steer_policy.num_sta = btm_steer_pol->num_sta;
            for(i = 0; i < btm_steer_pol->num_sta; i++) {
                memcpy(policy.steering_policy.btm_steer_policy.sta_mac[i], btm_steer_pol->sta_mac[i], sizeof(mac_address_t));
            }
            data_len += sizeof(btm_steer_pol->num_sta) + (sizeof(mac_addr_t) * btm_steer_pol->num_sta);

            policy.steering_policy.radio_num = *(tlv->value + data_len);
            data_len += sizeof(unsigned char);

            em_steering_policy_radio_t *radio_steer_pol = reinterpret_cast<em_steering_policy_radio_t *> (tlv->value + data_len);
            for(i = 0; i < policy.steering_policy.radio_num; i++) {
                memcpy(&policy.steering_policy.radio_steer_policy[i], &radio_steer_pol[i], sizeof(em_steering_policy_radio_t));
            }
            data_len += policy.steering_policy.radio_num * sizeof(em_steering_policy_radio_t);
        } else if (tlv->type == em_tlv_type_metric_reporting_policy) {
            em_metric_rprt_policy_t *metrics = reinterpret_cast<em_metric_rprt_policy_t *> (tlv->value);
            policy.metrics_policy.interval = metrics->interval;
            data_len += (2 * sizeof(unsigned char));

            // Only overwrite radios if the TLV actually carries radio entries;
            // otherwise keep the previously cached per-radio policies (from last_policy).
            if (metrics->radios_num > 0) {
                policy.metrics_policy.radios_num = metrics->radios_num;
                for(i = 0; i < metrics->radios_num; i++) {
                    em_metric_rprt_policy_radio_t *radio = &metrics->radios[i];
                    memcpy(&policy.metrics_policy.radios[i], radio, sizeof(em_metric_rprt_policy_radio_t));
                    em_printfout("Recvd policy for radio %s", util::mac_to_string(policy.metrics_policy.radios[i].ruid).c_str());
                }
            }
            data_len += (metrics->radios_num * sizeof(em_metric_rprt_policy_radio_t));
        } else if (tlv->type == em_tlv_type_dflt_8021q_settings) {
            if (ntohs(tlv->len) >= sizeof(em_8021q_settings_t)) {
                em_8021q_settings_t *settings = reinterpret_cast<em_8021q_settings_t *>(tlv->value);
                policy.def_8021q_settings.primary_vlan_id = ntohs(settings->primary_vlan_id);
                policy.def_8021q_settings.default_pcp = settings->default_pcp;
                em_printfout("Recvd Default 802.1Q Settings: primary_vlan_id=%u, default_pcp=%u",
                    policy.def_8021q_settings.primary_vlan_id, policy.def_8021q_settings.default_pcp);
            }
        } else if (tlv->type == em_tlv_type_traffic_separation_policy) {
            unsigned char *tmp = static_cast<unsigned char *>(tlv->value);
            policy.traffic_separation_policy.ssids_num = *tmp;
	        if(policy.traffic_separation_policy.ssids_num <= em_haul_type_max) {
            	tmp += sizeof(unsigned char);
            	data_len += sizeof(unsigned char);
            	for ( i = 0; i < policy.traffic_separation_policy.ssids_num ; i++ ) {
                    size_t ssid_len = *tmp;
                    tmp += sizeof(unsigned char);
                    data_len += sizeof(unsigned char);
		
		            if(ssid_len <= MAX_SSID_NAME_LEN) {
                        memcpy(policy.traffic_separation_policy.ssids[i].ssid, tmp, ssid_len);
                        policy.traffic_separation_policy.ssids[i].ssid[ssid_len] = '\0';
                        policy.traffic_separation_policy.ssids[i].ssid_len = ssid_len ;

                        tmp += ssid_len;
                        data_len += ssid_len;
                
                        unsigned short net_vlan = 0;
                        memcpy(&net_vlan, tmp, sizeof(net_vlan));
                        policy.traffic_separation_policy.ssids[i].vlan_id = ntohs(net_vlan);
                        tmp += sizeof(unsigned short);
                        data_len += sizeof(unsigned short);
		            }
                    em_printfout("Recvd Traffic Separation policy SSID='%s' Len=%u, VLAN=%u ",policy.traffic_separation_policy.ssids[i].ssid , ssid_len ,policy.traffic_separation_policy.ssids[i].vlan_id);
                }
	        }
        } else if (tlv->type == em_tlv_type_channel_scan_rprt_policy) {
            if (ntohs(tlv->len) == sizeof(em_channel_scan_rprt_policy_t)) {
                em_channel_scan_rprt_policy_t *scan_policy =
                    reinterpret_cast<em_channel_scan_rprt_policy_t *>(tlv->value);
                policy.channel_scan_policy.rprt_ind_ch_scan = scan_policy->rprt_ind_ch_scan;
                em_printfout("Recvd Channel Scan Reporting Policy: rprt_ind_ch_scan=%d",
                    policy.channel_scan_policy.rprt_ind_ch_scan);
            }
        } else if (tlv->type == em_tlv_type_unsucc_assoc_policy) {
            if (ntohs(tlv->len) == sizeof(em_unsuccessful_assoc_policy_t)) {
                em_unsuccessful_assoc_policy_t *assoc =
                    reinterpret_cast<em_unsuccessful_assoc_policy_t *>(tlv->value);
                policy.unsuccessful_assoc_policy.rprt_flag = assoc->rprt_flag;
                policy.unsuccessful_assoc_policy.max_rprt_rate = ntohl(assoc->max_rprt_rate);
                em_printfout("Recvd Unsuccessful Assoc Policy: rprt_flag=%d, max_rprt_rate=%u",
                    policy.unsuccessful_assoc_policy.rprt_flag,
                    policy.unsuccessful_assoc_policy.max_rprt_rate);
            }
        } else if (tlv->type == em_tlv_type_backhaul_bss_conf) {
            if (policy.num_bh_bss_cfg < EM_MAX_BSS_PER_RADIO) {
                unsigned int bh_cnt = policy.num_bh_bss_cfg;
                // Spec 17.2.66: one TLV carries exactly one Backhaul BSS Config entry.
                em_bh_bss_config_t *bss_cfg = reinterpret_cast<em_bh_bss_config_t *>(tlv->value);
                em_printfout("Recvd Backhaul BSS Config TLV[%u]: bssid=%s, p1_disallowed=%d, p2_disallowed=%d",
                    bh_cnt, util::mac_to_string(bss_cfg->bssid).c_str(),
                    bss_cfg->p1_bsta_disallowed, bss_cfg->p2_bsta_disallowed);
                memcpy(policy.bh_bss_cfg_policy[bh_cnt].bssid, bss_cfg->bssid, sizeof(mac_address_t));
                policy.bh_bss_cfg_policy[bh_cnt].p1_bsta_disallowed = bss_cfg->p1_bsta_disallowed;
                policy.bh_bss_cfg_policy[bh_cnt].p2_bsta_disallowed = bss_cfg->p2_bsta_disallowed;
                policy.num_bh_bss_cfg++;
            }
        } else if (tlv->type == em_tlv_type_qos_mgmt_policy) {
            if (policy.num_qos_mgmt < EM_MAX_QOS_MGMT_POLICY) {
                unsigned int q_cnt = policy.num_qos_mgmt;
                unsigned char *qos_data = tlv->value;
                size_t qos_offset = 0;

                unsigned char mscs_num = qos_data[qos_offset++];
                mscs_num = (mscs_num < EM_MAX_STA_PER_AGENT) ? mscs_num : EM_MAX_STA_PER_AGENT;
                policy.qos_mgmt_policy[q_cnt].mscs_disallowed_num = mscs_num;
                for (unsigned int idx = 0; idx < mscs_num; idx++) {
                    memcpy(policy.qos_mgmt_policy[q_cnt].mac_addr_mscs_disallowed[idx].sta_mac_addr,
                        qos_data + qos_offset, sizeof(mac_address_t));
                    qos_offset += sizeof(mac_address_t);
                }

                unsigned char scs_num = qos_data[qos_offset++];
                scs_num = (scs_num < EM_MAX_STA_PER_AGENT) ? scs_num : EM_MAX_STA_PER_AGENT;
                policy.qos_mgmt_policy[q_cnt].scs_disallowed_num = scs_num;
                for (unsigned int idx = 0; idx < scs_num; idx++) {
                    memcpy(policy.qos_mgmt_policy[q_cnt].mac_addr_scs_disallowed[idx].sta_mac_addr,
                        qos_data + qos_offset, sizeof(mac_address_t));
                    qos_offset += sizeof(mac_address_t);
                }

                policy.num_qos_mgmt++;
                em_printfout("Recvd QoS Mgmt Policy[%u]: mscs_num=%d, scs_num=%d",
                    q_cnt,
                    policy.qos_mgmt_policy[q_cnt].mscs_disallowed_num,
                    policy.qos_mgmt_policy[q_cnt].scs_disallowed_num);
            }
        } else if (tlv->type == em_tlv_type_vendor_specific) {
            em_vendor_specific_t *vendor_tlv = reinterpret_cast<em_vendor_specific_t *> (tlv->value);
            em_printfout("Recvd vendor tlv, num: %d and tlv->len:%d", vendor_tlv->num, ntohs(tlv->len));
            if ((vendor_tlv->num <= 0) || (ntohs(tlv->len) == 0)) {
                break;
            }

            cursor = reinterpret_cast<unsigned char *> (vendor_tlv->data);
            for(int i = 0; i < vendor_tlv->num; i++)
            {
                data = reinterpret_cast<em_vendor_data_t *> (cursor);
                em_printfout("vendor attr id is: %d", data->attr_id);
                if (data->attr_id == vendor_ext_attr_id_policy_sta_marker) {
                    strncpy(policy.vendor_policy.managed_client_marker, reinterpret_cast<const char *>(data->vendor_data), strlen(reinterpret_cast<char *> (data->vendor_data)) + 1);
                    em_printfout(" Recvd sta marker: %s", policy.vendor_policy.managed_client_marker);
                    cursor += sizeof(data->attr_id) + strlen(reinterpret_cast<char *> (data->vendor_data)) + 1;
                } else if (data->attr_id == vendor_ext_attr_id_policy_alarm) {
                    em_link_stats_alarm_cfg_t *vendor = reinterpret_cast<em_link_stats_alarm_cfg_t *> (data->vendor_data);
                    memcpy(&policy.vendor_policy.link_stats_alarm_policy_cfg, vendor, sizeof(em_link_stats_alarm_cfg_t));

                    em_printfout(" Recvd link stats alarm cfg, collection_start_time : %s ", policy.vendor_policy.link_stats_alarm_policy_cfg.collection_start_time);
                    em_printfout(" Recvd link stats alarm cfg, reporting_interval : %d ", policy.vendor_policy.link_stats_alarm_policy_cfg.reporting_interval);
                    em_printfout(" Recvd link stats alarm cfg, link_quality_threshold : %f ", policy.vendor_policy.link_stats_alarm_policy_cfg.link_quality_threshold);

                    cursor += sizeof(data->attr_id) + sizeof(em_link_stats_alarm_cfg_t);
                } else if (data->attr_id == vendor_ext_attr_id_policy_cfg_client_filter) {
                    em_client_filters_cfg_t *vendor = reinterpret_cast<em_client_filters_cfg_t *> (data->vendor_data);
                    memcpy(&policy.vendor_policy.client_filters_policy_cfg, vendor, sizeof(em_client_filters_cfg_t));

                    em_printfout(" Recvd client filters cfg, sta_mac : %s ", util::mac_to_string(
                        policy.vendor_policy.client_filters_policy_cfg.sta_mac).c_str());
                    em_printfout(" Recvd client filters cfg, consec_alarm_thres_cnt : %d ", policy.vendor_policy.client_filters_policy_cfg.consec_alarm_thres_cnt);
                    em_printfout(" Recvd client filters cfg, collect_duration : %s ", policy.vendor_policy.client_filters_policy_cfg.collect_duration);

                    cursor += sizeof(data->attr_id) + sizeof(em_client_filters_cfg_t);
                } else {
                    em_printfout(" Unknown vendor attr id: %d ", data->attr_id);
                    break;
                }
            }
        }

        tlv_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
    }

    // Save as baseline for next partial update.
    last_policy = policy;

    get_mgr()->io_process(em_bus_event_type_set_policy, reinterpret_cast<unsigned char *> (&policy), sizeof(policy));
    send_1905_ack_message(ntohs(cmdu->id));

    return 0;
}

int em_policy_cfg_t::send_1905_ack_message(unsigned short msg_id)
{
    unsigned char buff[MAX_EM_BUFF_SZ] = {0};
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_1905_ack;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    mac_addr_str_t ctrl_mac_str;
    dm_easy_mesh_t::macbytes_to_string(dm->get_ctrl_al_interface_mac(), ctrl_mac_str);

    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    mac_addr_str_t agent_mac_str;
    dm_easy_mesh_t::macbytes_to_string(dm->get_agent_al_interface_mac(), agent_mac_str);

    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

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

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_1905_ack, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("1905 ACK validation failed\n");
        return 0;
    }

    if (send_frame(buff, len)  < 0) {
        em_printfout("1905 ACK send failed, error:%d\n", errno);
        return 0;
    }
    em_printfout("1905 ACK send success\n");

    return static_cast<int> (len);
}

int em_policy_cfg_t::handle_1905_ack(unsigned char *buff, unsigned int len)
{
    em_printfout("  ############ Handling 1905 ACK for Policy Cfg, msg len=%d", len);
    std::vector<em_t *> em_radios;
    bool match_found = false;

    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));
    unsigned short response_msg_id = ntohs(cmdu->id);
    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(buff);
    // Access the source MAC address (as a byte array)
    mac_address_t src_mac;
    memcpy(src_mac, hdr->src, sizeof(mac_address_t));
    get_mgr()->get_all_em_for_al_mac(src_mac, em_radios);

    for (auto &em : em_radios)
    {
	    if (em->get_state() == em_state_ctrl_set_policy_pending && response_msg_id == em->m_policy_req_msg_id) {
		    match_found = true;
		    em->m_policy_req_msg_id = 0;
		    break;
	    }
    }
    
    if (match_found) {
	    for (auto &em : em_radios) {
		    em->set_state(em_state_ctrl_configured);
	    }
    } else {
	    em_printfout("No radio waiting for policy config ack for given msg_id");
    }
    em_radios.clear();
    return 0;
}

void em_policy_cfg_t::process_msg(unsigned char *data, unsigned int len)
{
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));
    
    switch (htons(cmdu->type)) {
		case em_msg_type_map_policy_config_req:
			handle_policy_cfg_req(data, len);
			break;
		case em_msg_type_1905_ack:
			handle_1905_ack(data, len);
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
            {
                em_printfout("Processing set policy pending state for radio %s", util::mac_to_string(get_radio_interface_mac()).c_str());
                 std::vector<em_t *> em_radios;
                dm_easy_mesh_t *dm = get_data_model();
                mac_address_t current_ruid;
                memcpy(current_ruid, get_radio_interface_mac(), sizeof(mac_address_t));

                get_mgr()->get_all_em_for_al_mac(dm->get_agent_al_interface_mac(), em_radios);

                for (auto &em : em_radios) {
                    // Check for null em pointer in vector
                    if (em == NULL) {
                        em_printfout("Warning: Null em pointer in vector, skipping");
                        continue;
                    }
                    // Check if radio is in set policy pending, if not log and return without sending policy config request 
                    // check state of em is configured, to handle the case where radio exchange autoconfiguration messages multiple times
                    // resulting the queue of multiple em_cmd_type_em_config.
                    em_printfout("Checking radio[%s]'s state:%s for sending policy config request", util::mac_to_string(em->get_radio_interface_mac()).c_str(),  em_t::state_2_str(em->get_state()));
                    if (get_current_cmd()->get_type() != em_cmd_type_set_policy &&
                        em->get_state() != em_state_ctrl_set_policy_pending && em->get_state() != em_state_ctrl_configured) {
                        em_printfout("radio %s is in state:%s, not in em_state_ctrl_set_policy_pending or not in em_state_ctrl_configured",
                            util::mac_to_string(em->get_radio_interface_mac()).c_str(),  em_t::state_2_str(em->get_state()));
                        em_radios.clear();
                        return;
                    }
                }
                // If all radios or some radios in set policy pending state, send policy config request on one of them,
                // ignore sending policy config request on other radios
                if (!em_radios.empty() && em_radios.front() == this)
                {
                    // Check if current radio's RUID matches the first radio's RUID in the vector
                    if (memcmp(current_ruid, em_radios.front()->get_radio_interface_mac(), sizeof(mac_address_t)) == 0) {
                         em_printfout("Sending the Policy config request message to agent al_mac:%s on radio: %s",
                                 util::mac_to_string(dm->get_agent_al_interface_mac()).c_str(),
                                 util::mac_to_string(get_radio_interface_mac()).c_str());
                         // Send policy config request and check for errors
                         int send_result = send_policy_cfg_request_msg();
                         if (send_result < 0) {
                             em_printfout("Error: Failed to send policy config request message");
                         } else {
                             em_printfout("Policy config request sent successfully, bytes: %d", send_result);
                         }
                    }
                } else if (!em_radios.empty() && em_radios.front() != this) {
                    em_printfout("Policy config request message already sent by radio %s, not sending again from radio %s",
                              util::mac_to_string(em_radios.front()->get_radio_interface_mac()).c_str(),
                              util::mac_to_string(get_radio_interface_mac()).c_str());

                } else {
                    em_printfout("Policy config request already sent (msg_id: 0x%04x), waiting for ACK", m_policy_req_msg_id);
                }
                em_radios.clear();
            }
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


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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include "dm_policy.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"
#include "util.h"

int dm_policy_t::decode(const cJSON *obj, void *parent_id, em_policy_id_type_t type)
{
    cJSON *tmp, *sta_arr_obj;
	em_policy_id_t id;
	int i;

	//printf("%s:%d: Key: %s\tType: %d\n", __func__, __LINE__, (char *)parent_id, type);

    memset(&m_policy, 0, sizeof(em_policy_t));
	parse_dev_radio_mac_from_key(static_cast<char *>(parent_id), &id);
	strncpy(m_policy.id.net_id, id.net_id, sizeof(em_long_string_t));
	memcpy(m_policy.id.dev_mac, id.dev_mac, sizeof(mac_address_t));
	memcpy(m_policy.id.radio_mac, id.radio_mac, sizeof(mac_address_t));
	m_policy.id.type = type;	

	if ((type == em_policy_id_type_steering_local) || (type == em_policy_id_type_steering_btm)) {
		if ((sta_arr_obj = cJSON_GetObjectItem(obj, "Disallowed STA")) == NULL) {
			return 0;
		}
		static const mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		for (i = 0; i < cJSON_GetArraySize(sta_arr_obj); i++) {
			if (m_policy.num_sta >= EM_MAX_STA_PER_STEER_POLICY) {
				break;
			}
			tmp = cJSON_GetArrayItem(sta_arr_obj, i);
			char *mac_str = cJSON_GetStringValue(tmp);
			if (mac_str == NULL) {
				continue;
			}
			dm_easy_mesh_t::string_to_macbytes(mac_str, m_policy.sta_mac[m_policy.num_sta]);
			if (memcmp(m_policy.sta_mac[m_policy.num_sta], null_mac, sizeof(mac_address_t)) == 0) {
				continue;
			}
			m_policy.num_sta++;
		}
	} else if (type == em_policy_id_type_steering_param) {
		if ((tmp = cJSON_GetObjectItem(obj, "Steering Policy")) != NULL) {
			m_policy.policy = static_cast<em_steering_policy_type_t>(tmp->valuedouble);
		}	
		if ((tmp = cJSON_GetObjectItem(obj, "Utilization Threshold")) != NULL) {
			m_policy.util_threshold = static_cast<short unsigned int>(tmp->valuedouble);
		}	
		if ((tmp = cJSON_GetObjectItem(obj, "RCPI Threshold")) != NULL) {
			m_policy.rcpi_threshold = static_cast<short unsigned int>(tmp->valuedouble);
		}	
	} else if (type == em_policy_id_type_ap_metrics_rep) {
    	if ((tmp = cJSON_GetObjectItem(obj, "Interval")) != NULL) {
			m_policy.interval = static_cast<short unsigned int>(tmp->valuedouble);
    	}
    	if ((tmp = cJSON_GetObjectItem(obj, "Managed Client Marker")) != NULL) {
            snprintf(m_policy.managed_sta_marker, sizeof(em_long_string_t), "%s", cJSON_GetStringValue(tmp));
    	}
	} else if (type == em_policy_id_type_radio_metrics_rep) {
        if ((tmp = cJSON_GetObjectItem(obj, "STA RCPI Threshold")) != NULL) {
            m_policy.rcpi_threshold = static_cast<short unsigned int>(tmp->valuedouble);
        }
        if ((tmp = cJSON_GetObjectItem(obj, "STA RCPI Hysteresis")) != NULL) {
            m_policy.rcpi_hysteresis = static_cast<short unsigned int>(tmp->valuedouble);
        }
        if ((tmp = cJSON_GetObjectItem(obj, "AP Utilization Thresold")) != NULL) {
            m_policy.util_threshold = static_cast<short unsigned int>(tmp->valuedouble);
        }
        if ((tmp = cJSON_GetObjectItem(obj, "STA Traffic Stats")) != NULL) {
            m_policy.sta_traffic_stats = tmp->valuedouble;
        }
        if ((tmp = cJSON_GetObjectItem(obj, "STA Link Metrics")) != NULL) {
            m_policy.sta_link_metric = tmp->valuedouble;
        }
        if ((tmp = cJSON_GetObjectItem(obj, "STA Status")) != NULL) {
            m_policy.sta_status = tmp->valuedouble;
        }
	} else if (type == em_policy_id_type_default_8021q_settings) {
		if ((tmp = cJSON_GetObjectItem(obj, "Primary VLAN ID")) != NULL) {
			m_policy.def_8021q_settings.primary_vid = static_cast<unsigned short>(tmp->valuedouble);
		}
		if ((tmp = cJSON_GetObjectItem(obj, "Default PCP")) != NULL) {
			m_policy.def_8021q_settings.default_pcp = static_cast<unsigned char>(tmp->valuedouble);
		}
    } else if (type == em_policy_id_type_channel_scan) {
    	if ((tmp = cJSON_GetObjectItem(obj, "Report Independent Channel Scans")) != NULL) {
   			m_policy.independent_scan_report = tmp->valuedouble;
    	}
    } else if (type == em_policy_id_type_unsuccess_assoc) {
		if ((tmp = cJSON_GetObjectItem(obj, "Report Unsuccessful Associations")) != NULL) {
			m_policy.report_unassoc_sta = static_cast<bool>(tmp->valueint);
		}
		if ((tmp = cJSON_GetObjectItem(obj, "Maximum Reporting Rate")) != NULL) {
			m_policy.max_reporting_rate = static_cast<unsigned int>(tmp->valuedouble);
		}
	} else if (type == em_policy_id_type_backhaul_bss_config) {
        if ((tmp = cJSON_GetObjectItem(obj, "BSSID")) != NULL) {
			if (m_policy.num_backhaul_bss_config < EM_MAX_BSS_PER_RADIO) {
				unsigned int slot = m_policy.num_backhaul_bss_config;
				dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(tmp), m_policy.backhaul_bss_config[slot].bssid);
				if ((tmp = cJSON_GetObjectItem(obj, "Profile-1 bSTA Disallowed")) != NULL) {
					m_policy.backhaul_bss_config[slot].b_profile_1_sta_disallowed = static_cast<bool>(tmp->valueint);
				}
				if ((tmp = cJSON_GetObjectItem(obj, "Profile-2 bSTA Disallowed")) != NULL) {
					m_policy.backhaul_bss_config[slot].b_profile_2_sta_disallowed = static_cast<bool>(tmp->valueint);
				}
				m_policy.num_backhaul_bss_config++;
			}
		}
	} else if (type == em_policy_id_type_qos_mgt) {
		if (m_policy.num_qos_mgt < EM_MAX_STA_PER_AGENT) {
			unsigned int slot = m_policy.num_qos_mgt;
			cJSON *mac_arr_obj;
			if ((mac_arr_obj = cJSON_GetObjectItem(obj, "MSCS Disallowed STA List")) != NULL) {
				for (i = 0; i < static_cast<int>(cJSON_GetArraySize(mac_arr_obj)) &&
						m_policy.qos_mgt[slot].num_mscs < EM_MAX_MSC_PER_TRAFFIC_SEPAR; i++) {
					tmp = cJSON_GetArrayItem(mac_arr_obj, i);
					dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(tmp),
							m_policy.qos_mgt[slot].msc_mac[m_policy.qos_mgt[slot].num_mscs]);
					m_policy.qos_mgt[slot].num_mscs++;
				}
			}
			if ((mac_arr_obj = cJSON_GetObjectItem(obj, "SCS Disallowed STA List")) != NULL) {
				for (i = 0; i < static_cast<int>(cJSON_GetArraySize(mac_arr_obj)) &&
						m_policy.qos_mgt[slot].num_scs < EM_MAX_SCS_PER_TRAFFIC_SEPAR; i++) {
					tmp = cJSON_GetArrayItem(mac_arr_obj, i);
					dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(tmp),
							m_policy.qos_mgt[slot].sc_mac[m_policy.qos_mgt[slot].num_scs]);
					m_policy.qos_mgt[slot].num_scs++;
				}
			}
			m_policy.num_qos_mgt++;
		}
	} else if (type == em_policy_id_type_alarm_threshold) {
        if ((tmp = cJSON_GetObjectItem(obj, "Collection Start Time")) != NULL) {
            snprintf(m_policy.link_stats_alarm_cfg.collection_start_time, sizeof(em_long_string_t), "%s", cJSON_GetStringValue(tmp));
        }
        if ((tmp = cJSON_GetObjectItem(obj, "Reporting Interval")) != NULL) {
            m_policy.link_stats_alarm_cfg.reporting_interval = tmp->valuedouble;
        }
        if ((tmp = cJSON_GetObjectItem(obj, "Link Quality Threshold")) != NULL) {
            m_policy.link_stats_alarm_cfg.link_quality_threshold = static_cast<float>(tmp->valuedouble);
        }
	} else if (type == em_policy_id_type_client_filters) {
        cJSON *client_filter_obj = NULL;
        cJSON *filter_config = NULL;
        // Iterate over object members (MAC addresses as keys)
        cJSON_ArrayForEach(client_filter_obj, obj) {
            if (client_filter_obj->string != NULL) {
                em_printfout("Decoding Client Filter Policy for %s", client_filter_obj->string);
                dm_easy_mesh_t::string_to_macbytes(client_filter_obj->string, m_policy.client_filters.sta_mac);

                filter_config = client_filter_obj;
                if ((tmp = cJSON_GetObjectItem(filter_config, "Consecutive Alarm Threshold")) != NULL)
                {
                    m_policy.client_filters.consec_alarm_thres_cnt = static_cast<unsigned int>(tmp->valuedouble);
                }
                if ((tmp = cJSON_GetObjectItem(filter_config, "Debug Duration")) != NULL)
                {
                    snprintf(m_policy.client_filters.collect_duration, sizeof(em_small_string_t), "%s", cJSON_GetStringValue(tmp));
                }
            }
        }

        em_printfout(" CLIENT FILTERS STA MAC='%s', CONSEC ALARM THRESHOLD=%d ,DURATION=%s ",
            util::mac_to_string(m_policy.client_filters.sta_mac).c_str(),
            m_policy.client_filters.consec_alarm_thres_cnt,
            m_policy.client_filters.collect_duration);
    }
	
	return 0;
}

void dm_policy_t::encode(cJSON *obj, em_policy_id_type_t id)
{
    unsigned int i;
	mac_addr_str_t	dev_mac_str, radio_mac_str, sta_mac_str;
	cJSON *sta_arr_obj;

	dm_easy_mesh_t::macbytes_to_string(m_policy.id.dev_mac, dev_mac_str);
	dm_easy_mesh_t::macbytes_to_string(m_policy.id.radio_mac, radio_mac_str);

	if ((id == em_policy_id_type_steering_local) || (id == em_policy_id_type_steering_btm)) {
		static const mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		sta_arr_obj = cJSON_AddArrayToObject(obj, "Disallowed STA");
		for (i = 0; i < m_policy.num_sta; i++) {
			if (memcmp(m_policy.sta_mac[i], null_mac, sizeof(mac_address_t)) == 0) {
				continue;
			}
			dm_easy_mesh_t::macbytes_to_string(m_policy.sta_mac[i], sta_mac_str);
			cJSON_AddItemToArray(sta_arr_obj, cJSON_CreateString(sta_mac_str));
		}

	} else if (id == em_policy_id_type_steering_param) {
		cJSON_AddNumberToObject(obj, "Steering Policy", static_cast<unsigned int>(m_policy.policy));
    	cJSON_AddNumberToObject(obj, "Utilization Threshold", m_policy.util_threshold);
    	cJSON_AddNumberToObject(obj, "RCPI Threshold", m_policy.rcpi_threshold);
	} else if (id == em_policy_id_type_ap_metrics_rep) {
		cJSON_AddNumberToObject(obj, "Interval", m_policy.interval);
    	cJSON_AddStringToObject(obj, "Managed Client Marker", m_policy.managed_sta_marker);
	} else if (id == em_policy_id_type_radio_metrics_rep) {
		cJSON_AddNumberToObject(obj, "STA RCPI Threshold", m_policy.rcpi_threshold);
		cJSON_AddNumberToObject(obj, "STA RCPI Hysteresis", m_policy.rcpi_hysteresis);
		cJSON_AddNumberToObject(obj, "AP Utilization Thresold", m_policy.util_threshold);
		cJSON_AddNumberToObject(obj, "STA Traffic Stats", m_policy.sta_traffic_stats);
		cJSON_AddNumberToObject(obj, "STA Link Metrics", m_policy.sta_link_metric);
		cJSON_AddNumberToObject(obj, "STA Status", m_policy.sta_status);
	} else if (id == em_policy_id_type_default_8021q_settings) {
		cJSON_AddNumberToObject(obj, "Primary VLAN ID", m_policy.def_8021q_settings.primary_vid);
		cJSON_AddNumberToObject(obj, "Default PCP", m_policy.def_8021q_settings.default_pcp);
	} else if (id == em_policy_id_type_channel_scan) {
		cJSON_AddNumberToObject(obj, "Report Independent Channel Scans", m_policy.independent_scan_report);
	} else if (id == em_policy_id_type_unsuccess_assoc) {
        cJSON_AddBoolToObject(obj, "Report Unsuccessful Associations", m_policy.report_unassoc_sta);
        cJSON_AddNumberToObject(obj, "Maximum Reporting Rate", m_policy.max_reporting_rate);
	} else if (id == em_policy_id_type_backhaul_bss_config) {
		for (unsigned int b = 0; b < m_policy.num_backhaul_bss_config; b++) {
			cJSON *item = cJSON_CreateObject();
			dm_easy_mesh_t::macbytes_to_string(m_policy.backhaul_bss_config[b].bssid, sta_mac_str);
			cJSON_AddStringToObject(item, "BSSID", sta_mac_str);
			cJSON_AddBoolToObject(item, "Profile-1 bSTA Disallowed", m_policy.backhaul_bss_config[b].b_profile_1_sta_disallowed);
			cJSON_AddBoolToObject(item, "Profile-2 bSTA Disallowed", m_policy.backhaul_bss_config[b].b_profile_2_sta_disallowed);
			cJSON_AddItemToArray(obj, item);
		}
	} else if (id == em_policy_id_type_qos_mgt) {
		for (unsigned int q = 0; q < m_policy.num_qos_mgt; q++) {
			cJSON *mscs_arr = cJSON_AddArrayToObject(obj, "MSCS Disallowed STA List");
			for (i = 0; i < m_policy.qos_mgt[q].num_mscs; i++) {
				dm_easy_mesh_t::macbytes_to_string(m_policy.qos_mgt[q].msc_mac[i], sta_mac_str);
				cJSON_AddItemToArray(mscs_arr, cJSON_CreateString(sta_mac_str));
			}
			cJSON *scs_arr = cJSON_AddArrayToObject(obj, "SCS Disallowed STA List");
			for (i = 0; i < m_policy.qos_mgt[q].num_scs; i++) {
				dm_easy_mesh_t::macbytes_to_string(m_policy.qos_mgt[q].sc_mac[i], sta_mac_str);
				cJSON_AddItemToArray(scs_arr, cJSON_CreateString(sta_mac_str));
			}
		}
	}
}

bool dm_policy_t::operator == (const dm_policy_t& obj)
{
    int ret = 0;

    ret += (memcmp(&m_policy, &obj.m_policy, sizeof(em_policy_t)) != 0);

    return (ret > 0) ? false:true;
}

void dm_policy_t::operator = (const dm_policy_t& obj)
{
    if (this == &obj) { return; }
    memcpy(&m_policy, &obj.m_policy, sizeof(em_policy_t));
}

int dm_policy_t::parse_dev_radio_mac_from_key(const char *key, em_policy_id_t *id)
{
    em_long_string_t   str;
    char *tmp, *remain;
    unsigned int i = 0;

    strncpy(str, key, strlen(key) + 1);
    remain = str;
    while ((tmp = strchr(remain, '@')) != NULL) {
        if (i == 0) {
            *tmp = 0;
            strncpy(id->net_id, remain, strlen(remain) + 1);
            tmp++;
            remain = tmp;
        } else if (i == 1) {
            *tmp = 0;
			dm_easy_mesh_t::string_to_macbytes(remain, id->dev_mac);
            tmp++;
			remain = tmp;
        } else if (i == 2) {
            *tmp = 0;
			dm_easy_mesh_t::string_to_macbytes(remain, id->radio_mac);
            tmp++;
			id->type = static_cast<em_policy_id_type_t>(atoi(tmp));
		}
        i++;
    }

    return 0;
}

dm_policy_t::dm_policy_t(em_policy_t *policy)
{
    memcpy(&m_policy, policy, sizeof(em_policy_t));
}

dm_policy_t::dm_policy_t(const dm_policy_t& policy)
{
    memcpy(&m_policy, &policy.m_policy, sizeof(em_policy_t));
}

dm_policy_t::dm_policy_t(const em_policy_t& policy)
{
    memcpy(&m_policy, &policy, sizeof(em_policy_t));
}

dm_policy_t::dm_policy_t()
{
	memset(&m_policy, 0, sizeof(em_policy_t));
}

dm_policy_t::~dm_policy_t()
{

}

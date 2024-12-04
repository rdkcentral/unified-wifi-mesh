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
#include "dm_policy.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_policy_t::decode(const cJSON *obj, void *parent_id, em_policy_id_type_t type)
{
    cJSON *tmp, *sta_arr_obj;
	mac_addr_str_t	mac_str;
	em_policy_id_t id;
	unsigned int i;

	//printf("%s:%d: Key: %s\tType: %d\n", __func__, __LINE__, (char *)parent_id, type);

    memset(&m_policy, 0, sizeof(em_policy_t));
	parse_dev_radio_mac_from_key((char *)parent_id, &id);
	strncpy(m_policy.id.net_id, id.net_id, strlen(id.net_id));
	memcpy(m_policy.id.dev_mac, id.dev_mac, sizeof(mac_address_t));
	memcpy(m_policy.id.radio_mac, id.radio_mac, sizeof(mac_address_t));
	m_policy.id.type = type;	

	if ((type == em_policy_id_type_steering_local) || (type == em_policy_id_type_steering_btm)) {
		if ((sta_arr_obj = cJSON_GetObjectItem(obj, "Disallowed STA")) == NULL) {
			return 0;
		}
		for (i = 0; i < cJSON_GetArraySize(sta_arr_obj); i++) {
			tmp = cJSON_GetArrayItem(sta_arr_obj, i);
			dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(cJSON_GetObjectItem(tmp, "MAC")), 
					m_policy.sta_mac[m_policy.num_sta]);
			m_policy.num_sta++;	
		}
	} else if (type == em_policy_id_type_steering_param) {
		if ((tmp = cJSON_GetObjectItem(obj, "Steering Policy")) != NULL) {
			m_policy.policy = (em_steering_policy_type_t)tmp->valuedouble;
		}	
		if ((tmp = cJSON_GetObjectItem(obj, "Utilization Threshold")) != NULL) {
			m_policy.util_threshold = tmp->valuedouble;
		}	
		if ((tmp = cJSON_GetObjectItem(obj, "RCPI Thresold")) != NULL) {
			m_policy.rcpi_threshold = tmp->valuedouble;
		}	
	} else if (type == em_policy_id_type_ap_metrics_rep) {
    	if ((tmp = cJSON_GetObjectItem(obj, "Interval")) != NULL) {
        	m_policy.interval = tmp->valuedouble;
    	}
    	if ((tmp = cJSON_GetObjectItem(obj, "Managed Client Marker")) != NULL) {
			strncpy(m_policy.managed_sta_marker, cJSON_GetStringValue(tmp), sizeof(em_long_string_t));
    	}
	} else if (type == em_policy_id_type_radio_metrics_rep) {
    	if ((tmp = cJSON_GetObjectItem(obj, "STA RCPI Threshold")) != NULL) {
        	m_policy.rcpi_threshold = tmp->valuedouble;
    	}
    	if ((tmp = cJSON_GetObjectItem(obj, "STA RCPI Hysteresis")) != NULL) {
        	m_policy.rcpi_hysteresis = tmp->valuedouble;
    	}
    	if ((tmp = cJSON_GetObjectItem(obj, "AP Utilization Thresold")) != NULL) {
       		m_policy.util_threshold = tmp->valuedouble;
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
	} else if (type == em_policy_id_type_channel_scan) {
    	if ((tmp = cJSON_GetObjectItem(obj, "Report Independent Channel Scans")) != NULL) {
   			m_policy.independent_scan_report = tmp->valuedouble;
    	}
	} 
	
	return 0;

}

void dm_policy_t::encode(cJSON *obj, em_policy_id_type_t id)
{
    unsigned int i;
	mac_addr_str_t	dev_mac_str, radio_mac_str, sta_mac_str;
	cJSON *sta_arr_obj, *sta_obj;

	dm_easy_mesh_t::macbytes_to_string(m_policy.id.dev_mac, dev_mac_str);
	dm_easy_mesh_t::macbytes_to_string(m_policy.id.radio_mac, radio_mac_str);

	if ((id == em_policy_id_type_steering_local) || (id == em_policy_id_type_steering_btm)) {
		sta_arr_obj = cJSON_AddArrayToObject(obj, "Disallowed STA");
		for (i = 0; i < m_policy.num_sta; i++) {
			sta_obj = cJSON_CreateObject();
			dm_easy_mesh_t::macbytes_to_string(m_policy.sta_mac[i], sta_mac_str);
			cJSON_AddStringToObject(sta_obj, "MAC", sta_mac_str);
			cJSON_AddItemToArray(sta_arr_obj, sta_obj);
		}

	} else if (id == em_policy_id_type_steering_param) {
    	cJSON_AddNumberToObject(obj, "Steering Policy", (unsigned int)m_policy.policy);
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
	} else if (id == em_policy_id_type_channel_scan) {
		cJSON_AddNumberToObject(obj, "Report Independent Channel Scans", m_policy.independent_scan_report);
	} else if (id == em_policy_id_type_backhaul_bss_config) {

	}


}

bool dm_policy_t::operator == (const dm_policy_t& obj)
{
    int ret = 0;
    
	ret += (memcmp(&this->m_policy.id.dev_mac, &obj.m_policy.id.dev_mac, sizeof(mac_address_t)) != 0);
	ret += (memcmp(&this->m_policy.id.radio_mac, &obj.m_policy.id.radio_mac, sizeof(mac_address_t)) != 0);
    ret += !(this->m_policy.interval == obj.m_policy.interval);
    ret += !(this->m_policy.rcpi_threshold == obj.m_policy.rcpi_threshold);
    ret += !(this->m_policy.rcpi_hysteresis == obj.m_policy.rcpi_hysteresis);
    ret += !(this->m_policy.util_threshold == obj.m_policy.util_threshold);
    ret += !(this->m_policy.sta_traffic_stats == obj.m_policy.sta_traffic_stats);
    ret += !(this->m_policy.sta_link_metric == obj.m_policy.sta_link_metric);
    ret += !(this->m_policy.sta_status == obj.m_policy.sta_status);
	ret += (strncmp(this->m_policy.managed_sta_marker, obj.m_policy.managed_sta_marker, strlen(this->m_policy.managed_sta_marker)) != 0);
     

	return (ret > 0) ? false:true;
}

void dm_policy_t::operator = (const dm_policy_t& obj)
{
    memcpy(&this->m_policy.id.dev_mac, &obj.m_policy.id.dev_mac, sizeof(mac_address_t));
    memcpy(&this->m_policy.id.radio_mac, &obj.m_policy.id.radio_mac, sizeof(mac_address_t));
    this->m_policy.interval = obj.m_policy.interval;
    this->m_policy.rcpi_threshold = obj.m_policy.rcpi_threshold;
    this->m_policy.rcpi_hysteresis = obj.m_policy.rcpi_hysteresis;
    this->m_policy.util_threshold = obj.m_policy.util_threshold;
    this->m_policy.sta_traffic_stats = obj.m_policy.sta_traffic_stats;
    this->m_policy.sta_link_metric = obj.m_policy.sta_link_metric;
    this->m_policy.sta_status = obj.m_policy.sta_status;
    strncpy(this->m_policy.managed_sta_marker, obj.m_policy.managed_sta_marker, strlen(obj.m_policy.managed_sta_marker) + 1);
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
			id->type = (em_policy_id_type_t)atoi(tmp);
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

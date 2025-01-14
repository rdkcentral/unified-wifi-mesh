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
#include "dm_scan_result.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_scan_result_t::decode(const cJSON *obj, void *parent_id)
{
	cJSON *tmp, *arr_item;
	char *str;
	unsigned int i;

	memset(&m_scan_result, 0, sizeof(em_scan_result_t));
	
	if ((tmp = cJSON_GetObjectItem(obj, "ScanStatus")) != NULL) {
		m_scan_result.scan_status = cJSON_GetNumberValue(tmp);
	}

	if ((tmp = cJSON_GetObjectItem(obj, "TimeStamp")) != NULL) {
		str = cJSON_GetStringValue(tmp);
		strncpy(m_scan_result.timestamp, str, strlen(str) + 1);
	}

	if ((tmp = cJSON_GetObjectItem(obj, "Utilization")) != NULL) {
		m_scan_result.util = cJSON_GetNumberValue(tmp);
	}

	if ((tmp = cJSON_GetObjectItem(obj, "Noise")) != NULL) {
		m_scan_result.noise = cJSON_GetNumberValue(tmp);
	}

	if ((tmp = cJSON_GetObjectItem(obj, "Neighbors")) == NULL) {
		return 0;
	}

	for (i = 0; i < cJSON_GetArraySize(tmp); i++) {
		arr_item = cJSON_GetArrayItem(tmp, i);
		
		if ((tmp = cJSON_GetObjectItem(arr_item, "BSSID")) != NULL) {
			str = cJSON_GetStringValue(tmp); 
			dm_easy_mesh_t::string_to_macbytes(str, m_scan_result.neighbor[m_scan_result.num_neighbors].bssid);
		}
		
		if ((tmp = cJSON_GetObjectItem(arr_item, "SSID")) != NULL) {
			str = cJSON_GetStringValue(tmp); 
			strncpy(m_scan_result.neighbor[m_scan_result.num_neighbors].ssid, str, strlen(str) + 1);
		}
			
		if ((tmp = cJSON_GetObjectItem(arr_item, "SignalStrength")) != NULL) {
			m_scan_result.neighbor[m_scan_result.num_neighbors].signal_strength = cJSON_GetNumberValue(tmp);
		}

		if ((tmp = cJSON_GetObjectItem(arr_item, "Bandwidth")) != NULL) {
			m_scan_result.neighbor[m_scan_result.num_neighbors].bandwidth = (wifi_channelBandwidth_t)cJSON_GetNumberValue(tmp);
		}

		if ((tmp = cJSON_GetObjectItem(arr_item, "BSSColor")) != NULL) {
			m_scan_result.neighbor[m_scan_result.num_neighbors].bss_color = cJSON_GetNumberValue(tmp);
		}

		if ((tmp = cJSON_GetObjectItem(arr_item, "ChannelUtil")) != NULL) {
			m_scan_result.neighbor[m_scan_result.num_neighbors].channel_util = cJSON_GetNumberValue(tmp);
		}

		if ((tmp = cJSON_GetObjectItem(arr_item, "STACount")) != NULL) {
			m_scan_result.neighbor[m_scan_result.num_neighbors].sta_count = cJSON_GetNumberValue(tmp);
		}

		if ((tmp = cJSON_GetObjectItem(arr_item, "ScanDuration")) != NULL) {
			m_scan_result.neighbor[m_scan_result.num_neighbors].aggr_scan_duration = cJSON_GetNumberValue(tmp);
		}

		if ((tmp = cJSON_GetObjectItem(arr_item, "ScanType")) != NULL) {
			m_scan_result.neighbor[m_scan_result.num_neighbors].scan_type = cJSON_GetNumberValue(tmp);
		}

	}	

	return 0;
}

void dm_scan_result_t::encode(cJSON *obj, em_scan_result_id_t id)
{
	cJSON *arr_obj, *tmp;
	unsigned int i;
	mac_addr_str_t	bssid_str;

	cJSON_AddNumberToObject(obj, "ScanStatus", m_scan_result.scan_status);
	cJSON_AddStringToObject(obj, "TimeStamp", m_scan_result.timestamp);
	cJSON_AddNumberToObject(obj, "Utilization", m_scan_result.util);
	cJSON_AddNumberToObject(obj, "Noise", m_scan_result.noise);
	
	arr_obj = cJSON_AddArrayToObject(obj, "Neighbors");
	for (i = 0; i < m_scan_result.num_neighbors; i++) {
		tmp = cJSON_CreateObject();

		dm_easy_mesh_t::macbytes_to_string(m_scan_result.neighbor[i].bssid, bssid_str);
		cJSON_AddStringToObject(tmp, "BSSID", bssid_str);	
		cJSON_AddStringToObject(tmp, "SSID", m_scan_result.neighbor[i].ssid);	
		cJSON_AddNumberToObject(tmp, "SignalStrength", m_scan_result.neighbor[i].signal_strength);
		cJSON_AddNumberToObject(tmp, "Bandwidth", m_scan_result.neighbor[i].bandwidth);
		cJSON_AddNumberToObject(tmp, "BSSColor", m_scan_result.neighbor[i].bss_color);
		cJSON_AddNumberToObject(tmp, "ChannelUtil", m_scan_result.neighbor[i].channel_util);
		cJSON_AddNumberToObject(tmp, "STACount", m_scan_result.neighbor[i].sta_count);
		cJSON_AddNumberToObject(tmp, "ScanDuration", m_scan_result.neighbor[i].aggr_scan_duration);
		cJSON_AddNumberToObject(tmp, "ScanType", m_scan_result.neighbor[i].scan_type);
		
		cJSON_AddItemToArray(arr_obj, tmp);
	}
}

bool dm_scan_result_t::operator == (const dm_scan_result_t& obj)
{
    int ret = 0;
    
	return (ret > 0) ? false:true;
}

void dm_scan_result_t::operator = (const dm_scan_result_t& obj)
{

}

int dm_scan_result_t::parse_scan_result_id_from_key(const char *key, em_scan_result_id_t *id)
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
            dm_easy_mesh_t::string_to_macbytes(remain, id->ruid);
            tmp++;
            remain = tmp;
        } else if (i == 3) {
            *tmp = 0; 
			id->op_class = atoi(tmp);
            tmp++;
			id->channel = atoi(tmp);
        }   
        i++;
    }
    

    return 0;
}

dm_scan_result_t::dm_scan_result_t(em_scan_result_t *scan_result)
{
    memcpy(&m_scan_result, scan_result, sizeof(em_scan_result_t));
}

dm_scan_result_t::dm_scan_result_t(const dm_scan_result_t& scan_result)
{
    memcpy(&m_scan_result, &scan_result.m_scan_result, sizeof(em_scan_result_t));
}

dm_scan_result_t::dm_scan_result_t(const em_scan_result_t& scan_result)
{
    memcpy(&m_scan_result, &scan_result, sizeof(em_scan_result_t));
}

dm_scan_result_t::dm_scan_result_t()
{
	memset(&m_scan_result, 0, sizeof(em_scan_result_t));
}

dm_scan_result_t::~dm_scan_result_t()
{

}

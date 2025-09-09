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
#include "dm_easy_mesh_ctrl.h"
#include "dm_easy_mesh.h"
#include "util.h"

int dm_network_t::decode(const cJSON *obj, void *parent_id)
{
    cJSON *tmp;
    mac_addr_str_t  mac_str;

    memset(&m_net_info, 0, sizeof(em_network_info_t));

    if ((tmp = cJSON_GetObjectItem(obj, "ID")) != NULL) {
        snprintf(m_net_info.id, sizeof(m_net_info.id), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "NumberOfDevices")) != NULL) {
       m_net_info.num_of_devices = static_cast<short unsigned int> (cJSON_IsTrue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "TimeStamp")) != NULL) {
        snprintf(m_net_info.timestamp, sizeof(m_net_info.timestamp), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "ControllerID")) != NULL) {
        snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
        dm_easy_mesh_t::string_to_macbytes(mac_str, m_net_info.ctrl_id.mac);
        dm_easy_mesh_t::name_from_mac_address(&m_net_info.ctrl_id.mac, m_net_info.ctrl_id.name);

    }

#ifdef STA_ENGANCEMENT
    cJSON *tmp_arr;
    if ((tmp_arr = cJSON_GetObjectItem(obj, "MSCSDisallowedStaList")) != NULL) {
        m_net_info.num_mscs_disallowed_sta = cJSON_GetArraySize(tmp_arr);
        for (i = 0; i < m_net_info.num_mscs_disallowed_sta; i++) {
            tmp = cJSON_GetArrayItem(tmp_arr, i);
            snprintf(m_net_info.mscs_disallowed_sta[i], sizeof(m_net_info.mscs_disallowed_sta[i]), "%s", cJSON_GetStringValue(tmp));
        }
    }

    if ((tmp_arr = cJSON_GetObjectItem(obj, "SCSDisallowedStaList")) != NULL) {
        m_net_info.num_scs_disallowed_sta = cJSON_GetArraySize(tmp_arr);
        for (i = 0; i < m_net_info.num_scs_disallowed_sta; i++) {
            tmp = cJSON_GetArrayItem(tmp_arr, i);
            snprintf(m_net_info.scs_disallowed_sta[i], sizeof(m_net_info.scs_disallowed_sta[i]), "%s", cJSON_GetStringValue(tmp));
        }
    }
#endif

    if ((tmp = cJSON_GetObjectItem(obj, "CollocatedAgentID")) != NULL) {
        snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
        dm_easy_mesh_t::string_to_macbytes(mac_str, m_net_info.colocated_agent_id.mac);
	}

    if ((tmp = cJSON_GetObjectItem(obj, "MediaType")) != NULL) {
		if (strncmp(cJSON_GetStringValue(tmp), "Wireless", strlen("Wireless")) == 0) { 
			m_net_info.media = em_media_type_ieee80211b_24;
		} else if (strncmp(cJSON_GetStringValue(tmp), "Ethernet", strlen("Ethernet")) == 0) {
			m_net_info.media = em_media_type_ieee8023ab;
		} else {
			m_net_info.media = em_media_type_ieee80211b_24;
		}
	}

    return 0;
}

void dm_network_t::encode(cJSON *obj, bool summary)
{
    mac_addr_str_t  mac_str;
	em_string_t	str;

    cJSON_AddStringToObject(obj, "ID", m_net_info.id);

    cJSON_AddNumberToObject(obj, "NumberOfDevices", m_net_info.num_of_devices); 
    cJSON_AddStringToObject(obj, "TimeStamp", m_net_info.timestamp);

    dm_easy_mesh_t::macbytes_to_string(m_net_info.ctrl_id.mac, mac_str);
    cJSON_AddStringToObject(obj, "ControllerID", mac_str);
    
#ifdef STA_ENGANCEMENT
    cJSON *mscs_staArray = cJSON_CreateArray();
    for (i = 0; i < m_net_info.num_mscs_disallowed_sta; i++) {
        cJSON_AddItemToArray(mscs_staArray, cJSON_CreateString(m_net_info.mscs_disallowed_sta[i]));
    }

    // Add the array to the object
    cJSON_AddItemToObject(obj, "MSCSDisallowedStaList", mscs_staArray);

    cJSON *scs_staArray = cJSON_CreateArray();
    for (i = 0; i < m_net_info.num_scs_disallowed_sta; i++) {
        cJSON_AddItemToArray(scs_staArray, cJSON_CreateString(m_net_info.scs_disallowed_sta[i]));
    }
    // Add the array to the object
    cJSON_AddItemToObject(obj, "SCSDisallowedStaList", scs_staArray);
#endif

    dm_easy_mesh_t::macbytes_to_string(m_net_info.colocated_agent_id.mac, mac_str);
    cJSON_AddStringToObject(obj, "CollocatedAgentID", mac_str);
	
	if (m_net_info.media == em_media_type_ieee8023ab) {
		strncpy(str, "Ethernet", strlen("Ethernet") + 1);
	} else if (m_net_info.media == em_media_type_ieee80211b_24) {
		strncpy(str, "Wireless", strlen("Wireless") + 1);
	} else {
		strncpy(str, "Unknown", strlen("Unknown") + 1);

	}
    cJSON_AddStringToObject(obj, "MediaType", str);
}

bool dm_network_t::operator == (const dm_network_t& obj)
{    
    int ret = 0;
    ret += (memcmp(&this->m_net_info.id,&obj.m_net_info.id,sizeof(em_long_string_t)) != 0);
    ret += !(this->m_net_info.num_of_devices == obj.m_net_info.num_of_devices);
    ret += (memcmp(&this->m_net_info.timestamp,&obj.m_net_info.timestamp,sizeof(em_long_string_t)) != 0);
    ret += (memcmp(&this->m_net_info.ctrl_id.mac ,&obj.m_net_info.ctrl_id.mac,sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_net_info.ctrl_id.name,&obj.m_net_info.ctrl_id.name,sizeof(em_interface_name_t)) != 0);
    ret += !(this->m_net_info.num_mscs_disallowed_sta == obj.m_net_info.num_mscs_disallowed_sta);
    for (int i = 0; i < this->m_net_info.num_mscs_disallowed_sta; i++) {
        ret += (memcmp(&this->m_net_info.mscs_disallowed_sta[i], &obj.m_net_info.mscs_disallowed_sta[i], sizeof(em_string_t)) != 0);
    }
    ret += !(this->m_net_info.num_scs_disallowed_sta == obj.m_net_info.num_scs_disallowed_sta);
    for (int i = 0; i < this->m_net_info.num_scs_disallowed_sta; i++) {
        ret += (memcmp(&this->m_net_info.scs_disallowed_sta[i], &obj.m_net_info.scs_disallowed_sta[i], sizeof(em_string_t)) != 0);
    }
    ret += (memcmp(&this->m_net_info.colocated_agent_id.mac ,&obj.m_net_info.colocated_agent_id.mac,sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_net_info.colocated_agent_id.name,&obj.m_net_info.colocated_agent_id.name,sizeof(em_interface_name_t)) != 0);

    if (ret > 0)
        return false;
    else
        return true;
}

void dm_network_t::operator = (const dm_network_t& obj)
{
    if (this == &obj) { return; }
    memcpy(&this->m_net_info.id,&obj.m_net_info.id,sizeof(em_long_string_t));
    this->m_net_info.num_of_devices = obj.m_net_info.num_of_devices;
    strncpy(this->m_net_info.timestamp, obj.m_net_info.timestamp, sizeof(em_long_string_t));
    memcpy(&this->m_net_info.ctrl_id.mac ,&obj.m_net_info.ctrl_id.mac,sizeof(mac_address_t));
    memcpy(&this->m_net_info.ctrl_id.name,&obj.m_net_info.ctrl_id.name,sizeof(em_interface_name_t));
    this->m_net_info.num_mscs_disallowed_sta = obj.m_net_info.num_mscs_disallowed_sta;
    for (int i = 0; i < this->m_net_info.num_mscs_disallowed_sta; i++) {
        memcpy(&this->m_net_info.mscs_disallowed_sta[i], &obj.m_net_info.mscs_disallowed_sta[i], sizeof(em_string_t));
    }
    this->m_net_info.num_scs_disallowed_sta = obj.m_net_info.num_scs_disallowed_sta;
    for (int i = 0; i < this->m_net_info.num_scs_disallowed_sta; i++) {
        memcpy(&this->m_net_info.scs_disallowed_sta[i], &obj.m_net_info.scs_disallowed_sta[i], sizeof(em_string_t));
    }
    memcpy(&this->m_net_info.colocated_agent_id.mac ,&obj.m_net_info.colocated_agent_id.mac,sizeof(mac_address_t));
    memcpy(&this->m_net_info.colocated_agent_id.name,&obj.m_net_info.colocated_agent_id.name,sizeof(em_interface_name_t));
}

int dm_network_t::init()
{
	char date_time[EM_DATE_TIME_BUFF_SZ];

	util::get_date_time_rfc3399(date_time, EM_DATE_TIME_BUFF_SZ);

	memset(&m_net_info, 0, sizeof(em_network_info_t)); 
	strncpy(m_net_info.timestamp, date_time, EM_DATE_TIME_BUFF_SZ);
	return 0;
}

dm_network_t::dm_network_t(em_network_info_t *net)
{
    memcpy(&m_net_info, net, sizeof(em_network_info_t));
}

dm_network_t::dm_network_t(const dm_network_t& net)
{
    memcpy(&m_net_info, &net.m_net_info, sizeof(em_network_info_t));
}

dm_network_t::dm_network_t()
{
    memset(&m_net_info, 0, sizeof(em_network_info_t));
}

dm_network_t::~dm_network_t()
{

}

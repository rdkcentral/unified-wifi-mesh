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
#include "dm_bss.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_bss_t::decode(const cJSON *obj, void *parent_id)
{
    cJSON *tmp, *tmp_arr;
    mac_addr_str_t  mac_str;
    unsigned int i;

    memset(&m_bss_info, 0, sizeof(em_bss_info_t));
    dm_easy_mesh_t::string_to_macbytes((char *)parent_id, m_bss_info.ruid.mac);

    if ((tmp = cJSON_GetObjectItem(obj, "BSSID")) != NULL) {
        snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
        dm_easy_mesh_t::string_to_macbytes(mac_str, m_bss_info.bssid.mac);
        dm_easy_mesh_t::name_from_mac_address(&m_bss_info.bssid.mac, m_bss_info.bssid.name);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "UnicastBytesSent")) != NULL) {
        m_bss_info.unicast_bytes_sent = tmp->valuedouble;
    }


    if ((tmp = cJSON_GetObjectItem(obj, "SSID")) != NULL) {
        snprintf(m_bss_info.ssid, sizeof(m_bss_info.ssid), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "Enabled")) != NULL) {
        m_bss_info.enabled = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "LastChange")) != NULL) {
        m_bss_info.last_change = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "TimeStamp")) != NULL) {    
        snprintf(m_bss_info.timestamp, sizeof(m_bss_info.timestamp), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "UnicastBytesReceived")) != NULL) {
        m_bss_info.unicast_bytes_rcvd = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "NumberOfSTA")) != NULL) {
        m_bss_info.numberofsta = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "EstServiceParametersBE")) != NULL) {
        snprintf(m_bss_info.est_svc_params_be, sizeof(m_bss_info.est_svc_params_be), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "EstServiceParametersBK")) != NULL) {
        snprintf(m_bss_info.est_svc_params_bk, sizeof(m_bss_info.est_svc_params_bk), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "EstServiceParametersVI")) != NULL) {
         snprintf(m_bss_info.est_svc_params_vi, sizeof(m_bss_info.est_svc_params_vi), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "EstServiceParametersVO")) != NULL) {
        snprintf(m_bss_info.est_svc_params_vo, sizeof(m_bss_info.est_svc_params_vo), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "ByteCounterUnits")) != NULL) {
        m_bss_info.byte_counter_units = tmp->valuedouble;
    }

    if ((tmp_arr = cJSON_GetObjectItem(obj, "FronthaulAKMsAllowed")) != NULL) {
        m_bss_info.num_fronthaul_akms = cJSON_GetArraySize(tmp_arr);
        for (i = 0; i < m_bss_info.num_fronthaul_akms; i++) {
            tmp = cJSON_GetArrayItem(tmp_arr, i);
            snprintf(m_bss_info.fronthaul_akm[i], sizeof(m_bss_info.fronthaul_akm[i]), "%s", cJSON_GetStringValue(tmp));
        }
    }

    if ((tmp_arr = cJSON_GetObjectItem(obj, "BackhaulAKMsAllowed")) != NULL) {
        m_bss_info.num_backhaul_akms = cJSON_GetArraySize(tmp_arr);
        for (i = 0; i < m_bss_info.num_backhaul_akms; i++) {
            tmp = cJSON_GetArrayItem(tmp_arr, i);
            snprintf(m_bss_info.backhaul_akm[i], sizeof(m_bss_info.backhaul_akm[i]), "%s", cJSON_GetStringValue(tmp));
        }
    }

    if ((tmp = cJSON_GetObjectItem(obj, "Profile1bSTAsDisallowed")) != NULL) {
        m_bss_info.profile_1b_sta_allowed = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "Profile2bSTAsDisallowed")) != NULL) {
        m_bss_info.profile_2b_sta_allowed = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "AssociationAllowanceStatus")) != NULL) {
        m_bss_info.assoc_allowed_status = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "FronthaulUse")) != NULL) {
        m_bss_info.fronthaul_use = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "BackhaulUse")) != NULL) {
        m_bss_info.backhaul_use = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "R1disallowed")) != NULL) {
        m_bss_info.r1_disallowed = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "R2disallowed")) != NULL) {
        m_bss_info.r2_disallowed = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "MultiBSSID")) != NULL) {
        m_bss_info.multi_bssid = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "TransmittedBSSID")) != NULL) {
        m_bss_info.transmitted_bssid = cJSON_IsTrue(tmp);
    }

    return 0;

}

void dm_bss_t::encode(cJSON *obj, bool summary)
{
    mac_addr_str_t  mac_str;
    unsigned short i;
	em_short_string_t	haul_type_str;

    dm_easy_mesh_t::macbytes_to_string(m_bss_info.bssid.mac, mac_str);
    cJSON_AddStringToObject(obj, "BSSID", mac_str);

	switch (m_bss_info.id.haul_type) {
		case em_haul_type_fronthaul:
			strncpy(haul_type_str, "Fronthaul", strlen("Fronthaul") + 1);
			break;

		case em_haul_type_backhaul:
			strncpy(haul_type_str, "Backhaul", strlen("Backhaul") + 1);
			break;

		case em_haul_type_iot:
			strncpy(haul_type_str, "IoT", strlen("IoT") + 1);
			break;

		case em_haul_type_configurator:
			strncpy(haul_type_str, "Configurator", strlen("Configurator") + 1);
			break;
		case em_haul_type_hotspot:
			strncpy(haul_type_str, "Hotspot", strlen("Hotspot") + 1);
			break;
	}

    cJSON_AddStringToObject(obj, "HaulType", haul_type_str);
    cJSON_AddStringToObject(obj, "SSID", m_bss_info.ssid);
    cJSON_AddBoolToObject(obj, "Enabled", m_bss_info.enabled);
    cJSON_AddStringToObject(obj, "TimeStamp", m_bss_info.timestamp);
    
	if (summary == true) {
        return;
    }

    cJSON_AddNumberToObject(obj, "LastChange", m_bss_info.last_change);
    cJSON_AddNumberToObject(obj, "UnicastBytesSent", m_bss_info.unicast_bytes_sent);
    cJSON_AddNumberToObject(obj, "UnicastBytesReceived", m_bss_info.unicast_bytes_rcvd);
    cJSON_AddNumberToObject(obj, "NumberOfSTA", m_bss_info.numberofsta );
    cJSON_AddStringToObject(obj, "EstServiceParametersBE", m_bss_info.est_svc_params_be);
    cJSON_AddStringToObject(obj, "EstServiceParametersBK", m_bss_info.est_svc_params_bk);
    cJSON_AddStringToObject(obj, "EstServiceParametersVI", m_bss_info.est_svc_params_vi);
    cJSON_AddStringToObject(obj, "EstServiceParametersVO", m_bss_info.est_svc_params_vo);
    cJSON_AddNumberToObject(obj, "ByteCounterUnits", m_bss_info.byte_counter_units);
    cJSON_AddBoolToObject(obj, "Profile1bSTAsDisallowed",  m_bss_info.profile_1b_sta_allowed);
    cJSON_AddBoolToObject(obj, "Profile2bSTAsDisallowed",  m_bss_info.profile_2b_sta_allowed);
    cJSON_AddNumberToObject(obj, "AssociationAllowanceStatus", m_bss_info.assoc_allowed_status);
    cJSON_AddBoolToObject(obj, "FronthaulUse", m_bss_info.fronthaul_use);
    cJSON_AddBoolToObject(obj, "BackhaulUse", m_bss_info.backhaul_use);
    cJSON_AddBoolToObject(obj, "R1disallowed", m_bss_info.r1_disallowed);
    cJSON_AddBoolToObject(obj, "R2disallowed", m_bss_info.r2_disallowed);
    cJSON_AddBoolToObject(obj, "MultiBSSID", m_bss_info.multi_bssid);
    cJSON_AddBoolToObject(obj, "TransmittedBSSID", m_bss_info.transmitted_bssid);

    cJSON *fronthaul_akmsArray = cJSON_CreateArray();
    for (i = 0; i < m_bss_info.num_fronthaul_akms; i++) {
        cJSON_AddItemToArray(fronthaul_akmsArray, cJSON_CreateString(m_bss_info.fronthaul_akm[i]));
    }
    // Add the array to the object
    cJSON_AddItemToObject(obj, "FronthaulAKMsAllowed", fronthaul_akmsArray);

    cJSON *backhaul_akmsArray = cJSON_CreateArray();
    for (i = 0; i < m_bss_info.num_backhaul_akms; i++) {
        cJSON_AddItemToArray(fronthaul_akmsArray, cJSON_CreateString(m_bss_info.backhaul_akm[i]));
    }

    // Add the array to the object
    cJSON_AddItemToObject(obj, "BackhaulAKMsAllowed", backhaul_akmsArray);

}

void dm_bss_t::operator = (const dm_bss_t& obj)
{
	if (this == &obj) { return; }
	strncpy(this->m_bss_info.id.net_id, obj.m_bss_info.id.net_id, strlen(obj.m_bss_info.id.net_id));
	memcpy(this->m_bss_info.id.dev_mac, obj.m_bss_info.id.dev_mac, sizeof(mac_address_t));
	memcpy(this->m_bss_info.id.ruid, obj.m_bss_info.id.ruid, sizeof(mac_address_t));
	memcpy(this->m_bss_info.id.bssid, obj.m_bss_info.id.bssid, sizeof(mac_address_t));

    memcpy(&this->m_bss_info.bssid.mac, &obj.m_bss_info.bssid.mac, sizeof(mac_address_t));
    memcpy(&this->m_bss_info.bssid.name, &obj.m_bss_info.bssid.name, sizeof(em_interface_name_t));
    memcpy(&this->m_bss_info.ruid.mac, &obj.m_bss_info.ruid.mac, sizeof(mac_address_t));
    memcpy(&this->m_bss_info.ruid.name, &obj.m_bss_info.ruid.name, sizeof(em_interface_name_t));
    memcpy(&this->m_bss_info.ssid,&obj.m_bss_info.ssid, sizeof(ssid_t));
    this->m_bss_info.enabled = obj.m_bss_info.enabled;
    memcpy(&this->m_bss_info.est_svc_params_be,&obj.m_bss_info.est_svc_params_be,sizeof(em_string_t));
    memcpy(&this->m_bss_info.est_svc_params_bk,&obj.m_bss_info.est_svc_params_bk,sizeof(em_string_t));
    memcpy(&this->m_bss_info.est_svc_params_vi,&obj.m_bss_info.est_svc_params_vi,sizeof(em_string_t));
    memcpy(&this->m_bss_info.est_svc_params_vo,&obj.m_bss_info.est_svc_params_vo,sizeof(em_string_t));
    this->m_bss_info.num_fronthaul_akms = obj.m_bss_info.num_fronthaul_akms;
    memcpy(&this->m_bss_info.fronthaul_akm,&obj.m_bss_info.fronthaul_akm,sizeof(em_string_t));
    this->m_bss_info.num_backhaul_akms = obj.m_bss_info.num_backhaul_akms;
    memcpy(&this->m_bss_info.backhaul_akm,&obj.m_bss_info.backhaul_akm,sizeof(em_string_t));
    this->m_bss_info.profile_1b_sta_allowed = obj.m_bss_info.profile_1b_sta_allowed;
    this->m_bss_info.profile_2b_sta_allowed = obj.m_bss_info.profile_2b_sta_allowed;
    this->m_bss_info.assoc_allowed_status = obj.m_bss_info.assoc_allowed_status;
    this->m_bss_info.backhaul_use = obj.m_bss_info.backhaul_use;
    this->m_bss_info.fronthaul_use = obj.m_bss_info.fronthaul_use;
    this->m_bss_info.r1_disallowed = obj.m_bss_info.r1_disallowed;
    this->m_bss_info.r2_disallowed = obj.m_bss_info.r2_disallowed;
    this->m_bss_info.multi_bssid = obj.m_bss_info.multi_bssid;
    this->m_bss_info.transmitted_bssid = obj.m_bss_info.transmitted_bssid;
}


bool dm_bss_t::operator == (const dm_bss_t& obj)
{
	int ret = 0;

	ret += (strncmp(this->m_bss_info.id.net_id, obj.m_bss_info.id.net_id, strlen(obj.m_bss_info.id.net_id)) != 0);
	ret += (memcmp(this->m_bss_info.id.dev_mac, obj.m_bss_info.id.dev_mac, sizeof(mac_address_t)) != 0);
	ret += (memcmp(this->m_bss_info.id.ruid, obj.m_bss_info.id.ruid, sizeof(mac_address_t)) != 0);
	ret += (memcmp(this->m_bss_info.id.bssid, obj.m_bss_info.id.bssid, sizeof(mac_address_t)) != 0);

    ret += (memcmp(&this->m_bss_info.bssid.mac ,&obj.m_bss_info.bssid.mac,sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_bss_info.bssid.name,&obj.m_bss_info.bssid.name,sizeof(em_interface_name_t)) != 0);
    ret += (memcmp(&this->m_bss_info.ruid.mac ,&obj.m_bss_info.ruid.mac,sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_bss_info.ruid.name,&obj.m_bss_info.ruid.name,sizeof(em_interface_name_t)) != 0);
    ret += (memcmp(&this->m_bss_info.ssid,&obj.m_bss_info.ssid,sizeof(ssid_t)) != 0);
    ret += !(this->m_bss_info.enabled == obj.m_bss_info.enabled);
    ret += (memcmp(&this->m_bss_info.est_svc_params_be,&obj.m_bss_info.est_svc_params_be,sizeof(em_string_t)) != 0);
    ret += (memcmp(&this->m_bss_info.est_svc_params_bk,&obj.m_bss_info.est_svc_params_bk,sizeof(em_string_t)) != 0);
    ret += (memcmp(&this->m_bss_info.est_svc_params_vi,&obj.m_bss_info.est_svc_params_vi,sizeof(em_string_t)) != 0);
    ret += (memcmp(&this->m_bss_info.est_svc_params_vo,&obj.m_bss_info.est_svc_params_vo,sizeof(em_string_t)) != 0);
    ret += !(this->m_bss_info.num_fronthaul_akms == obj.m_bss_info.num_fronthaul_akms);
    ret += (memcmp(&this->m_bss_info.fronthaul_akm,&obj.m_bss_info.fronthaul_akm,sizeof(em_string_t)) != 0);
    ret += !(this->m_bss_info.num_backhaul_akms == obj.m_bss_info.num_backhaul_akms);
    ret += (memcmp(&this->m_bss_info.backhaul_akm,&obj.m_bss_info.backhaul_akm,sizeof(em_string_t)) != 0);
    ret += !(this->m_bss_info.profile_1b_sta_allowed == obj.m_bss_info.profile_1b_sta_allowed);
    ret += !(this->m_bss_info.profile_2b_sta_allowed == obj.m_bss_info.profile_2b_sta_allowed);
    ret += !(this->m_bss_info.assoc_allowed_status == obj.m_bss_info.assoc_allowed_status);
    ret += !(this->m_bss_info.backhaul_use == obj.m_bss_info.backhaul_use);
    ret += !(this->m_bss_info.fronthaul_use == obj.m_bss_info.fronthaul_use);
    ret += !(this->m_bss_info.r1_disallowed == obj.m_bss_info.r1_disallowed);
    ret += !(this->m_bss_info.r2_disallowed == obj.m_bss_info.r2_disallowed);
    ret += !(this->m_bss_info.multi_bssid == obj.m_bss_info.multi_bssid);
    ret += !(this->m_bss_info.transmitted_bssid == obj.m_bss_info.transmitted_bssid);

    if (ret > 0)
        return false;
    else
        return true;
}

bool dm_bss_t::match_criteria(char *criteria)
{
	char *tmp;
	mac_address_t radio_mac;

	if ((tmp = strstr(criteria, "radio=")) != NULL) {
		tmp += strlen("radio=");
		dm_easy_mesh_t::string_to_macbytes(tmp, radio_mac);
		if (memcmp(m_bss_info.id.ruid, radio_mac, sizeof(mac_address_t)) == 0) {
			printf("%s:%d: Only deleting bss on radio: %s\n", __func__, __LINE__, tmp);
			return true;
		} else {
			return false;
		}
	}

	return true;	
}

int dm_bss_t::parse_bss_id_from_key(const char *key, em_bss_id_t *id)
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
			dm_easy_mesh_t::string_to_macbytes(remain, id->bssid);
            tmp++;
			id->haul_type = (em_haul_type_t)atoi(tmp);
        }
        i++;
    }
   

    return 0;
}

dm_bss_t::dm_bss_t(em_bss_info_t *bss)
{
    memcpy(&m_bss_info, bss, sizeof(em_bss_info_t));
}

dm_bss_t::dm_bss_t(const dm_bss_t& bss)
{
	memcpy(&m_bss_info, &bss.m_bss_info, sizeof(em_bss_info_t));
}

dm_bss_t::dm_bss_t()
{

}

dm_bss_t::~dm_bss_t()
{

}

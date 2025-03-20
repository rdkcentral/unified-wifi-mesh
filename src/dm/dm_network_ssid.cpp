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
#include "dm_network_ssid.h"
#include "dm_easy_mesh.h"

int dm_network_ssid_t::decode(const cJSON *obj, void *parent_id)
{
    cJSON *tmp, *tmp_arr;
    mac_addr_str_t  mac_str;
    int j;
    em_string_t haul_str;

    char *net_id = static_cast<char *> (parent_id);

    memset(&m_network_ssid_info, 0, sizeof(em_network_ssid_info_t));
    if ((tmp = cJSON_GetObjectItem(obj, "SSID")) != NULL) {
        snprintf(m_network_ssid_info.ssid, sizeof(m_network_ssid_info.ssid), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "PassPhrase")) != NULL) {
        snprintf(m_network_ssid_info.pass_phrase, sizeof(m_network_ssid_info.pass_phrase), "%s", cJSON_GetStringValue(tmp));
    }
		

    if ((tmp_arr = cJSON_GetObjectItem(obj, "Band")) != NULL) {
		m_network_ssid_info.num_bands = static_cast<unsigned char> (cJSON_GetArraySize(tmp_arr));
		for (j = 0; j < m_network_ssid_info.num_bands; j++) {	
			tmp = cJSON_GetArrayItem(tmp_arr, j);
		    snprintf(m_network_ssid_info.band[j], sizeof(m_network_ssid_info.band[j]), "%s", cJSON_GetStringValue(tmp));
        }
    }

    if ((tmp = cJSON_GetObjectItem(obj, "Enable")) != NULL) {
        m_network_ssid_info.enable = cJSON_IsTrue(tmp);
    }

    if ((tmp_arr = cJSON_GetObjectItem(obj, "AKMsAllowed")) != NULL) {
		m_network_ssid_info.num_akms = static_cast<unsigned char> (cJSON_GetArraySize(tmp_arr));
		for (j = 0; j < m_network_ssid_info.num_akms; j++) {	
			tmp = cJSON_GetArrayItem(tmp_arr, j);
		    snprintf(m_network_ssid_info.akm[j], sizeof(m_network_ssid_info.akm[j]), "%s", cJSON_GetStringValue(tmp));
        }
    }

    if ((tmp = cJSON_GetObjectItem(obj, "SuiteSelector")) != NULL) {
   	    snprintf(m_network_ssid_info.suite_select, sizeof(m_network_ssid_info.suite_select), "%s", cJSON_GetStringValue(tmp));
   	}

    if ((tmp = cJSON_GetObjectItem(obj, "AdvertisementEnabled")) != NULL) {
       m_network_ssid_info.advertisement = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "MFPConfig")) != NULL) {
        snprintf(m_network_ssid_info.mfp, sizeof(m_network_ssid_info.mfp), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "MobilityDomain")) != NULL) {
       snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
       dm_easy_mesh_t::string_to_macbytes(mac_str, m_network_ssid_info.mobility_domain);
    }

    if ((tmp_arr = cJSON_GetObjectItem(obj, "HaulType")) != NULL) {
        m_network_ssid_info.num_hauls = static_cast<unsigned char> (cJSON_GetArraySize(tmp_arr));
        for (j = 0; j < m_network_ssid_info.num_hauls; j++) {	
            tmp = cJSON_GetArrayItem(tmp_arr, j);
            m_network_ssid_info.haul_type[j] = dm_network_ssid_t::haul_type_from_string(cJSON_GetStringValue(tmp));
        }
        m_network_ssid_info.num_hauls = static_cast<unsigned char> (j);
    }
    snprintf(m_network_ssid_info.id, sizeof(em_long_string_t), "%s@%s", dm_network_ssid_t::haul_type_to_string(m_network_ssid_info.haul_type[0], haul_str), net_id);
    return 0;
}

void dm_network_ssid_t::encode(cJSON *obj)
{
  
    unsigned int i;
    mac_addr_str_t  mac_str;
    em_string_t	haul_str;

    cJSON_AddStringToObject(obj, "SSID", m_network_ssid_info.ssid);
    cJSON_AddStringToObject(obj, "PassPhrase", m_network_ssid_info.pass_phrase);

    cJSON *band_Array = cJSON_CreateArray();
    for (i = 0; i < m_network_ssid_info.num_bands; i++) {
        cJSON_AddItemToArray(band_Array, cJSON_CreateString(m_network_ssid_info.band[i]));
    }
    // Add the array to the object
    cJSON_AddItemToObject(obj, "Band", band_Array); 
	
    cJSON_AddBoolToObject(obj, "Enable", m_network_ssid_info.enable);

    cJSON *akms_Array = cJSON_CreateArray();
    for (i = 0; i < m_network_ssid_info.num_akms; i++) {
        cJSON_AddItemToArray(akms_Array, cJSON_CreateString(m_network_ssid_info.akm[i]));
    }
    // Add the array to the object
    cJSON_AddItemToObject(obj, "AKMsAllowed", akms_Array);
	
    cJSON_AddStringToObject(obj, "SuiteSelector", m_network_ssid_info.suite_select);
    cJSON_AddBoolToObject(obj, "AdvertisementEnabled", m_network_ssid_info.advertisement);
    cJSON_AddStringToObject(obj, "MFPConfig", m_network_ssid_info.mfp);
	
    dm_easy_mesh_t::macbytes_to_string(m_network_ssid_info.mobility_domain, mac_str);
    cJSON_AddStringToObject(obj, "MobilityDomain", mac_str);
	
    cJSON *haultype_Array = cJSON_CreateArray();
    for (i = 0; i < m_network_ssid_info.num_hauls; i++) {
        dm_network_ssid_t::haul_type_to_string(m_network_ssid_info.haul_type[i], haul_str);
        cJSON_AddItemToArray(haultype_Array, cJSON_CreateString(haul_str));
    }
    // Add the array to the object
    cJSON_AddItemToObject(obj, "HaulType", haultype_Array);
}

bool dm_network_ssid_t::operator == (const dm_network_ssid_t& obj)
{
    int ret = 0, i;
    ret += (memcmp(&this->m_network_ssid_info.id,&obj.m_network_ssid_info.id,sizeof(em_long_string_t)) != 0);
    ret += (memcmp(&this->m_network_ssid_info.ssid, &obj.m_network_ssid_info.ssid, sizeof(ssid_t)) != 0);
    ret += (memcmp(&this->m_network_ssid_info.pass_phrase, &obj.m_network_ssid_info.pass_phrase, sizeof(em_long_string_t)) != 0);
    ret += (this->m_network_ssid_info.num_bands != obj.m_network_ssid_info.num_bands);
    for (i = 0; i < this->m_network_ssid_info.num_bands; i++) {
    ret += (memcmp(&this->m_network_ssid_info.band[i], &obj.m_network_ssid_info.band[i], sizeof(em_short_string_t)) != 0);
    }
    ret += (this->m_network_ssid_info.enable != obj.m_network_ssid_info.enable);
    ret += (this->m_network_ssid_info.num_akms != obj.m_network_ssid_info.num_akms);
    for (i = 0; i < this->m_network_ssid_info.num_akms; i++) {
    ret += (memcmp(&this->m_network_ssid_info.akm[i], &obj.m_network_ssid_info.akm[i], sizeof(em_string_t)) != 0);
}
    ret += (memcmp(&this->m_network_ssid_info.suite_select, &obj.m_network_ssid_info.suite_select, sizeof(em_string_t)) != 0);
    ret += (this->m_network_ssid_info.advertisement != obj.m_network_ssid_info.advertisement);
    ret += (memcmp(&this->m_network_ssid_info.mfp, &obj.m_network_ssid_info.mfp, sizeof(em_string_t)) != 0);
    ret += (memcmp(&this->m_network_ssid_info.mobility_domain, &obj.m_network_ssid_info.mobility_domain, sizeof(mac_address_t)) != 0);
    ret += (this->m_network_ssid_info.num_hauls != obj.m_network_ssid_info.num_hauls);
    for (i = 0; i < this->m_network_ssid_info.num_hauls; i++) {
    ret += (this->m_network_ssid_info.haul_type[i] == obj.m_network_ssid_info.haul_type[i]);
}
    //em_util_info_print(EM_MGR, "%s:%d: MUH ret=%d\n", __func__, __LINE__,ret);

    if (ret > 0)
        return false;
    else
        return true;


}

void dm_network_ssid_t::operator = (const dm_network_ssid_t& obj)
{
    if (this == &obj) { return; }
    memcpy(&this->m_network_ssid_info.id ,&obj.m_network_ssid_info.id,sizeof(em_long_string_t));
    memcpy(&this->m_network_ssid_info.ssid, &obj.m_network_ssid_info.ssid, sizeof(ssid_t));
    memcpy(&this->m_network_ssid_info.pass_phrase, &obj.m_network_ssid_info.pass_phrase, sizeof(em_long_string_t));
    this->m_network_ssid_info.num_bands = obj.m_network_ssid_info.num_bands;
    for (int i = 0; i < this->m_network_ssid_info.num_bands; i++) {
       memcpy(&this->m_network_ssid_info.band[i], &obj.m_network_ssid_info.band[i], sizeof(em_tiny_string_t));
    }
    this->m_network_ssid_info.enable = obj.m_network_ssid_info.enable;
    this->m_network_ssid_info.num_akms = obj.m_network_ssid_info.num_akms;
    for (int i = 0; i < this->m_network_ssid_info.num_akms; i++) {
       memcpy(&this->m_network_ssid_info.akm[i], &obj.m_network_ssid_info.akm[i], sizeof(em_string_t));
    }
    memcpy(&this->m_network_ssid_info.suite_select, &obj.m_network_ssid_info.suite_select, sizeof(em_string_t));
    this->m_network_ssid_info.advertisement = obj.m_network_ssid_info.advertisement;
    memcpy(&this->m_network_ssid_info.mfp, &obj.m_network_ssid_info.mfp, sizeof(em_string_t));
    memcpy(&this->m_network_ssid_info.mobility_domain, &obj.m_network_ssid_info.mobility_domain, sizeof(mac_address_t));
    this->m_network_ssid_info.num_hauls = obj.m_network_ssid_info.num_hauls;
    for (int i = 0; i < this->m_network_ssid_info.num_hauls; i++) {
        this->m_network_ssid_info.haul_type[i] = obj.m_network_ssid_info.haul_type[i];
    }

}

char *dm_network_ssid_t::haul_type_to_string(em_haul_type_t type, em_string_t   str)
{
	switch (type) {
		case em_haul_type_fronthaul:
			strncpy(str, "Fronthaul", strlen("Fronthaul") + 1);
			break;

		case em_haul_type_backhaul:
			strncpy(str, "Backhaul", strlen("Backhaul") + 1);
			break;
		
		case em_haul_type_iot:
			strncpy(str, "IoT", strlen("IoT") + 1);
			break;

		case em_haul_type_configurator:
			strncpy(str, "Configurator", strlen("Configurator") + 1);
			break;

		case em_haul_type_hotspot:
			strncpy(str, "Hotspot", strlen("Hotspot") + 1);
			break;

		case em_haul_type_max:
			strncpy(str, "Unknown", strlen("Unknown") + 1);
			break;
	}

	return str;
}

em_haul_type_t dm_network_ssid_t::haul_type_from_string(em_string_t str)
{
    em_haul_type_t type;

    if (strncmp(str, "Fronthaul", strlen(str)) == 0) {
	type = em_haul_type_fronthaul;		
    } else if (strncmp(str, "Backhaul", strlen(str)) == 0) {
        type = em_haul_type_backhaul;
    } else if (strncmp(str, "IoT", strlen(str)) == 0) {
        type = em_haul_type_iot;
    } else if (strncmp(str, "Configurator", strlen(str)) == 0) {
        type = em_haul_type_configurator;
	} else if (strncmp(str, "Hotspot", strlen(str)) == 0) {
		type = em_haul_type_hotspot;
    } else {
        type = em_haul_type_max;
    }

    return type; 
}

dm_network_ssid_t::dm_network_ssid_t(em_network_ssid_info_t *net_ssid)
{
    memcpy(&m_network_ssid_info, net_ssid, sizeof(em_network_ssid_info_t));
}

dm_network_ssid_t::dm_network_ssid_t(const dm_network_ssid_t& net_ssid)
{
	memcpy(&m_network_ssid_info, &net_ssid.m_network_ssid_info, sizeof(em_network_ssid_info_t));
}

dm_network_ssid_t::dm_network_ssid_t()
{

}

dm_network_ssid_t::~dm_network_ssid_t()
{

}

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
#include "dm_ssid_2_vid_map.h"
#include "dm_easy_mesh.h"

int dm_ssid_2_vid_map_t::get_config(cJSON *obj_arr, void *parent_id, bool summary)
{
    return 0;
}

int dm_ssid_2_vid_map_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    em_ssid_2_vid_map_info_t info;
    cJSON *tmp, *obj, *map_arr;
    mac_address_t dev_mac;
    mac_addr_str_t  mac_str;
    int i, j, size;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {

        obj = cJSON_GetArrayItem(obj_arr, i);
	if ((tmp = cJSON_GetObjectItem(obj, "ID")) != NULL) {
            snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
            dm_easy_mesh_t::string_to_macbytes(mac_str, dev_mac);
        }

	if ((map_arr = cJSON_GetObjectItem(obj, "SSIDtoVIDMapping")) == NULL) {
	    assert(1);
	}

	for (j = 0; j < cJSON_GetArraySize(map_arr); j++) {

	    obj = cJSON_GetArrayItem(map_arr, j);

    	    memset(&info, 0, sizeof(em_ssid_2_vid_map_info_t));
		
    	    if ((tmp = cJSON_GetObjectItem(obj, "SSID")) != NULL) {
    	        snprintf(info.ssid, sizeof(info.ssid), "%s", cJSON_GetStringValue(tmp));
            }
			
	    snprintf(info.id, sizeof(em_long_string_t), "%s@%s", info.ssid, mac_str);

    	    if ((tmp = cJSON_GetObjectItem(obj, "VID")) != NULL) {
                info.vid = static_cast<short unsigned int>(tmp->valuedouble);
    	    }

	    update_db(db_client, update_list(dm_ssid_2_vid_map_t(&info)), &info);

	}
    }


    return 0;
}


dm_orch_type_t dm_ssid_2_vid_map_t::update_list(const dm_ssid_2_vid_map_t& ssid_2_vid_map)
{
    dm_ssid_2_vid_map_t *pssid_2_vid_map;
    bool found = false;

    pssid_2_vid_map = static_cast<dm_ssid_2_vid_map_t *>(hash_map_get_first(m_list));
    while (pssid_2_vid_map != NULL) {
	if (strncmp(ssid_2_vid_map.m_ssid_2_vid_map_info.id, pssid_2_vid_map->m_ssid_2_vid_map_info.id, strlen(ssid_2_vid_map.m_ssid_2_vid_map_info.id)) == 0) {
	    found = true;
	    break;
	}	
	pssid_2_vid_map = static_cast<dm_ssid_2_vid_map_t *>(hash_map_get_next(m_list, pssid_2_vid_map));
    }

    if (found == true) {
        if (*pssid_2_vid_map == ssid_2_vid_map) {
            printf("%s:%d: Network SSID: %s already in list\n", __func__, __LINE__, pssid_2_vid_map->m_ssid_2_vid_map_info.id);
	    return dm_orch_type_none;
	}
		
        	
	printf("%s:%d: Network SSID: %s in list but needs update\n", __func__, __LINE__, pssid_2_vid_map->m_ssid_2_vid_map_info.id);
	return dm_orch_type_db_update;
    }	

    hash_map_put(m_list, strdup(ssid_2_vid_map.m_ssid_2_vid_map_info.id), new dm_ssid_2_vid_map_t(ssid_2_vid_map));	

		
    return dm_orch_type_db_insert;
}

bool dm_ssid_2_vid_map_t::operator == (const db_easy_mesh_t& obj)
{
    dm_ssid_2_vid_map_t *pssid_2_vid_map = const_cast<dm_ssid_2_vid_map_t *>(reinterpret_cast<const dm_ssid_2_vid_map_t *>(&obj));

    if (strncmp(m_ssid_2_vid_map_info.id, pssid_2_vid_map->m_ssid_2_vid_map_info.id, strlen(pssid_2_vid_map->m_ssid_2_vid_map_info.id)) != 0) {
	printf("%s:%d: id is different\n", __func__, __LINE__);
	return false;
    }

    if (strncmp(m_ssid_2_vid_map_info.ssid, pssid_2_vid_map->m_ssid_2_vid_map_info.ssid, strlen(pssid_2_vid_map->m_ssid_2_vid_map_info.ssid)) != 0) {
        printf("%s:%d: ssid is different\n", __func__, __LINE__);
	return false;
    }

    if (m_ssid_2_vid_map_info.vid != pssid_2_vid_map->m_ssid_2_vid_map_info.vid) {
	printf("%s:%d: vids are different\n", __func__, __LINE__);
	return false;
    }

    return true;
}

int dm_ssid_2_vid_map_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    em_ssid_2_vid_map_info_t *info = static_cast<em_ssid_2_vid_map_info_t *>(data);
    int ret = 0;

    //printf("%s:%d: Opeartion:%d\n", __func__, __LINE__, op);
	
	switch (op) {
		case dm_orch_type_db_insert:
			ret = insert_row(db_client, info->id, info->ssid, info->vid);
			break;

		case dm_orch_type_db_update:
			ret = update_row(db_client, info->ssid, info->vid, info->id);
			break;

		case dm_orch_type_db_delete:
			ret = delete_row(db_client, info->id);
			break;

		default:
			break;
	}

    return ret;
}

bool dm_ssid_2_vid_map_t::search_db(db_client_t& db_client, void *ctx, void *key)
{
    return false;
}

int dm_ssid_2_vid_map_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_ssid_2_vid_map_info_t info;
    int rc = 0;

    while (db_client.next_result(ctx)) {
	memset(&info, 0, sizeof(em_ssid_2_vid_map_info_t));

	db_client.get_string(ctx, info.id, 1);
	db_client.get_string(ctx, info.ssid, 2);
        info.vid = static_cast<short unsigned int>(db_client.get_number(ctx, 3));
        
	update_list(dm_ssid_2_vid_map_t(&info));
    }
    return rc;
}

void dm_ssid_2_vid_map_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "SSIDtoVIDMapping");
}

void dm_ssid_2_vid_map_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("SSID", db_data_type_char, 32);
    m_columns[m_num_cols++] = db_column_t("VID", db_data_type_mediumint, 0);
}

int dm_ssid_2_vid_map_t::init()
{
	m_list = hash_map_create();
    init_table();
    init_columns();
    return 0;
}

dm_ssid_2_vid_map_t::dm_ssid_2_vid_map_t(em_ssid_2_vid_map_info_t *ssid_2_vid_map)
{
    memcpy(&m_ssid_2_vid_map_info, ssid_2_vid_map, sizeof(em_ssid_2_vid_map_info_t));
}

dm_ssid_2_vid_map_t::dm_ssid_2_vid_map_t(const dm_ssid_2_vid_map_t& ssid_2_vid_map)
{
    memcpy(&m_ssid_2_vid_map_info, &ssid_2_vid_map.m_ssid_2_vid_map_info, sizeof(em_ssid_2_vid_map_info_t));
}

dm_ssid_2_vid_map_t::dm_ssid_2_vid_map_t()
{

}

dm_ssid_2_vid_map_t::~dm_ssid_2_vid_map_t()
{

}

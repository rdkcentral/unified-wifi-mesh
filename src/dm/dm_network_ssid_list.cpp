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
#include "dm_network_ssid_list.h"
#include "dm_easy_mesh.h"
#include "em_cmd.h"

int dm_network_ssid_list_t::get_config(cJSON *obj_arr, void *parent_id, bool summary)
{
	dm_network_ssid_t *pnet_ssid;
    em_network_ssid_info_t *info;
	cJSON *obj, *band_arr, *akms_arr, *hauls_arr;
	mac_addr_str_t	mac_str;
	unsigned int i;
    em_string_t	haul_str;
    char *tmp = NULL, *net_id = static_cast<char *> (parent_id);

	pnet_ssid = get_first_network_ssid();
	while (pnet_ssid != NULL) {
        info = pnet_ssid->get_network_ssid_info();
		if ((tmp = strchr(info->id, '@')) == NULL) {
			pnet_ssid = get_next_network_ssid(pnet_ssid);
			continue;
		}

		if ((strncmp(tmp + 1, net_id, strlen(net_id))) != 0) {
			pnet_ssid = get_next_network_ssid(pnet_ssid);
			continue;
		}

		obj = cJSON_CreateObject();

		cJSON_AddStringToObject(obj, "SSID", pnet_ssid->m_network_ssid_info.ssid);
		cJSON_AddStringToObject(obj, "PassPhrase", pnet_ssid->m_network_ssid_info.pass_phrase);

		band_arr = cJSON_AddArrayToObject(obj, "Band");
		for (i = 0; i < pnet_ssid->m_network_ssid_info.num_bands; i++) {
			cJSON_AddItemToArray(band_arr, cJSON_CreateString(pnet_ssid->m_network_ssid_info.band[i]));
		}

		cJSON_AddBoolToObject(obj, "Enable", pnet_ssid->m_network_ssid_info.enable);
	
		akms_arr = cJSON_AddArrayToObject(obj, "AKMsAllowed");
		for (i = 0; i < pnet_ssid->m_network_ssid_info.num_akms; i++) {
			cJSON_AddItemToArray(akms_arr, cJSON_CreateString(pnet_ssid->m_network_ssid_info.akm[i]));
		}

		cJSON_AddStringToObject(obj, "SuiteSelector", pnet_ssid->m_network_ssid_info.suite_select);
		cJSON_AddBoolToObject(obj, "AdvertisementEnabled", pnet_ssid->m_network_ssid_info.advertisement);
		cJSON_AddStringToObject(obj, "MFPConfig", pnet_ssid->m_network_ssid_info.mfp);

		dm_easy_mesh_t::macbytes_to_string(pnet_ssid->m_network_ssid_info.mobility_domain, mac_str);
		cJSON_AddStringToObject(obj, "MobilityDomain", mac_str);
		
		hauls_arr = cJSON_AddArrayToObject(obj, "HaulType");
		for (i = 0; i < pnet_ssid->m_network_ssid_info.num_hauls; i++) {
            haul_type_to_string(pnet_ssid->m_network_ssid_info.haul_type[i], haul_str);
            cJSON_AddItemToArray(hauls_arr, cJSON_CreateString(haul_str));
		}


		cJSON_AddItemToArray(obj_arr, obj);		
		pnet_ssid = get_next_network_ssid(pnet_ssid);
	}

	
	return 0;
}

int dm_network_ssid_list_t::analyze_config(const cJSON *obj_arr, void *parent_id, em_cmd_t *pcmd[], em_cmd_params_t *param)
{
    int num = 0;

	return num;
}

int dm_network_ssid_list_t::set_config(db_client_t& db_client, dm_network_ssid_t& net_ssid, void *parent_id)
{
    dm_orch_type_t op;
    
    //printf("%s:%d: Enter: Network SSID: %s\n", __func__, __LINE__, (char *)parent_id);
    
    update_db(db_client, (op = get_dm_orch_type(net_ssid)), net_ssid.get_network_ssid_info());
    update_list(net_ssid, op);
    //printf("%s:%d: Exit: Network SSID: %s\n", __func__, __LINE__, (char *)parent_id);
    return 0;
}


int dm_network_ssid_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    cJSON *obj;
    int i, size;
	dm_network_ssid_t network_ssid;
	dm_orch_type_t op;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
		network_ssid.decode(obj, parent_id);
		update_db(db_client, (op = get_dm_orch_type(network_ssid)), network_ssid.get_network_ssid_info());
		update_list(network_ssid, op);
    }

    return 0;
}

dm_orch_type_t dm_network_ssid_list_t::get_dm_orch_type(const dm_network_ssid_t& net_ssid)
{
    dm_network_ssid_t *pnet_ssid;

    pnet_ssid = get_network_ssid(net_ssid.m_network_ssid_info.id);

    if (pnet_ssid != NULL) {
        if (*pnet_ssid == net_ssid) {
            printf("%s:%d: Network SSID: %s already in list\n", __func__, __LINE__, pnet_ssid->m_network_ssid_info.id);
            return dm_orch_type_none;
        }


        printf("%s:%d: Network SSID: %s in list but needs update\n", __func__, __LINE__, pnet_ssid->m_network_ssid_info.id);
        return dm_orch_type_db_update;
    }  

    return dm_orch_type_db_insert;
}


void dm_network_ssid_list_t::update_list(const dm_network_ssid_t& net_ssid, dm_orch_type_t op)
{
	dm_network_ssid_t *pnet_ssid;

	switch (op) {
		case dm_orch_type_db_insert:
            put_network_ssid(net_ssid.m_network_ssid_info.id, &net_ssid);
            break;

		case dm_orch_type_db_update:
            pnet_ssid = get_network_ssid(net_ssid.m_network_ssid_info.id);
            memcpy(&pnet_ssid->m_network_ssid_info, &net_ssid.m_network_ssid_info, sizeof(em_network_ssid_info_t));
			break;
		
		case dm_orch_type_db_delete:
            remove_network_ssid(net_ssid.m_network_ssid_info.id);
            break;

        default:
            break;
	}
}

void dm_network_ssid_list_t::delete_list()
{       
    dm_network_ssid_t *pnetssid, *tmp;
    
    pnetssid = get_first_network_ssid();
    while (pnetssid != NULL) {
        tmp = pnetssid;
        pnetssid = get_next_network_ssid(pnetssid);
        remove_network_ssid(tmp->m_network_ssid_info.id);
    }
}   


bool dm_network_ssid_list_t::operator == (const db_easy_mesh_t& obj)
{
	dm_network_ssid_t *pnet_ssid = const_cast<dm_network_ssid_t*>(reinterpret_cast<const dm_network_ssid_t*>(&obj));
	unsigned int i, j;
	bool matched = false;

	if (strncmp(m_network_ssid_info.id, pnet_ssid->m_network_ssid_info.id, strlen(m_network_ssid_info.id)) != 0) {
		printf("%s:%d: id is different src:%s dst:%s\n", __func__, __LINE__, m_network_ssid_info.id, pnet_ssid->m_network_ssid_info.id);
		return false;
	}

	if (strncmp(m_network_ssid_info.ssid, pnet_ssid->m_network_ssid_info.ssid, strlen(m_network_ssid_info.ssid)) != 0) {
		printf("%s:%d: ssid is different\n", __func__, __LINE__);
		return false;
	}

	if (strncmp(m_network_ssid_info.pass_phrase, pnet_ssid->m_network_ssid_info.pass_phrase, strlen(m_network_ssid_info.pass_phrase)) != 0) {
		printf("%s:%d: pass_phrase is different\n", __func__, __LINE__);
		return false;
	}

	if (m_network_ssid_info.num_bands != pnet_ssid->m_network_ssid_info.num_bands) {
		printf("%s:%d: number of bands are different\n", __func__, __LINE__);
		return false;
	}

	for (i = 0; i < m_network_ssid_info.num_bands; i++) {
		matched = false;
		for (j = 0; j < pnet_ssid->m_network_ssid_info.num_bands; j++) {
			//printf("%s:%d: Src Band: %s Dst Band: %s\n", __func__, __LINE__, 
			//			m_network_ssid_info.band[i], pnet_ssid->m_network_ssid_info.band[j]);
			if (strncmp(m_network_ssid_info.band[i], pnet_ssid->m_network_ssid_info.band[j], strlen(m_network_ssid_info.band[i])) == 0) {
				matched = true;
				break;
			}
		}
	}

	if (matched == false) {
		printf("%s:%d: bands are different\n", __func__, __LINE__);
		return false;
	}

	if (m_network_ssid_info.enable != pnet_ssid->m_network_ssid_info.enable) {
		printf("%s:%d: number of bands are different\n", __func__, __LINE__);
		return false;
	}

	if (m_network_ssid_info.num_akms != pnet_ssid->m_network_ssid_info.num_akms) {
		printf("%s:%d: number of akms are different\n", __func__, __LINE__);
		return false;
	}

	for (i = 0; i < m_network_ssid_info.num_akms; i++) {
		matched = false;
		for (j = 0; j < pnet_ssid->m_network_ssid_info.num_akms; j++) {
			if (strncmp(m_network_ssid_info.akm[i], pnet_ssid->m_network_ssid_info.akm[j], strlen(m_network_ssid_info.akm[i])) == 0) {
				matched = true;
				break;
			}
		}
	}

	if (matched == false) {
		printf("%s:%d: akms are different\n", __func__, __LINE__);
		return false;
	}

	if (strncmp(m_network_ssid_info.suite_select, pnet_ssid->m_network_ssid_info.suite_select, strlen(m_network_ssid_info.suite_select)) != 0) {
		printf("%s:%d: suite select is different\n", __func__, __LINE__);
		return false;
	}

	if (m_network_ssid_info.advertisement != pnet_ssid->m_network_ssid_info.advertisement) {
		printf("%s:%d: advertisements are different\n", __func__, __LINE__);
		return false;
	}

	if (strncmp(m_network_ssid_info.mfp, pnet_ssid->m_network_ssid_info.mfp, strlen(m_network_ssid_info.mfp)) != 0) {
		printf("%s:%d: mfps different\n", __func__, __LINE__);
		return false;
	}

	if (memcmp(m_network_ssid_info.mobility_domain, pnet_ssid->m_network_ssid_info.mobility_domain, sizeof(mac_address_t)) != 0) {
		printf("%s:%d: mobility domains are different\n", __func__, __LINE__);
		return false;
	}

	if (m_network_ssid_info.num_hauls != pnet_ssid->m_network_ssid_info.num_hauls) {
		printf("%s:%d: number of haul types are different\n", __func__, __LINE__);
		return false;
	}

	for (i = 0; i < m_network_ssid_info.num_hauls; i++) {
		matched = false;
		for (j = 0; j < pnet_ssid->m_network_ssid_info.num_hauls; j++) {
			if (m_network_ssid_info.haul_type[i] == pnet_ssid->m_network_ssid_info.haul_type[j]) {
				matched = true;
				break;
			}
		}
	}

	if (matched == false) {
		printf("%s:%d: haul types are different\n", __func__, __LINE__);
		return false;
	}

	return true;
}

int dm_network_ssid_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t mac_str;
    em_network_ssid_info_t *info = static_cast<em_network_ssid_info_t *> (data);
	int ret = 0;
	em_long_string_t	bands, hauls, akms;
    em_string_t	haul_str;
	unsigned int i;

	//printf("%s:%d: Opeartion:%d\n", __func__, __LINE__, op);
	
	memset(bands, 0, sizeof(em_long_string_t));
	for (i = 0; i < info->num_bands; i++) {
		snprintf(bands + strlen(bands), sizeof(bands) - strlen(bands), "%s", info->band[i]);
        snprintf(bands + strlen(bands), sizeof(bands) - strlen(bands), "%s", ",");
	}
	bands[strlen(bands) - 1] = 0;
	//printf("%s:%d: Bands: %s\n", __func__, __LINE__, bands);

	memset(hauls, 0, sizeof(em_long_string_t));
    for (i = 0; i < info->num_hauls; i++) {
        dm_network_ssid_t::haul_type_to_string(info->haul_type[i], haul_str);
		snprintf(hauls + strlen(hauls), sizeof(hauls) - strlen(hauls) - 1, "%s,", haul_str);
    }
    hauls[strlen(hauls) - 1] = 0;
    //printf("%s:%d: Haul Types: %s\n", __func__, __LINE__, bands);

	memset(akms, 0, sizeof(em_long_string_t));
    for (i = 0; i < info->num_akms; i++) {
        snprintf(akms + strlen(akms), sizeof(akms) - strlen(akms), "%s", info->akm[i]);
        snprintf(akms + strlen(akms), sizeof(akms) - strlen(akms), "%s", ",");
    }
    akms[strlen(akms) - 1] = 0;
    //printf("%s:%d: AKMs: %s\n", __func__, __LINE__, akms);

	switch (op) {
		case dm_orch_type_db_insert:
			ret = insert_row(db_client, info->id, info->ssid, info->pass_phrase, bands, info->enable, akms, info->suite_select,
						info->advertisement, info->mfp, dm_easy_mesh_t::macbytes_to_string(info->mobility_domain, mac_str), hauls);
			break;

		case dm_orch_type_db_update:
			ret = update_row(db_client, info->ssid, info->pass_phrase, bands, info->enable, akms, info->suite_select, info->advertisement, info->mfp, dm_easy_mesh_t::macbytes_to_string(info->mobility_domain, mac_str), hauls, info->id);
			break;

		case dm_orch_type_db_delete:
			ret = delete_row(db_client, info->id);
			break;

		default:
			break;
	}

    return ret;
}

bool dm_network_ssid_list_t::search_db(db_client_t& db_client, void *ctx, void *key)
{
    em_long_string_t id;

    while (db_client.next_result(ctx)) {
        db_client.get_string(ctx, id, 1);

        if (strncmp(id, static_cast<char *> (key), strlen(static_cast<char *> (key))) == 0) {
            return true;
        }
    }

    return false;
}

int dm_network_ssid_list_t::sync_db(db_client_t& db_client, void *ctx)
{
	em_network_ssid_info_t info;
	mac_addr_str_t	mac;
    em_long_string_t   str;
    char   *token_parts[10];
    em_string_t haul_type[10];
	unsigned int i;
    int rc = 0;

    while (db_client.next_result(ctx)) {
		memset(&info, 0, sizeof(em_network_ssid_info_t));

		db_client.get_string(ctx, info.id, 1);
		db_client.get_string(ctx, info.ssid, 2);
        db_client.get_string(ctx, info.pass_phrase, 3);
		db_client.get_string(ctx, str, 4);
		for (i = 0; i < EM_MAX_BANDS; i++) {
			token_parts[i] = info.band[i];
		}
		info.num_bands = static_cast<unsigned char> (get_strings_by_token(str, ',', EM_MAX_BANDS, token_parts));
		for (i = 0; i < info.num_bands; i++) {
			//printf("%s:%d: Band[%d]: %s\n", __func__, __LINE__, i, info.band[i]);
		}

        info.enable = db_client.get_number(ctx, 5);

		db_client.get_string(ctx, str, 6);
		for (i = 0; i < EM_MAX_AKMS; i++) {
			token_parts[i] = info.akm[i];
		}
		info.num_akms = static_cast<unsigned char> (get_strings_by_token(str, ',', EM_MAX_AKMS, token_parts));
		for (i = 0; i < info.num_akms; i++) {
			//printf("%s:%d: akm[%d]: %s\n", __func__, __LINE__, i, info.akm[i]);
		}


		db_client.get_string(ctx, info.suite_select, 7);
		info.advertisement = db_client.get_number(ctx, 8);
		db_client.get_string(ctx, info.mfp, 9);

		db_client.get_string(ctx, mac, 10);
		dm_easy_mesh_t::string_to_macbytes(mac, info.mobility_domain);

		db_client.get_string(ctx, str, 11);
		for (i = 0; i < EM_MAX_HAUL_TYPES; i++) {
			token_parts[i] = haul_type[i];
		}
		info.num_hauls = static_cast<unsigned char> (get_strings_by_token(str, ',', EM_MAX_HAUL_TYPES, token_parts));
		for (i = 0; i < info.num_hauls; i++) {
            info.haul_type[i] = dm_network_ssid_t::haul_type_from_string(haul_type[i]);
			//printf("%s:%d: Haul Type[%d]: %s\n", __func__, __LINE__, i, info.haul_type[i]);
		}

        
		update_list(dm_network_ssid_t(&info), dm_orch_type_db_insert);
    }
    return rc;
}

void dm_network_ssid_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "NetworkSSIDList");
}

void dm_network_ssid_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("SSID", db_data_type_char, 32);
    m_columns[m_num_cols++] = db_column_t("PassPhrase", db_data_type_char, 32);
    m_columns[m_num_cols++] = db_column_t("Band", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("Enable", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("AKMsAllowed", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("SuiteSelector", db_data_type_char, 16);
    m_columns[m_num_cols++] = db_column_t("AdvertisementEnabled", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("MFPConfig", db_data_type_char, 16);
    m_columns[m_num_cols++] = db_column_t("MobilityDomain", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("HaulType", db_data_type_char, 64);
}

int dm_network_ssid_list_t::init()
{
    init_table();
    init_columns();
    return 0;
}

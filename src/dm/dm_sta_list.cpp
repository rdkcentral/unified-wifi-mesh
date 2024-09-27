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
#include "dm_sta_list.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_sta_list_t::get_config(cJSON *obj_arr, void *parent)
{
	dm_sta_t *psta;
	cJSON *obj, *akms_arr;
	mac_addr_str_t  mac_str;
	unsigned int i;
	
	psta = (dm_sta_t *)hash_map_get_first(m_list);
    while (psta != NULL) {
       	obj = cJSON_CreateObject(); 

		dm_easy_mesh_t::macbytes_to_string(psta->m_sta_info.id, mac_str);
		cJSON_AddStringToObject(obj, "MACAddress", mac_str);
		cJSON_AddNumberToObject(obj, "LastDataUplinkRate", psta->m_sta_info.last_ul_rate);
		cJSON_AddNumberToObject(obj, "LastDataDownlinkRate", psta->m_sta_info.last_dl_rate);
		cJSON_AddNumberToObject(obj, "EstMACDataRateUplink", psta->m_sta_info.est_ul_rate);
		cJSON_AddNumberToObject(obj, "EstMACDataRateDownlink", psta->m_sta_info.est_dl_rate);
		cJSON_AddNumberToObject(obj, "LastConnectTime", psta->m_sta_info.last_conn_time);
		cJSON_AddNumberToObject(obj, "RetransCount", psta->m_sta_info.retrans_count);
		cJSON_AddNumberToObject(obj, "SignalStrength", psta->m_sta_info.signal_strength);
		cJSON_AddNumberToObject(obj, "UtilizationTransmit", psta->m_sta_info.util_tx);
		cJSON_AddNumberToObject(obj, "UtilizationReceive", psta->m_sta_info.util_rx);
		cJSON_AddNumberToObject(obj, "PacketsSent", psta->m_sta_info.pkts_tx);
		cJSON_AddNumberToObject(obj, "PacketsReceived", psta->m_sta_info.pkts_rx);
		cJSON_AddNumberToObject(obj, "BytesSent", psta->m_sta_info.bytes_tx);
		cJSON_AddNumberToObject(obj, "BytesReceived", psta->m_sta_info.bytes_rx);
		cJSON_AddNumberToObject(obj, "ErrorsSent", psta->m_sta_info.errors_tx);
		cJSON_AddNumberToObject(obj, "ErrorsReceived", psta->m_sta_info.errors_rx);
		cJSON_AddStringToObject(obj, "ClientCapabilities", psta->m_sta_info.cap);
		cJSON_AddStringToObject(obj, "HTCapabilities", psta->m_sta_info.ht_cap);
		cJSON_AddStringToObject(obj, "VHTCapabilities", psta->m_sta_info.vht_cap);
		cJSON_AddStringToObject(obj, "HECapabilities", psta->m_sta_info.he_cap);

		cJSON_AddItemToArray(obj_arr, obj);
		psta = (dm_sta_t *)hash_map_get_next(m_list, psta);
    }
    
	
	return 0;
}

int dm_sta_list_t::analyze_config(const cJSON *obj_arr, void *parent_id, em_cmd_t *pcmd[], em_cmd_params_t *param)
{
	printf("%s:%d: Enter\n", __func__, __LINE__);

	return 0;
}

int dm_sta_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    cJSON *obj;
    unsigned int i, size;
	dm_sta_t sta;
	dm_orch_type_t op;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
		sta.decode(obj, parent_id);
		update_db(db_client, (op = get_dm_orch_type(sta)), sta.get_sta_info());
		update_list(sta, op);
    }

    return 0;
}

dm_orch_type_t dm_sta_list_t::get_dm_orch_type(const dm_sta_t& sta)
{
    dm_sta_t *psta;
    mac_addr_str_t  sta_mac_str, bssid_mac_str;
    em_long_string_t key;

    dm_easy_mesh_t::macbytes_to_string((unsigned char *)sta.m_sta_info.id, sta_mac_str);
    dm_easy_mesh_t::macbytes_to_string((unsigned char *)sta.m_sta_info.bssid, bssid_mac_str);
    snprintf(key, sizeof (em_long_string_t), "%s-%s", sta_mac_str, bssid_mac_str);

	psta = (dm_sta_t *)hash_map_get(m_list, key);

    if (psta != NULL) {
        if (*psta == sta) {
            printf("%s:%d: STA: %s BSS: %s already in list\n", __func__, __LINE__, 
                        dm_easy_mesh_t::macbytes_to_string(psta->m_sta_info.id, sta_mac_str),
                        dm_easy_mesh_t::macbytes_to_string(psta->m_sta_info.bssid, bssid_mac_str));
            return dm_orch_type_none;
        }


        printf("%s:%d: STA: %s BSS: %s in list but needs update\n", __func__, __LINE__,
                        dm_easy_mesh_t::macbytes_to_string(psta->m_sta_info.id, sta_mac_str),
                        dm_easy_mesh_t::macbytes_to_string(psta->m_sta_info.bssid, bssid_mac_str));
        return dm_orch_type_sta_update;
    }


    return dm_orch_type_sta_insert;
}


void dm_sta_list_t::update_list(const dm_sta_t& sta, dm_orch_type_t op)
{
	dm_sta_t *psta;
	mac_addr_str_t	sta_mac_str, bssid_mac_str;
	em_long_string_t key;

   	dm_easy_mesh_t::macbytes_to_string((unsigned char *)sta.m_sta_info.id, sta_mac_str);
    dm_easy_mesh_t::macbytes_to_string((unsigned char *)sta.m_sta_info.bssid, bssid_mac_str);
    snprintf(key, sizeof (em_long_string_t), "%s-%s", sta_mac_str, bssid_mac_str);

    switch (op) {
        case dm_orch_type_sta_insert:
			hash_map_put(m_list, strdup(key), new dm_sta_t(sta));	
            break;

        case dm_orch_type_sta_update:
			psta = (dm_sta_t *)hash_map_get(m_list, key);
            memcpy(&psta->m_sta_info, &sta.m_sta_info, sizeof(em_sta_info_t));
            break;

        case dm_orch_type_sta_delete:
			psta = (dm_sta_t *)hash_map_remove(m_list, key);
            delete(psta);
            break;
    }

}

void dm_sta_list_t::delete_list()
{       
    dm_sta_t *psta, *tmp;
	mac_addr_str_t	sta_mac_str, bssid_mac_str;
	em_long_string_t key;
    
    psta = (dm_sta_t *)hash_map_get_first(m_list);
    while (psta != NULL) {
        tmp = psta;
        psta = (dm_sta_t *)hash_map_get_next(m_list, psta);       
    
   		dm_easy_mesh_t::macbytes_to_string((unsigned char *)tmp->m_sta_info.id, sta_mac_str);
    	dm_easy_mesh_t::macbytes_to_string((unsigned char *)tmp->m_sta_info.bssid, bssid_mac_str);
    	snprintf(key, sizeof (em_long_string_t), "%s-%s", sta_mac_str, bssid_mac_str);
        hash_map_remove(m_list, key);
        delete(tmp);
    }
}   


bool dm_sta_list_t::operator == (const db_easy_mesh_t& obj)
{
	return true;
}

int dm_sta_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t sta_mac_str, bssid_mac_str;
    em_sta_info_t *info = (em_sta_info_t *)data;
	int ret = 0;

	switch (op) {
		case dm_orch_type_sta_insert:
			ret = insert_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->id, sta_mac_str),
						dm_easy_mesh_t::macbytes_to_string(info->bssid, bssid_mac_str), info->last_ul_rate, info->last_dl_rate,
						info->est_ul_rate, info->est_dl_rate, info->last_conn_time, info->retrans_count,
						info->signal_strength, info->util_tx, info->util_rx, info->pkts_tx, info->pkts_rx,
						info->bytes_tx, info->bytes_rx, info->errors_tx, info->errors_rx, info->cap, 
						info->ht_cap, info->vht_cap, info->he_cap);
							
			break;

		case dm_orch_type_sta_update:
			ret = update_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->bssid, bssid_mac_str), 
						info->last_ul_rate, info->last_dl_rate,
						info->est_ul_rate, info->est_dl_rate, info->last_conn_time, info->retrans_count,
						info->signal_strength, info->util_tx, info->util_rx, info->pkts_tx, info->pkts_rx,
						info->bytes_tx, info->bytes_rx, info->errors_tx, info->errors_rx, info->cap, 
						info->ht_cap, info->vht_cap, info->he_cap,
						dm_easy_mesh_t::macbytes_to_string(info->id, sta_mac_str));
			break;

		case dm_orch_type_sta_delete:
			ret = delete_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->id, sta_mac_str));
			break;

		default:
			break;
	}

    return ret;
}

void dm_sta_list_t::sync_db(db_client_t& db_client, void *ctx)
{
	em_sta_info_t info;
	mac_addr_str_t	mac;
    em_long_string_t   str;
	unsigned int i;

    while (db_client.next_result(ctx)) {
		memset(&info, 0, sizeof(em_sta_info_t));

		db_client.get_string(ctx, mac, 1);
		dm_easy_mesh_t::string_to_macbytes(mac, info.id);

		db_client.get_string(ctx, mac, 2);
		dm_easy_mesh_t::string_to_macbytes(mac, info.bssid);

		info.last_ul_rate = db_client.get_number(ctx, 3);
		info.last_dl_rate = db_client.get_number(ctx, 4);
		info.est_ul_rate = db_client.get_number(ctx, 5);
		info.est_dl_rate = db_client.get_number(ctx, 6);
		info.last_conn_time = db_client.get_number(ctx, 7);
		info.retrans_count = db_client.get_number(ctx, 8);
		info.signal_strength = db_client.get_number(ctx, 9);
		info.util_tx = db_client.get_number(ctx, 10);
		info.util_rx = db_client.get_number(ctx, 11);
		info.pkts_tx = db_client.get_number(ctx, 12);
		info.pkts_rx = db_client.get_number(ctx, 13);
		info.bytes_tx = db_client.get_number(ctx, 14);
		info.bytes_rx = db_client.get_number(ctx, 15);
		info.errors_tx = db_client.get_number(ctx, 16);
		info.errors_rx = db_client.get_number(ctx, 17);
		db_client.get_string(ctx, info.cap, 18);
		db_client.get_string(ctx, info.ht_cap, 19);
		db_client.get_string(ctx, info.vht_cap, 20);
		db_client.get_string(ctx, info.he_cap, 21);
        
		update_list(dm_sta_t(&info), dm_orch_type_sta_insert);
    }
}

void dm_sta_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "STAList");
}

void dm_sta_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("MACAddress", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("BSSID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("LastDataUplinkRate", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("LastDataDownlinkRate", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("EstMACDataRateUplink", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("EstMACDataRateDownlink", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("LastConnectTime", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("RetransCount", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("SignalStrength", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("UtilizationTransmit", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("UtilizationReceive", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("PacketsSent", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("PacketsReceived", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("BytesSent", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("BytesReceived", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("ErrorsSent", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("ErrorsReceived", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("ClientCapabilities", db_data_type_char, 255);
    m_columns[m_num_cols++] = db_column_t("HTCapabilities", db_data_type_char, 255);
    m_columns[m_num_cols++] = db_column_t("VHTCapabilities", db_data_type_char, 255);
    m_columns[m_num_cols++] = db_column_t("HECapabilities", db_data_type_char, 255);
}

int dm_sta_list_t::init()
{
	m_list = hash_map_create();
    init_table();
    init_columns();
    return 0;
}

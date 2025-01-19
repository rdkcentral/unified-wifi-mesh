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
#include "dm_scan_result_list.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_scan_result_list_t::get_config(cJSON *parent_obj, void *parent, bool summary)
{

    return 0;
}

int dm_scan_result_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    cJSON *obj;
    dm_scan_result_t scan_result;
    dm_orch_type_t op;
	unsigned int i, size;
	db_update_scan_result_t res;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
        scan_result.decode(obj, parent_id);
		for (i = 0; i < scan_result.m_scan_result.num_neighbors; i++) {
			res.result = scan_result.get_scan_result();
			res.index = i;
        	update_db(db_client, (op = get_dm_orch_type(db_client, scan_result, i)), &res);
        	update_list(scan_result, i, op);
		}
    }

    return 0;
}

int dm_scan_result_list_t::set_config(db_client_t& db_client, dm_scan_result_t& scan_result, void *parent_id)
{
    dm_orch_type_t op;
    char *tmp = (char *)parent_id;
	unsigned int i;
	db_update_scan_result_t res;

	// first update the self with no neighbors
	res.result = scan_result.get_scan_result();
	res.index = scan_result_self_index;
	update_db(db_client, (op = get_dm_orch_type(db_client, scan_result, scan_result_self_index)), &res);
	update_list(scan_result, scan_result_self_index, op);

	for (i = 0; i < scan_result.m_scan_result.num_neighbors; i++) {
		res.result = scan_result.get_scan_result();
		res.index = i;
    	update_db(db_client, (op = get_dm_orch_type(db_client, scan_result, i)), &res);
    	update_list(scan_result, i, op);
	}

    return 0;
}

dm_orch_type_t dm_scan_result_list_t::get_dm_orch_type(db_client_t& db_client, const dm_scan_result_t& scan_result, unsigned int index)
{
    dm_scan_result_t *pscan_result;
    mac_addr_str_t	dev_mac_str, radio_mac_str, bssid_str;
	em_long_string_t key;
	em_neighbor_t *nbr, null_nbr = {0};

	nbr = (index == scan_result_self_index) ? &null_nbr:(em_neighbor_t *)&scan_result.m_scan_result.neighbor[index];

    dm_easy_mesh_t::macbytes_to_string((unsigned char *)scan_result.m_scan_result.id.dev_mac, dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string((unsigned char *)scan_result.m_scan_result.id.ruid, radio_mac_str);
	dm_easy_mesh_t::macbytes_to_string((unsigned char *)nbr->bssid, bssid_str);
    snprintf(key, sizeof(em_long_string_t), "%s@%s@%s@%d@%d@%s", 
					scan_result.m_scan_result.id.net_id, dev_mac_str, radio_mac_str, scan_result.m_scan_result.id.op_class, 
					scan_result.m_scan_result.id.channel, bssid_str);

    pscan_result = get_scan_result(key);
    if (pscan_result != NULL) {

        if (entry_exists_in_table(db_client, key) == false) {
            return dm_orch_type_db_insert;
        }

        if (*pscan_result == scan_result) {
            return dm_orch_type_db_update;
        }

        return dm_orch_type_db_update;
    }  

    return dm_orch_type_db_insert;
}

void dm_scan_result_list_t::update_list(const dm_scan_result_t& scan_result, unsigned int index, dm_orch_type_t op)
{
    dm_scan_result_t *pscan_result;
    mac_addr_str_t	dev_mac_str, radio_mac_str, bssid_str;
	em_long_string_t key;
	em_neighbor_t *nbr, null_nbr = {0};

	nbr = (index == scan_result_self_index) ? &null_nbr:(em_neighbor_t *)&scan_result.m_scan_result.neighbor[index];

    dm_easy_mesh_t::macbytes_to_string((unsigned char *)scan_result.m_scan_result.id.dev_mac, dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string((unsigned char *)scan_result.m_scan_result.id.ruid, radio_mac_str);
    dm_easy_mesh_t::macbytes_to_string((unsigned char *)nbr->bssid, bssid_str);
    snprintf(key, sizeof(em_long_string_t), "%s@%s@%s@%d@%d@%s", 
					scan_result.m_scan_result.id.net_id, dev_mac_str, radio_mac_str, scan_result.m_scan_result.id.op_class, 
					scan_result.m_scan_result.id.channel, bssid_str);

	//printf("%s:%d: Operation: %d for key: %s\n", __func__, __LINE__, op, key);

    switch (op) {
        case dm_orch_type_db_insert:
            put_scan_result(key, &scan_result);
            break;

        case dm_orch_type_db_update:
            pscan_result = get_scan_result(key);
            memcpy(&pscan_result->m_scan_result, &scan_result.m_scan_result, sizeof(em_scan_result_t));
            break;

        case dm_orch_type_db_delete:
            remove_scan_result(key);
            break;
    }
}

void dm_scan_result_list_t::delete_list()
{   
    dm_scan_result_t *scan_result, *tmp;
	mac_addr_str_t dev_mac_str, radio_mac_str, bssid_str;
    em_long_string_t key;
	unsigned int i;
  
    scan_result = get_first_scan_result();
    while (scan_result != NULL) {
        tmp = scan_result;
        scan_result = get_next_scan_result(scan_result);

		for (i = 0; i < scan_result->m_scan_result.num_neighbors; i++) {
    		dm_easy_mesh_t::macbytes_to_string((unsigned char *)scan_result->m_scan_result.id.dev_mac, dev_mac_str);
    		dm_easy_mesh_t::macbytes_to_string((unsigned char *)scan_result->m_scan_result.id.ruid, radio_mac_str);
    		dm_easy_mesh_t::macbytes_to_string((unsigned char *)scan_result->m_scan_result.neighbor[i].bssid, bssid_str);
    		snprintf(key, sizeof(em_long_string_t), "%s@%s@%s@%d@%d@%s", 
						scan_result->m_scan_result.id.net_id, dev_mac_str, radio_mac_str, scan_result->m_scan_result.id.op_class, 
						scan_result->m_scan_result.id.channel, bssid_str);
  
        	remove_scan_result(key);
		}
    }
}

bool dm_scan_result_list_t::operator == (const db_easy_mesh_t& obj)
{
    return true;
}

int dm_scan_result_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t dev_mac_str, radio_mac_str, bssid_str;
	em_long_string_t key;
	db_update_scan_result_t *res = (db_update_scan_result_t *)data;
    em_scan_result_t *scan_result = res->result;
	unsigned int index = res->index;
    int ret = 0;
	em_neighbor_t	*nbr, null_nbr = {0};

	nbr = (index == scan_result_self_index) ? &null_nbr:&scan_result->neighbor[index];

   	dm_easy_mesh_t::macbytes_to_string((unsigned char *)scan_result->id.dev_mac, dev_mac_str);
   	dm_easy_mesh_t::macbytes_to_string((unsigned char *)scan_result->id.ruid, radio_mac_str);
   	dm_easy_mesh_t::macbytes_to_string((unsigned char *)nbr->bssid, bssid_str);
   	snprintf(key, sizeof(em_long_string_t), "%s@%s@%s@%d@%d@%s", 
					scan_result->id.net_id, dev_mac_str, radio_mac_str, scan_result->id.op_class, 
					scan_result->id.channel, bssid_str);
  
    switch (op) {
        case dm_orch_type_db_insert:
            ret = insert_row(db_client, key, scan_result->scan_status, scan_result->timestamp, scan_result->util, 
											scan_result->noise, bssid_str, nbr->ssid, nbr->signal_strength,
											nbr->bandwidth, nbr->bss_color, nbr->channel_util, nbr->sta_count,
											scan_result->aggr_scan_duration, scan_result->scan_type);
            break;

	    case dm_orch_type_db_update:
            ret = update_row(db_client, scan_result->scan_status, scan_result->timestamp, scan_result->util, scan_result->noise,
											bssid_str, nbr->ssid, nbr->signal_strength, nbr->bandwidth, nbr->bss_color,
											nbr->channel_util, nbr->sta_count,
                                            scan_result->aggr_scan_duration, scan_result->scan_type, key);
            break;

	    case dm_orch_type_db_delete:
	        ret = delete_row(db_client, key);
            break;

	    default:
	        break;
	}

    return ret;
}

bool dm_scan_result_list_t::search_db(db_client_t& db_client, void *ctx, void *key)
{
    em_long_string_t  str;

    while (db_client.next_result(ctx)) {
        db_client.get_string(ctx, str, 1);
		//printf("%s:%d: Comparing source: %s target: %s\n", __func__, __LINE__, str, (char *)key);

        if (strncmp(str, (char *)key, strlen((char *)key)) == 0) {
            return true;
        }
    }
    return false;
}

int dm_scan_result_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_scan_result_t scan_result;
	em_scan_result_id_t	id;
    em_long_string_t   str;
	int rc = 0;

    while (db_client.next_result(ctx)) {
        memset(&scan_result, 0, sizeof(em_scan_result_t));

        db_client.get_string(ctx, str, 1);
		
		dm_scan_result_t::parse_scan_result_id_from_key(str, &id);
		memcpy(scan_result.id.net_id, id.net_id, sizeof(em_long_string_t));
		memcpy(scan_result.id.dev_mac, id.dev_mac, sizeof(mac_address_t));
		memcpy(scan_result.id.ruid, id.ruid, sizeof(mac_address_t));
		scan_result.id.op_class = id.op_class;
		scan_result.id.channel = id.channel;

		scan_result.scan_status = db_client.get_number(ctx, 2);
		
		db_client.get_string(ctx, str, 3);
		strncpy(scan_result.timestamp, str, strlen(str) + 1);

		scan_result.util = db_client.get_number(ctx, 4);
		scan_result.noise = db_client.get_number(ctx, 5);

        db_client.get_string(ctx, str, 6);
		dm_easy_mesh_t::string_to_macbytes(str, scan_result.neighbor[scan_result.num_neighbors].bssid);

        db_client.get_string(ctx, str, 7);
		strncpy(scan_result.neighbor[scan_result.num_neighbors].ssid, str, strlen(str) + 1);

		scan_result.neighbor[scan_result.num_neighbors].signal_strength = db_client.get_number(ctx, 8);
		scan_result.neighbor[scan_result.num_neighbors].bandwidth = (wifi_channelBandwidth_t)db_client.get_number(ctx, 9);
		scan_result.neighbor[scan_result.num_neighbors].bss_color = db_client.get_number(ctx, 10);
		scan_result.neighbor[scan_result.num_neighbors].channel_util = db_client.get_number(ctx, 11);
		scan_result.neighbor[scan_result.num_neighbors].sta_count = db_client.get_number(ctx, 12);
		scan_result.aggr_scan_duration = db_client.get_number(ctx, 13);
		scan_result.scan_type = db_client.get_number(ctx, 14);
        
		update_list(dm_scan_result_t(&scan_result), scan_result.num_neighbors, dm_orch_type_db_insert);
		scan_result.num_neighbors++;
    }

    return rc;
}

void dm_scan_result_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "ScanResultList");
}

void dm_scan_result_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 128);
    m_columns[m_num_cols++] = db_column_t("ScanStatus", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("TimeStamp", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("Utilization", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("Noise", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("BSSID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("SSID", db_data_type_char, 32);
    m_columns[m_num_cols++] = db_column_t("SignalStrength", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("Bandwidth", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("BSSColor", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("ChannelUtil", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("STACount", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("ScanDuration", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("ScanType", db_data_type_smallint, 0);
}

int dm_scan_result_list_t::init()
{
    init_table();
    init_columns();
    return 0;
}

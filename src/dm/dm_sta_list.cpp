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
#include "em_cmd.h"
#include "dm_sta_list.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_sta_list_t::get_config(cJSON *obj_arr, void *parent, bool summary)
{
    return 0;
}

int dm_sta_list_t::get_config(cJSON *obj_arr, void *parent, em_get_sta_list_reason_t reason)
{
    dm_sta_t *sta;
    cJSON *obj, *akms_arr;
    mac_addr_str_t  mac_str;
    bssid_t	bssid;
    unsigned int i;

    dm_easy_mesh_t::string_to_macbytes(static_cast<char *>(parent), bssid);

    sta = get_first_sta();
    while (sta != NULL) {
        if (memcmp(sta->m_sta_info.bssid, bssid, sizeof(mac_address_t)) != 0) {
            sta = get_next_sta(sta);
            continue;
        }
        obj = cJSON_CreateObject(); 
        sta->encode(obj, reason);

        cJSON_AddItemToArray(obj_arr, obj);
        sta = get_next_sta(sta);
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
        update_db(db_client, (op = get_dm_orch_type(db_client, sta)), sta.get_sta_info());
        update_list(sta, op);
    }

    return 0;
}

int dm_sta_list_t::set_config(db_client_t& db_client, dm_sta_t& sta, void *parent_id)
{
    dm_orch_type_t op;
    char *tmp = static_cast<char *>(parent_id);

    //printf("dm_op_class_list_t::%s:%d: id: %s\n", __func__, __LINE__, (char *)parent_id);
    update_db(db_client, (op = get_dm_orch_type(db_client, sta)), sta.get_sta_info());
    update_list(sta, op);

    return 0;
}

dm_orch_type_t dm_sta_list_t::get_dm_orch_type(db_client_t& db_client, const dm_sta_t& sta)
{
    dm_sta_t *psta;
    mac_addr_str_t  sta_mac_str, bssid_mac_str, radio_mac_str;
    em_long_string_t key;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *>(sta.m_sta_info.id), sta_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *>(sta.m_sta_info.bssid), bssid_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *>(sta.m_sta_info.radiomac), radio_mac_str);
    snprintf(key, sizeof (em_long_string_t), "%s@%s@%s", sta_mac_str, bssid_mac_str, radio_mac_str);

    psta = get_sta(key);
    if (psta != NULL) {
        if (entry_exists_in_table(db_client, sta_mac_str) == false) {
            //printf("%s:%d: STA: %s does not exist in db\n", __func__, __LINE__, key);
            return dm_orch_type_db_insert;
        }

        if (*psta == sta) {
            //printf("%s:%d: STA: %s BSS: %s already in list\n", __func__, __LINE__, sta_mac_str, bssid_mac_str);
            if (compare_db(db_client, sta) != true) {
                //printf("%s:%d: sta_map and DB mismatch, needs update\n", __func__, __LINE__);
                return dm_orch_type_db_update;
            }
            return dm_orch_type_none;
        }

        //printf("%s:%d: STA: %s BSS: %s in list but needs update\n", __func__, __LINE__, sta_mac_str, bssid_mac_str);
        return dm_orch_type_db_update;
    }

    //printf("%s:%d: STA: %s on BSS: %s not found, inserting\n", __func__, __LINE__, sta_mac_str, bssid_mac_str);
    return dm_orch_type_db_insert;
}

void dm_sta_list_t::update_list(const dm_sta_t& sta, dm_orch_type_t op)
{
    dm_sta_t *psta;
    mac_addr_str_t	sta_mac_str, bssid_mac_str, radio_mac_str;
    em_long_string_t key;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *>(sta.m_sta_info.id), sta_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *>(sta.m_sta_info.bssid), bssid_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *>(sta.m_sta_info.radiomac), radio_mac_str);
    snprintf(key, sizeof (em_long_string_t), "%s@%s@%s", sta_mac_str, bssid_mac_str, radio_mac_str);

    switch (op) {
        case dm_orch_type_db_insert:
			put_sta(key, &sta);	
            break;

        case dm_orch_type_db_update:
			psta = get_sta(key);
            memcpy(&psta->m_sta_info, &sta.m_sta_info, sizeof(em_sta_info_t));
            break;

        case dm_orch_type_db_delete:
            remove_sta(key);            
            break;

        default:
            break;
    }

}

void dm_sta_list_t::delete_list()
{       
    dm_sta_t *psta, *tmp;
    mac_addr_str_t	sta_mac_str, bssid_mac_str;
    em_long_string_t key;
    
    psta = get_first_sta();
    while (psta != NULL) {
        tmp = psta;
        psta = get_next_sta(psta);       
    
   	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *>(tmp->m_sta_info.id), sta_mac_str);
    	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *>(tmp->m_sta_info.bssid), bssid_mac_str);
    	snprintf(key, sizeof (em_long_string_t), "%s@%s", sta_mac_str, bssid_mac_str);
        remove_sta(key);    
    }
}   

bool dm_sta_list_t::operator == (const db_easy_mesh_t& obj)
{
    return true;
}

int dm_sta_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t sta_mac_str, bssid_mac_str, radio_mac_str;
    em_sta_info_t *info = static_cast<em_sta_info_t *>(data);
    int ret = 0;
    char frame_body[EM_MAX_FRAME_BODY_LEN*2];

    //printf("dm_sta_list_t:%s:%d: Operation: %s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(op));

	switch (op) {
		case dm_orch_type_db_insert:
			dm_easy_mesh_t::hex(info->frame_body_len, info->frame_body, EM_MAX_FRAME_BODY_LEN*2, frame_body);
			ret = insert_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->id, sta_mac_str),
						dm_easy_mesh_t::macbytes_to_string(info->bssid, bssid_mac_str),
						dm_easy_mesh_t::macbytes_to_string(info->radiomac, radio_mac_str),
						info->associated, info->last_ul_rate, info->last_dl_rate,
						info->est_ul_rate, info->est_dl_rate, info->last_conn_time, info->retrans_count,
						info->signal_strength, info->rcpi, info->util_tx, info->util_rx, info->pkts_tx, info->pkts_rx,
						info->bytes_tx, info->bytes_rx, info->errors_tx, info->errors_rx,
						info->frame_body_len, frame_body);
							
			break;

		case dm_orch_type_db_update:
			dm_easy_mesh_t::hex(info->frame_body_len, info->frame_body, EM_MAX_FRAME_BODY_LEN*2, frame_body);
			ret = update_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->bssid, bssid_mac_str), 
						dm_easy_mesh_t::macbytes_to_string(info->radiomac, radio_mac_str),
						info->associated, info->last_ul_rate, info->last_dl_rate,
						info->est_ul_rate, info->est_dl_rate, info->last_conn_time, info->retrans_count,
						info->signal_strength, info->rcpi, info->util_tx, info->util_rx, info->pkts_tx, info->pkts_rx,
						info->bytes_tx, info->bytes_rx, info->errors_tx, info->errors_rx,
						info->frame_body_len, frame_body,
						dm_easy_mesh_t::macbytes_to_string(info->id, sta_mac_str));
			break;

		case dm_orch_type_db_delete:
			ret = delete_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->id, sta_mac_str));
			break;

		default:
			break;
	}

    return ret;
}

bool dm_sta_list_t::search_db(db_client_t& db_client, void *ctx, void *key)
{
    mac_addr_str_t  mac;

    while (db_client.next_result(ctx)) {
        db_client.get_string(ctx, mac, 1);

        if (strncmp(mac, static_cast<char *>(key), strlen(static_cast<char *>(key))) == 0) {
            return true;
        }
    }

    return false;
}

bool dm_sta_list_t::compare_db(db_client_t& db_client, const dm_sta_t& sta)
{
    em_sta_info_t info;
    mac_addr_str_t mac;
    char frame_body[EM_MAX_FRAME_BODY_LEN*2];

    db_query_t    query;
    db_result_t   result;
    void *ctx;

    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "select * from %s", m_table_name);

    ctx = db_client.execute(query);

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_sta_info_t));

        db_client.get_string(ctx, mac, 1);
        dm_easy_mesh_t::string_to_macbytes(mac, info.id);

        db_client.get_string(ctx, mac, 2);
        dm_easy_mesh_t::string_to_macbytes(mac, info.bssid);

        db_client.get_string(ctx, mac, 3);
        dm_easy_mesh_t::string_to_macbytes(mac, info.radiomac);

        info.associated = db_client.get_number(ctx, 4);
        info.last_ul_rate = db_client.get_number(ctx, 5);
        info.last_dl_rate = db_client.get_number(ctx, 6);
        info.est_ul_rate = db_client.get_number(ctx, 7);
        info.est_dl_rate = db_client.get_number(ctx, 8);
        info.last_conn_time = db_client.get_number(ctx, 9);
        info.retrans_count = db_client.get_number(ctx, 10);
        info.signal_strength = db_client.get_number(ctx, 11);
        info.rcpi = static_cast<unsigned char> (db_client.get_number(ctx, 12));
        info.util_tx = db_client.get_number(ctx, 13);
        info.util_rx = db_client.get_number(ctx, 14);
        info.pkts_tx = db_client.get_number(ctx, 15);
        info.pkts_rx = db_client.get_number(ctx, 16);
        info.bytes_tx = db_client.get_number(ctx, 17);
        info.bytes_rx = db_client.get_number(ctx, 18);
        info.errors_tx = db_client.get_number(ctx, 19);
        info.errors_rx = db_client.get_number(ctx, 20);
        info.frame_body_len = db_client.get_number(ctx, 21);

        db_client.get_string(ctx, frame_body, 22);
        dm_easy_mesh_t::unhex(strlen(frame_body), frame_body, EM_MAX_FRAME_BODY_LEN, info.frame_body);

        if (memcmp(static_cast<const void*>(&sta.m_sta_info), static_cast<const void*>(&info), sizeof(em_sta_info_t)) == 0) {
            return true;
        }
    }

    return false;
}

int dm_sta_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_sta_info_t info;
    mac_addr_str_t	mac;
    em_long_string_t   str;
    unsigned int i;
    int rc = 0;
    char frame_body[EM_MAX_FRAME_BODY_LEN*2];

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_sta_info_t));

        db_client.get_string(ctx, mac, 1);
        dm_easy_mesh_t::string_to_macbytes(mac, info.id);

        db_client.get_string(ctx, mac, 2);
        dm_easy_mesh_t::string_to_macbytes(mac, info.bssid);

        db_client.get_string(ctx, mac, 3);
        dm_easy_mesh_t::string_to_macbytes(mac, info.radiomac);

        info.associated = db_client.get_number(ctx, 4);
        info.last_ul_rate = db_client.get_number(ctx, 5);
        info.last_dl_rate = db_client.get_number(ctx, 6);
        info.est_ul_rate = db_client.get_number(ctx, 7);
        info.est_dl_rate = db_client.get_number(ctx, 8);
        info.last_conn_time = db_client.get_number(ctx, 9);
        info.retrans_count = db_client.get_number(ctx, 10);
        info.signal_strength = db_client.get_number(ctx, 11);
        info.rcpi = static_cast<unsigned char> (db_client.get_number(ctx, 12));
        info.util_tx = db_client.get_number(ctx, 13);
        info.util_rx = db_client.get_number(ctx, 14);
        info.pkts_tx = db_client.get_number(ctx, 15);
        info.pkts_rx = db_client.get_number(ctx, 16);
        info.bytes_tx = db_client.get_number(ctx, 17);
        info.bytes_rx = db_client.get_number(ctx, 18);
        info.errors_tx = db_client.get_number(ctx, 19);
        info.errors_rx = db_client.get_number(ctx, 20);
        info.frame_body_len = db_client.get_number(ctx, 21);

        db_client.get_string(ctx, frame_body, 22);
        dm_easy_mesh_t::unhex(strlen(frame_body), frame_body, EM_MAX_FRAME_BODY_LEN, info.frame_body);

        update_list(dm_sta_t(&info), dm_orch_type_db_insert);
    }
    return rc;
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
    m_columns[m_num_cols++] = db_column_t("RUID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("Associated", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("LastDataUplinkRate", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("LastDataDownlinkRate", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("EstMACDataRateUplink", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("EstMACDataRateDownlink", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("LastConnectTime", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("RetransCount", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("SignalStrength", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("RCPI", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("UtilizationTransmit", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("UtilizationReceive", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("PacketsSent", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("PacketsReceived", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("BytesSent", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("BytesReceived", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("ErrorsSent", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("ErrorsReceived", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("FrameBodyLength", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("FrameBody", db_data_type_text, 1024);
}

int dm_sta_list_t::init()
{
    init_table();
    init_columns();
    return 0;
}

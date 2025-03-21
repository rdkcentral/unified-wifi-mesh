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
#include "dm_bss_list.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_bss_list_t::get_config(cJSON *obj_arr, void *parent, bool summary)
{
    dm_bss_t *pbss;
    cJSON *obj;
    mac_addr_str_t  mac_str;
    mac_address_t	ruid;

    dm_easy_mesh_t::string_to_macbytes(static_cast<char *> (parent), ruid);

    pbss = get_first_bss();
    //printf("%s:%d: pbss: %p\n", __func__, __LINE__, pbss);
    
    while (pbss != NULL) {
        dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.ruid.mac, mac_str);
        //printf("%s:%d: Parent Radio: %s, Current BSS Radio: %s\n", __func__, __LINE__, (char *)parent, mac_str);
        if (memcmp(pbss->m_bss_info.ruid.mac, ruid, sizeof(mac_address_t)) != 0) {
            pbss = get_next_bss(pbss);
            continue;
        }

        obj = cJSON_CreateObject(); 

        pbss->encode(obj, summary);

        cJSON_AddItemToArray(obj_arr, obj);
        pbss = get_next_bss(pbss);
    }
    
	
    return 0;
}

int dm_bss_list_t::set_config(db_client_t& db_client, dm_bss_t& bss, void *parent_id)
{
    dm_orch_type_t op;  

    //printf("%s:%d: Parent: %s \n", __func__, __LINE__, (char *)parent_id);
	parse_bss_id_from_key(static_cast<char *> (parent_id), &bss.m_bss_info.id);

    update_db(db_client, (op = get_dm_orch_type(db_client, bss)), bss.get_bss_info());
    update_list(bss, op);
                        
    return 0;
}

int dm_bss_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    cJSON *obj;
    int i, size;
    dm_bss_t bss;
    dm_orch_type_t op;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
		bss.decode(obj, parent_id);
		update_db(db_client, (op = get_dm_orch_type(db_client, bss)), bss.get_bss_info());
		update_list(bss, op);
    }

    return 0;
}

dm_orch_type_t dm_bss_list_t::get_dm_orch_type(db_client_t& db_client, const dm_bss_t& bss)
{
    dm_bss_t *pbss;
    mac_addr_str_t  bss_mac_str, radio_mac_str, dev_mac_str;
	em_2xlong_string_t key;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (bss.m_bss_info.id.dev_mac), dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (bss.m_bss_info.bssid.mac), bss_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (bss.m_bss_info.ruid.mac), radio_mac_str);

	snprintf(key, sizeof(em_2xlong_string_t), "%s@%s@%s@%s@%d", bss.m_bss_info.id.net_id, dev_mac_str, 
					radio_mac_str, bss_mac_str, bss.m_bss_info.id.haul_type);

    pbss = get_bss(key);

    if (pbss != NULL) {
        if (entry_exists_in_table(db_client, bss_mac_str) == false) {
            return dm_orch_type_db_insert;
        }

        if (*pbss == bss) {
            //printf("%s:%d: BSS: %s Radio: %s already in list\n", __func__, __LINE__, 
                //dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.bssid.mac, bss_mac_str),
                //dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.ruid.mac, radio_mac_str));
            return dm_orch_type_none;
        }


        //printf("%s:%d: BSS: %s Radio: %s in list but needs update\n", __func__, __LINE__,
            //dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.bssid.mac, bss_mac_str),
            //dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.ruid.mac, radio_mac_str));
        return dm_orch_type_db_update;
    }

    return dm_orch_type_db_insert;
}


void dm_bss_list_t::update_list(const dm_bss_t& bss, dm_orch_type_t op)
{
    dm_bss_t *pbss;
    mac_addr_str_t	bss_mac_str, radio_mac_str, dev_mac_str;
	em_2xlong_string_t	key;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (bss.m_bss_info.id.dev_mac), dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (bss.m_bss_info.ruid.mac), radio_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (bss.m_bss_info.bssid.mac), bss_mac_str);

	snprintf(key, sizeof(em_2xlong_string_t), "%s@%s@%s@%s@%d", bss.m_bss_info.id.net_id, dev_mac_str, 
					radio_mac_str, bss_mac_str, bss.m_bss_info.id.haul_type);

    switch (op) {
        case dm_orch_type_db_insert:
            put_bss(key, &bss);
            break;

        case dm_orch_type_db_update:
			pbss = get_bss(key);
            memcpy(&pbss->m_bss_info, &bss.m_bss_info, sizeof(em_bss_info_t));
            break;

        case dm_orch_type_db_delete:
            remove_bss(key);            
            break;

        default:
            break;
    }

}

void dm_bss_list_t::delete_list()
{       
    dm_bss_t *pbss, *tmp;
    mac_addr_str_t	bss_mac_str, radio_mac_str, dev_mac_str;
    em_2xlong_string_t key;
    
    pbss = get_first_bss();
    while (pbss != NULL) {
        tmp = pbss;
        pbss = get_next_bss(pbss);
    
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (tmp->m_bss_info.id.dev_mac), dev_mac_str);
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (tmp->m_bss_info.ruid.mac), radio_mac_str);
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (tmp->m_bss_info.bssid.mac), bss_mac_str);
        snprintf(key, sizeof (em_2xlong_string_t), "%s@%s@%s@%s@%d", tmp->m_bss_info.id.net_id, dev_mac_str, 
						radio_mac_str, bss_mac_str, tmp->m_bss_info.id.haul_type);

        remove_bss(key);
    }
}   


bool dm_bss_list_t::operator == (const db_easy_mesh_t& obj)
{
    return true;
}

int dm_bss_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t dev_mac_str, bss_mac_str, radio_mac_str;
    em_bss_info_t *info = static_cast<em_bss_info_t *> (data);
    int ret = 0;
    unsigned int i;
	em_2xlong_string_t key;
    em_long_string_t	front_akms, back_akms;
        
	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (info->id.dev_mac), dev_mac_str);
	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (info->ruid.mac), radio_mac_str);
	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (info->bssid.mac), bss_mac_str);
	snprintf(key, sizeof (em_2xlong_string_t), "%s@%s@%s@%s@%d", info->id.net_id, dev_mac_str, 
					radio_mac_str, bss_mac_str, info->id.haul_type);

    //printf("dm_bss_list_t:%s:%d: Operation: %s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(op));
    memset(front_akms, 0, sizeof(em_long_string_t));
    for (i = 0; i < info->num_fronthaul_akms; i++) {
        strncat(front_akms, info->fronthaul_akm[i], strlen(info->fronthaul_akm[i]));
        strncat(front_akms, ",", strlen(",") + 1);
    }
    memset(back_akms, 0, sizeof(em_long_string_t));
    for (i = 0; i < info->num_backhaul_akms; i++) {
        strncat(back_akms, info->backhaul_akm[i], strlen(info->backhaul_akm[i]));
        strncat(back_akms, ",", strlen(",") + 1);
    }
	
	switch (op) {
		case dm_orch_type_db_insert:
			ret = insert_row(db_client, key, dm_easy_mesh_t::macbytes_to_string(info->bssid.mac, bss_mac_str),
						dm_easy_mesh_t::macbytes_to_string(info->ruid.mac, radio_mac_str), info->ssid, info->enabled,
						info->est_svc_params_be, info->est_svc_params_bk, info->est_svc_params_vi, info->est_svc_params_vo,
						front_akms, back_akms, info->profile_1b_sta_allowed, info->profile_2b_sta_allowed, info->assoc_allowed_status,
						info->backhaul_use, info->fronthaul_use, info->r1_disallowed, info->r2_disallowed, 
						info->multi_bssid, info->transmitted_bssid);
							
			break;

		case dm_orch_type_db_update:
			ret = update_row(db_client, key, dm_easy_mesh_t::macbytes_to_string(info->ruid.mac, radio_mac_str), info->ssid, info->enabled,
                        info->est_svc_params_be, info->est_svc_params_bk, info->est_svc_params_vi, info->est_svc_params_vo,
                        front_akms, back_akms, info->profile_1b_sta_allowed, info->profile_2b_sta_allowed, info->assoc_allowed_status,
                        info->backhaul_use, info->fronthaul_use, info->r1_disallowed, info->r2_disallowed, 
                        info->multi_bssid, info->transmitted_bssid,
						dm_easy_mesh_t::macbytes_to_string(info->bssid.mac, bss_mac_str));
			break;

		case dm_orch_type_db_delete:
			ret = delete_row(db_client, key);
			break;

		default:
			break;
	}

    return ret;
}

bool dm_bss_list_t::search_db(db_client_t& db_client, void *ctx, void *key)
{
    em_long_string_t    str;

    while (db_client.next_result(ctx)) {
        db_client.get_string(ctx, str, 1);

        if (strncmp(str, static_cast<char *> (key), strlen(static_cast<char *> (key))) == 0) {
            return true;
        }
    }

    return false;
}

int dm_bss_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_bss_info_t info;
    mac_addr_str_t	mac;
    em_long_string_t   str;
    unsigned int i;
    char   *token_parts[EM_MAX_AKMS];
    int rc = 0;

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_bss_info_t));

        db_client.get_string(ctx, str, 1);
		dm_bss_t::parse_bss_id_from_key(str, &info.id);

        db_client.get_string(ctx, mac, 2);
        dm_easy_mesh_t::string_to_macbytes(mac, info.bssid.mac);

        db_client.get_string(ctx, mac, 3);
        dm_easy_mesh_t::string_to_macbytes(mac, info.ruid.mac);

        db_client.get_string(ctx, info.ssid, 4);
        info.enabled = db_client.get_number(ctx, 5);

        db_client.get_string(ctx, info.est_svc_params_be, 6);
        db_client.get_string(ctx, info.est_svc_params_bk, 7);
        db_client.get_string(ctx, info.est_svc_params_vi, 8);
        db_client.get_string(ctx, info.est_svc_params_vo, 9);

        db_client.get_string(ctx, str, 10);
        for (i = 0; i < EM_MAX_AKMS; i++) {
            token_parts[i] = info.fronthaul_akm[i];
        }
        info.num_fronthaul_akms = static_cast<unsigned char> (get_strings_by_token(str, ',', EM_MAX_AKMS, token_parts));

        db_client.get_string(ctx, str, 11);

        for (i = 0; i < EM_MAX_AKMS; i++) {
            token_parts[i] = info.backhaul_akm[i];
        }
        info.num_backhaul_akms = static_cast<unsigned char> (get_strings_by_token(str, ',', EM_MAX_AKMS, token_parts));

        info.profile_1b_sta_allowed = db_client.get_number(ctx, 12);
        info.profile_2b_sta_allowed = db_client.get_number(ctx, 13);
        info.assoc_allowed_status = static_cast<unsigned int> (db_client.get_number(ctx, 14));
        info.backhaul_use = db_client.get_number(ctx, 15);
        info.fronthaul_use = db_client.get_number(ctx, 16);
        info.r1_disallowed = db_client.get_number(ctx, 17);
        info.r2_disallowed = db_client.get_number(ctx, 18);
        info.multi_bssid = db_client.get_number(ctx, 19);
        info.transmitted_bssid = db_client.get_number(ctx, 20);

        update_list(dm_bss_t(&info), dm_orch_type_db_insert);
    }

    return rc;

}

void dm_bss_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "BSSList");
}

void dm_bss_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 128);
	m_columns[m_num_cols++] = db_column_t("BSSID", db_data_type_char, 17);
	m_columns[m_num_cols++] = db_column_t("RUID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("SSID", db_data_type_char, 32);
    m_columns[m_num_cols++] = db_column_t("Enabled", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("EstServiceParametersBE", db_data_type_char, 16);
    m_columns[m_num_cols++] = db_column_t("EstServiceParametersBK", db_data_type_char, 16);
    m_columns[m_num_cols++] = db_column_t("EstServiceParametersVI", db_data_type_char, 16);
    m_columns[m_num_cols++] = db_column_t("EstServiceParametersVO", db_data_type_char, 16);
    m_columns[m_num_cols++] = db_column_t("FronthaulAKMsAllowed", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("BackhaulAKMsAllowed", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("Profile1bSTAsDisallowed", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("Profile2bSTAsDisallowed", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("AssociationAllowanceStatus", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("FronthaulUse", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("BackhaulUse", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("R1disallowed", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("R2disallowed", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("MultiBSSID", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("TransmittedBSSID", db_data_type_tinyint, 0);
}

int dm_bss_list_t::init()
{
    init_table();
    init_columns();
    return 0;
}

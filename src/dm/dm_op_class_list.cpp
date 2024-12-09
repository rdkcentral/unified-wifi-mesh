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
#include "dm_op_class_list.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_op_class_list_t::get_config(cJSON *obj_arr, void *parent, bool summary)
{
    dm_op_class_t *pop_class;
    cJSON *obj, *non_op_arr, *anticipated_arr;
    unsigned int i;
    em_op_class_id_t id;
    em_op_class_info_t *info;
    mac_addr_str_t mac_str;

    dm_op_class_t::parse_op_class_id_from_key((char *)parent, &id);
	
    pop_class = (dm_op_class_t *)get_first_op_class();
    while (pop_class != NULL) {
        info = pop_class->get_op_class_info();
		dm_easy_mesh_t::macbytes_to_string(info->id.ruid, mac_str);
		//printf("%s:%d: ruid: %s type: %d\n", __func__, __LINE__, mac_str, info->id.type);
		if ((memcmp(info->id.ruid, id.ruid, sizeof(mac_address_t)) != 0) || (info->id.type != id.type)) {
	    	pop_class = get_next_op_class(pop_class);
	    	continue;
		}

       	obj = cJSON_CreateObject(); 

		cJSON_AddNumberToObject(obj, "Class", pop_class->m_op_class_info.op_class);
    	if (id.type == em_op_class_type_current) {
        	cJSON_AddNumberToObject(obj, "Channel", pop_class->m_op_class_info.channel);
        	cJSON_AddNumberToObject(obj, "TxPower", pop_class->m_op_class_info.tx_power);
    	} else if (id.type == em_op_class_type_capability) {
        	cJSON_AddNumberToObject(obj, "MaxTxPower", pop_class->m_op_class_info.max_tx_power);
        	non_op_arr = cJSON_AddArrayToObject(obj, "NonOperable");
	    	for (i = 0; i < pop_class->m_op_class_info.num_channels; i++) {
            	cJSON_AddItemToArray(non_op_arr, cJSON_CreateNumber(pop_class->m_op_class_info.channels[i]));
        	}
    	} else if ((id.type == em_op_class_type_preference) || 
							(id.type == em_op_class_type_anticipated) ||
							(id.type == em_op_class_type_scan_param)) {
			anticipated_arr = cJSON_AddArrayToObject(obj, "ChannelList");
			for (i = 0; i < pop_class->m_op_class_info.num_channels; i++) {
            	cJSON_AddItemToArray(anticipated_arr, cJSON_CreateNumber(pop_class->m_op_class_info.channels[i]));
        	}
    	}
		cJSON_AddItemToArray(obj_arr, obj);
		pop_class = get_next_op_class(pop_class);
    }
    
	
    return 0;
}

int dm_op_class_list_t::get_config(cJSON *obj_arr, em_op_class_type_t type)
{
	dm_op_class_t *op_class;
	cJSON *obj, *channel_arr;
	unsigned int i;

	// only anticipated is implemented now
	if ((type != em_op_class_type_anticipated) && (type != em_op_class_type_scan_param)) {
		printf("%s:%d: Non anticipated category not imeplemented, type: %d\n", __func__, __LINE__, type);
		assert(0);
		return -1;
	}		

	op_class = (dm_op_class_t *)get_first_pre_set_op_class_by_type(type);
	while (op_class) {
       	obj = cJSON_CreateObject(); 

		cJSON_AddNumberToObject(obj, "Class", op_class->m_op_class_info.op_class);
		channel_arr = cJSON_AddArrayToObject(obj, "ChannelList");
		for (i = 0; i < op_class->m_op_class_info.num_channels; i++) {
           	cJSON_AddItemToArray(channel_arr, cJSON_CreateNumber(op_class->m_op_class_info.channels[i]));
       	}

		cJSON_AddItemToArray(obj_arr, obj);
		op_class = (dm_op_class_t *)get_next_pre_set_op_class_by_type(type, op_class);
	}
}

int dm_op_class_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    cJSON *obj;
    unsigned int i, size;
    dm_op_class_t op_class;
    dm_orch_type_t op;

    //printf("dm_op_class_list_t::%s:%d: id: %s\n", __func__, __LINE__, (char *)parent_id);
    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
        op_class.decode(obj, parent_id);
        update_db(db_client, (op = get_dm_orch_type(db_client, op_class)), op_class.get_op_class_info());
        update_list(op_class, op);
    }

    return 0;
}

int dm_op_class_list_t::set_config(db_client_t& db_client, dm_op_class_t& op_class, void *parent_id)
{
    dm_orch_type_t op;
    char *tmp = (char *)parent_id;

    //printf("dm_op_class_list_t::%s:%d: id: %s\n", __func__, __LINE__, (char *)parent_id);
    update_db(db_client, (op = get_dm_orch_type(db_client, op_class)), op_class.get_op_class_info());
    update_list(op_class, op);

    return 0;
}

dm_orch_type_t dm_op_class_list_t::get_dm_orch_type(db_client_t& db_client, const dm_op_class_t& op_class)
{
    dm_op_class_t *pop_class;
    mac_addr_str_t  mac_str;
    em_short_string_t   key;

    dm_easy_mesh_t::macbytes_to_string((unsigned char *)op_class.m_op_class_info.id.ruid, mac_str);
	//printf("%s:%d: MAC: %s\tType: %d\tClass: %d\n", __func__, __LINE__, mac_str,
			//op_class.m_op_class_info.id.type, op_class.m_op_class_info.id.op_class);
    snprintf(key, sizeof(key), "%s@%d@%d", mac_str, op_class.m_op_class_info.id.type, op_class.m_op_class_info.id.op_class);

    pop_class = get_op_class(key);
    if (pop_class != NULL) {

        if (entry_exists_in_table(db_client, key) == false) {
            //printf("%s:%d: Op Class: %s does not exist in db\n", __func__, __LINE__, key);
            return dm_orch_type_db_insert;
        }

        if (*pop_class == op_class) {
            //printf("%s:%d: Op Class: %s already in list\n", __func__, __LINE__, key);
            return dm_orch_type_db_update;
        }

        //printf("%s:%d: Op Class: %s in list but needs update\n", __func__, __LINE__, key);
        return dm_orch_type_db_update;
    }  

    //printf("%s:%d: Op Class: %s could not be found, inserting\n", __func__, __LINE__, key);
    return dm_orch_type_db_insert;
}

void dm_op_class_list_t::update_list(const dm_op_class_t& op_class, dm_orch_type_t op)
{
    dm_op_class_t *pop_class;
    mac_addr_str_t	mac_str;
    em_long_string_t	key;

    dm_easy_mesh_t::macbytes_to_string((unsigned char *)op_class.m_op_class_info.id.ruid, mac_str);
    snprintf(key, sizeof(key), "%s@%d@%d", mac_str, op_class.m_op_class_info.id.type, op_class.m_op_class_info.id.op_class);

    switch (op) {
        case dm_orch_type_db_insert:
            put_op_class(key, &op_class);
            break;

        case dm_orch_type_db_update:
            pop_class = get_op_class(key);
            memcpy(&pop_class->m_op_class_info, &op_class.m_op_class_info, sizeof(em_op_class_info_t));
            break;

        case dm_orch_type_db_delete:
            remove_op_class(key);
            break;
    }
}

void dm_op_class_list_t::delete_list()
{   
    dm_op_class_t *pop_class, *tmp;
    mac_addr_str_t  mac_str = {0};
    em_short_string_t	key;
  
    pop_class = get_first_op_class();
    while (pop_class != NULL) {
        tmp = pop_class;
        pop_class = get_next_op_class(pop_class);
    	dm_easy_mesh_t::macbytes_to_string((unsigned char *)tmp->m_op_class_info.id.ruid, mac_str);
    	snprintf(key, sizeof(key), "%s@%d@%d", mac_str, tmp->m_op_class_info.id.type, tmp->m_op_class_info.id.op_class);
  
        remove_op_class(key);
    }
}

bool dm_op_class_list_t::operator == (const db_easy_mesh_t& obj)
{
    return true;
}

int dm_op_class_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t mac_str;
    em_long_string_t channels_str = {0}, id;
    char tmp[8];
    em_op_class_info_t *info = (em_op_class_info_t *)data;
    int ret = 0;
    unsigned int i;

    dm_easy_mesh_t::macbytes_to_string(info->id.ruid, mac_str);
    snprintf(id, sizeof(id), "%s@%d@%d", mac_str, info->id.type, info->id.op_class);
    //printf("\n%s:%d: Opeartion:%d, id:%s\tmac:%s\ttype:%d\tClass:%d\tClass: %d\n", __func__, __LINE__, op, id, mac_str, info->id.type, info->id.op_class, info->op_class);

	for (i = 0; i < info->num_channels; i++) {
		snprintf(tmp, sizeof(tmp), "%d,", info->channels[i]);
		snprintf(channels_str + strlen(channels_str), sizeof(channels_str) - strlen(channels_str), "%s", tmp);
	}

	channels_str[strlen(channels_str) - 1] = 0;
    switch (op) {
        case dm_orch_type_db_insert:
            ret = insert_row(db_client, id, info->op_class, info->channel, channels_str, info->tx_power, info->max_tx_power,
                                           info->mins_since_cac_comp, info->sec_remain_non_occ_dur, info->countdown_cac_comp);
            break;

	    case dm_orch_type_db_update:
            ret = update_row(db_client, info->op_class, info->channel, channels_str, info->tx_power, info->max_tx_power, 
                                       info->mins_since_cac_comp, info->sec_remain_non_occ_dur, info->countdown_cac_comp, id);
            break;

	    case dm_orch_type_db_delete:
	        ret = delete_row(db_client, id);
            break;

	    default:
	        break;
	}

    return ret;
}

bool dm_op_class_list_t::search_db(db_client_t& db_client, void *ctx, void *key)
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

int dm_op_class_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_op_class_info_t info;
    em_long_string_t   str, id;
    mac_addr_str_t	mac_str;
    em_short_string_t	ch_str[EM_MAX_CHANNELS_IN_LIST];
    char   *token_parts[EM_MAX_CHANNELS_IN_LIST], *tmp;
    unsigned int i = 0;
    int rc = 0;

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_op_class_info_t));

        db_client.get_string(ctx, id, 1);
        dm_op_class_t::parse_op_class_id_from_key(id, &info.id);
        info.op_class = db_client.get_number(ctx, 2);
        info.channel = db_client.get_number(ctx, 3);
        
		db_client.get_string(ctx, str, 4);
		for (i = 0; i < EM_MAX_CHANNELS_IN_LIST; i++) {
            token_parts[i] = ch_str[i];
        }

		if ((str != NULL) && (*str != 0)) {	
			info.num_channels = get_strings_by_token(str, ',', EM_MAX_CHANNELS_IN_LIST, token_parts);
			for (i = 0; i < info.num_channels; i++) {
				info.channels[i] = atoi(token_parts[i]);
			}
		}

        info.tx_power = db_client.get_number(ctx, 5);
        info.max_tx_power = db_client.get_number(ctx, 6);

        info.mins_since_cac_comp = db_client.get_number(ctx, 7);
        info.sec_remain_non_occ_dur = db_client.get_number(ctx, 8);
        info.countdown_cac_comp = db_client.get_number(ctx, 9);

        update_list(dm_op_class_t(&info), dm_orch_type_db_insert);
    }

    return rc;
}

void dm_op_class_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "OperatingClassList");
}

void dm_op_class_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 32);
    m_columns[m_num_cols++] = db_column_t("Class", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("Channel", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("ChannelList", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("TxPower", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("MaxTxPower", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("Minutes", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("Seconds", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("Countdown", db_data_type_int, 0);
}

int dm_op_class_list_t::init()
{
    init_table();
    init_columns();
    return 0;
}

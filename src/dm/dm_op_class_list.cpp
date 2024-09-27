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

int dm_op_class_list_t::get_config(cJSON *obj_arr, void *parent)
{
	dm_op_class_t *pop_class;
	cJSON *obj, *non_op_arr;
	unsigned int i;
	
	pop_class = (dm_op_class_t *)hash_map_get_first(m_list);
    while (pop_class != NULL) {
       	obj = cJSON_CreateObject(); 

		cJSON_AddNumberToObject(obj, "Class", pop_class->m_op_class_info.op_class);
		cJSON_AddNumberToObject(obj, "Channel", pop_class->m_op_class_info.channel);
		cJSON_AddNumberToObject(obj, "TxPower", pop_class->m_op_class_info.tx_power);
		cJSON_AddNumberToObject(obj, "MaxTxPower", pop_class->m_op_class_info.max_tx_power);
		non_op_arr = cJSON_AddArrayToObject(obj, "NonOperable");
		for (i = 0; i < pop_class->m_op_class_info.num_non_op_channels; i++) {
            cJSON_AddItemToArray(non_op_arr, cJSON_CreateNumber(pop_class->m_op_class_info.non_op_channel[i]));
        }

	
		cJSON_AddItemToArray(obj_arr, obj);
		pop_class = (dm_op_class_t *)hash_map_get_next(m_list, pop_class);
    }
    
	
	return 0;
}

int dm_op_class_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    cJSON *obj;
    unsigned int i, size;
	dm_op_class_t op_class;
	dm_orch_type_t op;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
		op_class.decode(obj, parent_id);
		update_db(db_client, (op = get_dm_orch_type(op_class)), op_class.get_op_class_info());
		update_list(op_class, op);
    }

    return 0;
}


dm_orch_type_t dm_op_class_list_t::get_dm_orch_type(const dm_op_class_t& op_class)
{
    dm_op_class_t *pop_class;
    mac_addr_str_t  mac_str;
    em_short_string_t   key;

    dm_easy_mesh_t::macbytes_to_string((unsigned char *)op_class.m_op_class_info.id.ruid.mac, mac_str);
    snprintf(key, sizeof(key), "%s-%d", mac_str, op_class.m_op_class_info.id.type);

    pop_class = (dm_op_class_t *)hash_map_get(m_list, key);
    if (pop_class != NULL) {
        if (*pop_class == op_class) {
            printf("%s:%d: Device: %s Type: %dalready in list\n", __func__, __LINE__,
                        dm_easy_mesh_t::macbytes_to_string(pop_class->m_op_class_info.id.ruid.mac, mac_str), pop_class->m_op_class_info.id.type);
            return dm_orch_type_none;
        }
   

        printf("%s:%d: Device: %s Type: %din list but needs update\n", __func__, __LINE__,
            dm_easy_mesh_t::macbytes_to_string(pop_class->m_op_class_info.id.ruid.mac, mac_str), pop_class->m_op_class_info.id.type);
        return dm_orch_type_op_class_update;
    }  

    return dm_orch_type_op_class_insert;
}

void dm_op_class_list_t::update_list(const dm_op_class_t& op_class, dm_orch_type_t op)
{
	dm_op_class_t *pop_class;
	mac_addr_str_t	mac_str;
	em_short_string_t	key;

    dm_easy_mesh_t::macbytes_to_string((unsigned char *)op_class.m_op_class_info.id.ruid.mac, mac_str);
    snprintf(key, sizeof(key), "%s-%d", mac_str, op_class.m_op_class_info.id.type);

    switch (op) {
        case dm_orch_type_op_class_insert:
			hash_map_put(m_list, strdup(key), new dm_op_class_t(op_class));	
            break;

        case dm_orch_type_op_class_update:
            pop_class = (dm_op_class_t *)hash_map_get(m_list, key);
            memcpy(&pop_class->m_op_class_info, &op_class.m_op_class_info, sizeof(em_op_class_info_t));
            break;

        case dm_orch_type_op_class_delete:
            pop_class = (dm_op_class_t *)hash_map_remove(m_list, key);
            delete(pop_class);
            break;
    }
}

void dm_op_class_list_t::delete_list()
{   
    dm_op_class_t *pop_class, *tmp;
    mac_addr_str_t  mac_str = {0};
	em_short_string_t	key;
  
    pop_class = (dm_op_class_t *)hash_map_get_first(m_list);
    while (pop_class != NULL) {
        tmp = pop_class;
        pop_class = (dm_op_class_t *)hash_map_get_next(m_list, pop_class);
    	dm_easy_mesh_t::macbytes_to_string((unsigned char *)tmp->m_op_class_info.id.ruid.mac, mac_str);
    	snprintf(key, sizeof(key), "%s-%d", mac_str, tmp->m_op_class_info.id.type);
  
        hash_map_remove(m_list, key);
        delete(tmp);
    }
}

bool dm_op_class_list_t::operator == (const db_easy_mesh_t& obj)
{
	return true;
}

int dm_op_class_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t mac_str;
	em_long_string_t non_op_str;
	char tmp[8];
    em_op_class_info_t *info = (em_op_class_info_t *)data;
	int ret = 0;
	unsigned int i;

	//printf("%s:%d: Opeartion:%d\n", __func__, __LINE__, op);

	for (i = 0; i < info->num_non_op_channels; i++) {
		snprintf(tmp, sizeof(tmp), "%d,", info->non_op_channel[i]);
	    snprintf(non_op_str + strlen(non_op_str), sizeof(non_op_str) - strlen(non_op_str), "%s", tmp);
    }

	non_op_str[strlen(non_op_str) - 1] = 0;

	switch (op) {
		case dm_orch_type_op_class_insert:
			ret = insert_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->id.ruid.mac, mac_str), 
						info->id.type, info->op_class, info->channel, info->tx_power, info->max_tx_power,
            			non_op_str); 
			break;

		case dm_orch_type_op_class_update:
			ret = update_row(db_client, info->id.type, info->op_class, info->channel, info->tx_power, info->max_tx_power,
						non_op_str, dm_easy_mesh_t::macbytes_to_string(info->id.ruid.mac, mac_str));
			break;

		case dm_orch_type_op_class_delete:
			ret = delete_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->id.ruid.mac, mac_str));
			break;

		default:
			break;
	}

    return ret;
}

void dm_op_class_list_t::sync_db(db_client_t& db_client, void *ctx)
{
	em_op_class_info_t info;
    em_long_string_t   str;
	mac_addr_str_t	mac_str;
	em_string_t	ch_str[EM_MAX_NON_OP_CHANNELS];
	char   *token_parts[EM_MAX_NON_OP_CHANNELS];
	unsigned int i;

    while (db_client.next_result(ctx)) {
		memset(&info, 0, sizeof(em_op_class_info_t));

		db_client.get_string(ctx, mac_str, 1);
		dm_easy_mesh_t::string_to_macbytes(mac_str, info.id.ruid.mac);

        info.id.type = (em_op_class_type_t)db_client.get_number(ctx, 2);
        info.op_class = db_client.get_number(ctx, 3);
        info.channel = db_client.get_number(ctx, 4);
        info.tx_power = db_client.get_number(ctx, 5);
        info.max_tx_power = db_client.get_number(ctx, 6);
        
		db_client.get_string(ctx, str, 7);
		for (i = 0; i < EM_MAX_NON_OP_CHANNELS; i++) {
			token_parts[i] = ch_str[i];
		}

		info.num_non_op_channels = get_strings_by_token(str, ',', EM_MAX_NON_OP_CHANNELS, token_parts);
		for (i = 0; i < info.num_non_op_channels; i++) {
			info.non_op_channel[i] = atoi(token_parts[i]);
		}
		
		update_list(dm_op_class_t(&info), dm_orch_type_op_class_insert);
    }
}

void dm_op_class_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "OperatingClasses");
}

void dm_op_class_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("Type", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("Class", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("Channel", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("TxPower", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("MaxTxPower", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("NonOperable", db_data_type_char, 64);
}

int dm_op_class_list_t::init()
{
	m_list = hash_map_create();
    init_table();
    init_columns();
    return 0;
}

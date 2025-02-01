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
#include "dm_easy_mesh_ctrl.h"
#include "dm_easy_mesh.h"
#include "dm_network_list.h"
#include "util.h"

int dm_network_list_t::get_config(cJSON *obj, void *net_id, bool summary)
{
    dm_network_t *pnet = NULL;
	
    pnet = get_network((char *)net_id);
    if (pnet == NULL) {
		printf("%s:%d: Network Object not found for key: %s\n", __func__, __LINE__, (char *)net_id);
		return -1;
    }
		
    pnet->encode(obj, summary);
	
    return 0;
}

int dm_network_list_t::set_config(db_client_t& db_client, dm_network_t& net, void *parent_id)
{
    dm_orch_type_t op;
    mac_addr_str_t  mac_str;	

    dm_easy_mesh_t::macbytes_to_string((unsigned char *)net.m_net_info.ctrl_id.mac, mac_str);

    //printf("%s:%d: Enter: networl: %s controller id:%s\n", __func__, __LINE__, net.m_net_info.id, mac_str);

    update_db(db_client, (op = get_dm_orch_type(db_client, net)), net.get_network_info());
    update_list(net, op);

    return 0;
}

int dm_network_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    cJSON *obj;
    unsigned int i, size;
    dm_network_t net;
    dm_orch_type_t op;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
        net.decode(obj, parent_id);
        update_db(db_client, (op = get_dm_orch_type(db_client, net)), net.get_network_info());
        update_list(net, op);
    }

    return 0;
}


dm_orch_type_t dm_network_list_t::get_dm_orch_type(db_client_t& db_client, const dm_network_t& net)
{
    dm_network_t *pnet;

    pnet = get_network(net.m_net_info.id);

    if (pnet != NULL) {
        if (entry_exists_in_table(db_client, (char *)net.m_net_info.id) == false) {
            return dm_orch_type_db_insert;
        }
        if (*pnet == net) {
            printf("%s:%d: Network: %s already in list\n", __func__, __LINE__, net.m_net_info.id);
            return dm_orch_type_none;
        }


        printf("%s:%d: Network: %s in list but needs update\n", __func__, __LINE__, net.m_net_info.id);
        return dm_orch_type_db_update;
    }

    return dm_orch_type_db_insert;
}


void dm_network_list_t::update_list(const dm_network_t& net, dm_orch_type_t op)
{
    dm_network_t *pnet;
    mac_addr_str_t  mac_str;

    dm_easy_mesh_t::macbytes_to_string((unsigned char *)net.m_net_info.colocated_agent_id.mac, mac_str);

    switch (op) {
        case dm_orch_type_db_insert:
            put_network(net.m_net_info.id, &net);
            break;

        case dm_orch_type_db_update:
            pnet = get_network(net.m_net_info.id);
            memcpy(&pnet->m_net_info, &net.m_net_info, sizeof(em_network_info_t));
            break;

        case dm_orch_type_db_delete:
            remove_network(net.m_net_info.id);
            break;
    }
}

void dm_network_list_t::delete_list()
{
    dm_network_t *pnet, *tmp;

    pnet = get_first_network();
    while (pnet != NULL) {
	tmp = pnet;
	pnet = get_next_network(pnet);	
        remove_network(tmp->m_net_info.id);	
    }
}

bool dm_network_list_t::operator == (const db_easy_mesh_t& obj)
{
    return true;
}

int dm_network_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    int ret = 0;
    mac_addr_str_t agent_str, ctrl_str;
    em_network_info_t *info = (em_network_info_t *)data;

    printf("dm_network_list_t:%s:%d: Operation: %s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(op));
	switch (op) {
		case dm_orch_type_db_insert:
			ret = insert_row(db_client, info->id, 
            			dm_easy_mesh_t::macbytes_to_string(info->ctrl_id.mac, ctrl_str), 
            			dm_easy_mesh_t::macbytes_to_string(info->colocated_agent_id.mac, agent_str), info->media);
			break;

		case dm_orch_type_db_update:
			ret = update_row(db_client,
            			dm_easy_mesh_t::macbytes_to_string(info->ctrl_id.mac, ctrl_str), 
            			dm_easy_mesh_t::macbytes_to_string(info->colocated_agent_id.mac, agent_str), info->media, info->id);
			break;

		case dm_orch_type_db_delete:
			ret = delete_row(db_client, (info == NULL) ? m_net_info.id:info->id);
			break;

		default:
			break;

	}

    return ret;
}

bool dm_network_list_t::search_db(db_client_t& db_client, void *ctx, void *key)
{
    em_string_t net_id;

    while (db_client.next_result(ctx)) {
        db_client.get_string(ctx, net_id, 1);

        if (strncmp(net_id, (char *)key, strlen((char *)key)) == 0) {
            return true;
        }
    }

    return false;
}

int dm_network_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    mac_addr_str_t	mac;
    em_network_info_t info;
    int rc = 0;
	char date_time[EM_DATE_TIME_BUFF_SZ];

	memset(&info, 0, sizeof(em_network_info_t));
	get_date_time_rfc3399(date_time, EM_DATE_TIME_BUFF_SZ);
	strncpy(info.timestamp, date_time, strlen(date_time) + 1);

    // there is only one row in network
    while (db_client.next_result(ctx)) {
		db_client.get_string(ctx, info.id, 1);
		db_client.get_string(ctx, mac, 2);
		dm_easy_mesh_t::string_to_macbytes(mac, info.ctrl_id.mac);

		db_client.get_string(ctx, mac, 3);
		dm_easy_mesh_t::string_to_macbytes(mac, info.colocated_agent_id.mac);

		info.media = (em_media_type_t)db_client.get_number(ctx, 4);

		update_list(dm_network_t(&info), dm_orch_type_db_insert);
    }
    return rc;
}

void dm_network_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "NetworkList");
}

void dm_network_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("ControllerID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("ColocatedAgentID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("Media", db_data_type_int, 0);
}

int dm_network_list_t::init()
{
    init_table();
    init_columns();

    return 0;
}

em_interface_t *dm_network_list_t::get_ctrl_al_interface(em_long_string_t net_id)
{
    dm_network_t *net;

    if ((net = get_network(net_id)) == NULL) {
	printf("%s:%d: Could not find network with id: %s\n", __func__, __LINE__, net_id);
	return NULL;
    }
	
    return net->get_colocated_agent_interface();	
}

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
#include "dm_easy_mesh_ctrl.h"
#include "dm_easy_mesh.h"
#include "dm_network_list.h"

int dm_network_list_t::get_config(cJSON *obj, void *parent_id)
{
	dm_network_t *pnet;
	
	pnet = (dm_network_t *)hash_map_get_first(m_list);
	while (pnet != NULL) {
		pnet->encode(obj);
		pnet = (dm_network_t *)hash_map_get_next(m_list, pnet);
	}
	
	return 0;
}

int dm_network_list_t::set_config(db_client_t& db_client, dm_network_t& net, void *parent_id)
{
	dm_orch_type_t op;
	mac_addr_str_t  mac_str;	

	dm_easy_mesh_t::macbytes_to_string((unsigned char *)net.m_net_info.ctrl_id.mac, mac_str);

	//printf("%s:%d: Enter: networl: %s controller id:%s\n", __func__, __LINE__, net.m_net_info.id, mac_str);

	update_db(db_client, (op = get_dm_orch_type(net)), net.get_network_info());
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
        update_db(db_client, (op = get_dm_orch_type(net)), net.get_network_info());
        update_list(net, op);
    }

    return 0;
}


dm_orch_type_t dm_network_list_t::get_dm_orch_type(const dm_network_t& net)
{
    dm_network_t *pnet;

    pnet = (dm_network_t *)hash_map_get(m_list, net.m_net_info.id);

    if (pnet != NULL) {
        if (*pnet == net) {
            printf("%s:%d: Network: %s already in list\n", __func__, __LINE__, net.m_net_info.id);
            return dm_orch_type_none;
        }


        printf("%s:%d: Network: %s in list but needs update\n", __func__, __LINE__, net.m_net_info.id);
        return dm_orch_type_net_update;
    }

    return dm_orch_type_net_insert;
}


void dm_network_list_t::update_list(const dm_network_t& net, dm_orch_type_t op)
{
    dm_network_t *pnet;
    mac_addr_str_t  mac_str;

    switch (op) {
        case dm_orch_type_net_insert:
            hash_map_put(m_list, strdup(net.m_net_info.id), new dm_network_t(net));
            break;

        case dm_orch_type_net_update:
            pnet = (dm_network_t *)hash_map_get(m_list, net.m_net_info.id);
            memcpy(&pnet->m_net_info, &net.m_net_info, sizeof(em_network_info_t));
            break;

        case dm_orch_type_net_delete:
            pnet = (dm_network_t *)hash_map_remove(m_list, net.m_net_info.id);
            delete(pnet);
            break;
    }
}

void dm_network_list_t::delete_list()
{
	dm_network_t *pnet, *tmp;

	pnet = (dm_network_t *)hash_map_get_first(m_list);
	while (pnet != NULL) {
		tmp = pnet;
		pnet = (dm_network_t *)hash_map_get_next(m_list, pnet);	
	
		hash_map_remove(m_list, tmp->m_net_info.id);	
		delete(tmp);
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

	//printf("%s:%d: Opeartion:%d\n", __func__, __LINE__, op);
	switch (op) {
		case dm_orch_type_net_insert:
			ret = insert_row(db_client, info->id, 
            			dm_easy_mesh_t::macbytes_to_string(info->ctrl_id.mac, ctrl_str), 
            			dm_easy_mesh_t::macbytes_to_string(info->colocated_agent_id.mac, agent_str));
			break;

		case dm_orch_type_net_update:
			ret = update_row(db_client,
            			dm_easy_mesh_t::macbytes_to_string(info->ctrl_id.mac, ctrl_str), 
            			dm_easy_mesh_t::macbytes_to_string(info->colocated_agent_id.mac, agent_str), info->id);
			break;

		case dm_orch_type_net_delete:
			ret = delete_row(db_client, (info == NULL) ? m_net_info.id:info->id);
			break;

		default:
			break;

	}

    return ret;
}

void dm_network_list_t::sync_db(db_client_t& db_client, void *ctx)
{
	mac_addr_str_t	mac;
	em_network_info_t info;


	// there is only one row in network
	while (db_client.next_result(ctx)) {
		db_client.get_string(ctx, info.id, 1);
		db_client.get_string(ctx, mac, 2);
		dm_easy_mesh_t::string_to_macbytes(mac, info.ctrl_id.mac);

		db_client.get_string(ctx, mac, 3);
		dm_easy_mesh_t::string_to_macbytes(mac, info.colocated_agent_id.mac);

		update_list(dm_network_t(&info), dm_orch_type_net_insert);
	}

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
}

int dm_network_list_t::init()
{
	m_list = hash_map_create();
    init_table();
    init_columns();

	return 0;
}

em_interface_t *dm_network_list_t::get_ctrl_al_interface(em_long_string_t net_id)
{
	dm_network_t *net;

	if ((net = (dm_network_t *)hash_map_get(m_list, net_id)) == NULL) {
		printf("%s:%d: Could not find network with id: %s\n", __func__, __LINE__, net_id);
		return NULL;
	}
	
	return net->get_colocated_agent_interface();	
}

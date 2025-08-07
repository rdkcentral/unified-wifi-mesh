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
#include "dm_neighbor_list.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_neighbor_list_t::get_config(cJSON *obj_arr, void *parent, bool summary)
{
    return 0;
}

int dm_neighbor_list_t::set_config(db_client_t& db_client, dm_neighbor_t& nbr, void *parent_id)
{
    dm_orch_type_t op;  

    //printf("%s:%d: Parent: %s \n", __func__, __LINE__, (char *)parent_id);

    update_db(db_client, (op = get_dm_orch_type(db_client, nbr)), nbr.get_neighbor_info());
    update_list(nbr, op);
                        
    return 0;
}

int dm_neighbor_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    cJSON *obj;
    int i, size;
    dm_neighbor_t nbr;
    dm_orch_type_t op;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
		nbr.decode(obj, parent_id);
		update_db(db_client, (op = get_dm_orch_type(db_client, nbr)), nbr.get_neighbor_info());
		update_list(nbr, op);
    }

    return 0;
}

dm_orch_type_t dm_neighbor_list_t::get_dm_orch_type(db_client_t& db_client, const dm_neighbor_t& nbr)
{
    dm_neighbor_t *pnbr;
    mac_addr_str_t  nbr_mac_str;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (nbr.m_neighbor_info.nbr), nbr_mac_str);

    pnbr = get_neighbor(nbr_mac_str);

    if (pnbr != NULL) {
        if (entry_exists_in_table(db_client, nbr_mac_str) == false) {
            return dm_orch_type_db_insert;
        }

        if (*pnbr == nbr) {
            return dm_orch_type_none;
        }


        return dm_orch_type_db_update;
    }

    return dm_orch_type_db_insert;
}


void dm_neighbor_list_t::update_list(const dm_neighbor_t& nbr, dm_orch_type_t op)
{
    dm_neighbor_t *pnbr;
    mac_addr_str_t	nbr_mac_str;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (nbr.m_neighbor_info.nbr), nbr_mac_str);

    switch (op) {
        case dm_orch_type_db_insert:
            put_neighbor(nbr_mac_str, &nbr);
            break;

        case dm_orch_type_db_update:
			pnbr = get_neighbor(nbr_mac_str);
            memcpy(&pnbr->m_neighbor_info, &nbr.m_neighbor_info, sizeof(em_neighbor_info_t));
            break;

        case dm_orch_type_db_delete:
            remove_neighbor(nbr_mac_str);            
            break;

		default:
			break;
    }

}

void dm_neighbor_list_t::delete_list()
{       
    dm_neighbor_t *pnbr, *tmp;
    mac_addr_str_t	nbr_mac_str;
    
    pnbr = get_first_neighbor();
    while (pnbr != NULL) {
        tmp = pnbr;
        pnbr = get_next_neighbor(pnbr);
    
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (tmp->m_neighbor_info.nbr), nbr_mac_str);

        remove_neighbor(nbr_mac_str);
    }
}   


bool dm_neighbor_list_t::operator == (const db_easy_mesh_t& obj)
{
    return true;
}

int dm_neighbor_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t nbr_mac_str, next_hop_mac_str;
    em_neighbor_info_t *info = static_cast<em_neighbor_info_t *> (data);
    int ret = 0;
        
	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (info->nbr), nbr_mac_str);
	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (info->next_hop), next_hop_mac_str);

    //printf("dm_neighbor_list_t:%s:%d: Operation: %s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(op));
	
	switch (op) {
		case dm_orch_type_db_insert:
			ret = insert_row(db_client, nbr_mac_str, info->pos_x, info->pos_y, info->pos_z, next_hop_mac_str,
						info->num_hops, info->path_loss);
							
			break;

		case dm_orch_type_db_update:
			ret = update_row(db_client, info->pos_x, info->pos_y, info->pos_z, next_hop_mac_str, info->num_hops,
						info->path_loss, nbr_mac_str);
			break;

		case dm_orch_type_db_delete:
			ret = delete_row(db_client, nbr_mac_str);
			break;

		default:
			break;
	}

    return ret;
}

bool dm_neighbor_list_t::search_db(db_client_t& db_client, void *ctx, void *key)
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

int dm_neighbor_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_neighbor_info_t info;
    mac_addr_str_t	mac;
    em_long_string_t   str;
    int rc = 0;

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_neighbor_info_t));

        db_client.get_string(ctx, str, 1);
		dm_easy_mesh_t::string_to_macbytes(str, info.nbr);

		info.pos_x = static_cast<float> (db_client.get_number(ctx, 2));
		info.pos_y = static_cast<float> (db_client.get_number(ctx, 3));
		info.pos_z = static_cast<float> (db_client.get_number(ctx, 4));
        
		db_client.get_string(ctx, mac, 5);
        dm_easy_mesh_t::string_to_macbytes(mac, info.next_hop);

        info.num_hops = static_cast<unsigned int> (db_client.get_number(ctx, 6));
        info.path_loss = db_client.get_number(ctx, 7);

        update_list(dm_neighbor_t(&info), dm_orch_type_db_insert);
    }

    return rc;

}

void dm_neighbor_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "NeighborList");
}

void dm_neighbor_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("Neighbor", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("Pos_X", db_data_type_float, 0);
    m_columns[m_num_cols++] = db_column_t("Pos_Y", db_data_type_float, 0);
    m_columns[m_num_cols++] = db_column_t("Pos_Z", db_data_type_float, 0);
    m_columns[m_num_cols++] = db_column_t("NextHop", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("NumHops", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("PathLoss", db_data_type_int, 0);
}

int dm_neighbor_list_t::init()
{
    init_table();
    init_columns();
    return 0;
}

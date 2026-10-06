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

// macbytes_to_string() takes a non-const mac_address_t, which would force a const_cast at
// every call site here; format locally so the const qualifiers survive.
static void mac_to_text(const unsigned char *mac, mac_addr_str_t out)
{
    snprintf(out, sizeof(mac_addr_str_t), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void dm_neighbor_list_t::make_key(const em_neighbor_info_t *info, em_long_string_t key)
{
    mac_addr_str_t dev_mac_str, local_mac_str, nbr_mac_str;

    mac_to_text(info->dev_al_mac, dev_mac_str);
    mac_to_text(info->local_iface_mac, local_mac_str);
    mac_to_text(info->nbr, nbr_mac_str);

    snprintf(key, sizeof(em_long_string_t), "%s@%s@%s@%d", dev_mac_str, local_mac_str, nbr_mac_str,
            info->is_ieee1905neighbor);
}

int dm_neighbor_list_t::get_config(cJSON *obj_arr, void *parent, bool summary)
{
    return 0;
}

int dm_neighbor_list_t::set_config(db_client_t& db_client, dm_neighbor_t& nbr, void *parent_id)
{
    dm_orch_type_t op;  
    int ret;

    //printf("%s:%d: Parent: %s \n", __func__, __LINE__, (char *)parent_id);

    ret = update_db(db_client, (op = get_dm_orch_type(db_client, nbr)), nbr.get_neighbor_info());
    if (ret != 0) {
        return ret;
    }
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
		if (update_db(db_client, (op = get_dm_orch_type(db_client, nbr)), nbr.get_neighbor_info()) != 0) {
			return -1;
		}
		update_list(nbr, op);
    }

    return 0;
}

dm_orch_type_t dm_neighbor_list_t::get_dm_orch_type(db_client_t& db_client, const dm_neighbor_t& nbr)
{
    dm_neighbor_t *pnbr;
    em_long_string_t key;

    make_key(&nbr.m_neighbor_info, key);

    pnbr = get_neighbor(key);

    if (pnbr != NULL) {
        if (row_exists(db_client, &nbr.m_neighbor_info) == false) {
            return dm_orch_type_db_insert;
        }

        if (*pnbr == nbr) {
            return dm_orch_type_none;
        }


        return dm_orch_type_db_update;
    }

    return dm_orch_type_db_insert;
}

bool dm_neighbor_list_t::row_exists(db_client_t& db_client, const em_neighbor_info_t *info)
{
    em_2xlong_string_t where;
    db_query_t query;
    void *ctx;

    make_where_clause(info, where);
    snprintf(query, sizeof(db_query_t), "select 1 from %s where %s limit 1", m_table_name, where);

    if ((ctx = db_client.execute(query)) == NULL) {
        return false;
    }

    // next_result() releases ctx itself when the row is absent.
    if (db_client.next_result(ctx) == false) {
        return false;
    }

    db_client.free_result(ctx);

    return true;
}


void dm_neighbor_list_t::update_list(const dm_neighbor_t& nbr, dm_orch_type_t op)
{
    dm_neighbor_t *pnbr;
    em_long_string_t key;

    make_key(&nbr.m_neighbor_info, key);

    switch (op) {
        case dm_orch_type_db_insert:
            put_neighbor(key, &nbr);
            break;

        case dm_orch_type_db_update:
			pnbr = get_neighbor(key);
            if (pnbr != NULL) {
                memcpy(&pnbr->m_neighbor_info, &nbr.m_neighbor_info, sizeof(em_neighbor_info_t));
            } else {
                put_neighbor(key, &nbr);
            }
            break;

        case dm_orch_type_db_delete:
            remove_neighbor(key);
            break;

		default:
			break;
    }

}

void dm_neighbor_list_t::delete_list()
{       
    dm_neighbor_t *pnbr, *tmp;
    em_long_string_t key;
    
    pnbr = get_first_neighbor();
    while (pnbr != NULL) {
        tmp = pnbr;
        pnbr = get_next_neighbor(pnbr);
    
        make_key(&tmp->m_neighbor_info, key);

        remove_neighbor(key);
    }
}   


bool dm_neighbor_list_t::operator == (const db_easy_mesh_t& obj)
{
    return true;
}

int dm_neighbor_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t nbr_mac_str, next_hop_mac_str, local_iface_mac_str, dev_al_mac_str;
    em_neighbor_info_t *info = static_cast<em_neighbor_info_t *> (data);
    em_2xlong_string_t where;
    db_query_t query;
    int ret = 0;
        
	mac_to_text(info->nbr, nbr_mac_str);
	mac_to_text(info->next_hop, next_hop_mac_str);
	mac_to_text(info->local_iface_mac, local_iface_mac_str);
	mac_to_text(info->dev_al_mac, dev_al_mac_str);

    //printf("dm_neighbor_list_t:%s:%d: Operation: %s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(op));
	
	switch (op) {
		case dm_orch_type_db_insert:
			ret = insert_row(db_client, dev_al_mac_str, nbr_mac_str, local_iface_mac_str,
					static_cast<int>(info->is_ieee1905neighbor), info->pos_x, info->pos_y, info->pos_z,
					next_hop_mac_str, info->num_hops, info->path_loss);
			break;

		case dm_orch_type_db_update:
			make_where_clause(info, where);
			snprintf(query, sizeof(db_query_t),
				"update %s set Pos_X = %f, Pos_Y = %f, Pos_Z = %f, "
				"NextHop = '%02x:%02x:%02x:%02x:%02x:%02x', NumHops = %d, PathLoss = %d where %s",
				m_table_name, info->pos_x, info->pos_y, info->pos_z,
				info->next_hop[0], info->next_hop[1], info->next_hop[2],
				info->next_hop[3], info->next_hop[4], info->next_hop[5],
				info->num_hops, info->path_loss, where);
			db_client.free_result(db_client.execute(query));
			break;

		case dm_orch_type_db_delete:
			make_where_clause(info, where);
			snprintf(query, sizeof(db_query_t), "delete from %s where %s", m_table_name, where);
			db_client.free_result(db_client.execute(query));
			break;

		default:
			break;
	}

    return ret;
}

// MACs are emitted from the raw bytes rather than via macbytes_to_string() so the
// clause can only ever contain hex digits and colons.
void dm_neighbor_list_t::make_where_clause(const em_neighbor_info_t *info, em_2xlong_string_t where)
{
    const unsigned char *dev = info->dev_al_mac;
    const unsigned char *nbr = info->nbr;
    const unsigned char *iface = info->local_iface_mac;

    snprintf(where, sizeof(em_2xlong_string_t),
        "DeviceALID = '%02x:%02x:%02x:%02x:%02x:%02x' and "
        "Neighbor = '%02x:%02x:%02x:%02x:%02x:%02x' and "
        "LocalInterface = '%02x:%02x:%02x:%02x:%02x:%02x' and Is1905Neighbor = %d",
        dev[0], dev[1], dev[2], dev[3], dev[4], dev[5],
        nbr[0], nbr[1], nbr[2], nbr[3], nbr[4], nbr[5],
        iface[0], iface[1], iface[2], iface[3], iface[4], iface[5],
        info->is_ieee1905neighbor ? 1 : 0);
}

bool dm_neighbor_list_t::search_db(db_client_t& db_client, void *ctx, void *key)
{
    mac_addr_str_t dev_mac_str, nbr_mac_str, local_mac_str;
    em_long_string_t row_key;
    int is_1905;

    // next_result() releases ctx itself once the rows are exhausted.
    while (db_client.next_result(ctx)) {
        db_client.get_string(ctx, dev_mac_str, 1);
        db_client.get_string(ctx, nbr_mac_str, 2);
        db_client.get_string(ctx, local_mac_str, 3);
        is_1905 = db_client.get_number(ctx, 4);

        snprintf(row_key, sizeof(em_long_string_t), "%s@%s@%s@%d", dev_mac_str, local_mac_str,
                nbr_mac_str, is_1905);

        if (strcmp(row_key, static_cast<char *> (key)) == 0) {
            db_client.free_result(ctx);
            return true;
        }
    }

    return false;
}

int dm_neighbor_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_neighbor_info_t info;
    mac_addr_str_t	mac;
    int rc = 0;

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_neighbor_info_t));

        db_client.get_string(ctx, mac, 1);
        dm_easy_mesh_t::string_to_macbytes(mac, info.dev_al_mac);

        db_client.get_string(ctx, mac, 2);
		dm_easy_mesh_t::string_to_macbytes(mac, info.nbr);

        db_client.get_string(ctx, mac, 3);
        dm_easy_mesh_t::string_to_macbytes(mac, info.local_iface_mac);

        info.is_ieee1905neighbor = (db_client.get_number(ctx, 4) != 0);

		info.pos_x = static_cast<float> (db_client.get_number(ctx, 5));
		info.pos_y = static_cast<float> (db_client.get_number(ctx, 6));
		info.pos_z = static_cast<float> (db_client.get_number(ctx, 7));
        
		db_client.get_string(ctx, mac, 8);
        dm_easy_mesh_t::string_to_macbytes(mac, info.next_hop);

        info.num_hops = static_cast<unsigned int> (db_client.get_number(ctx, 9));
        info.path_loss = db_client.get_number(ctx, 10);

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

    m_columns[m_num_cols++] = db_column_t("DeviceALID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("Neighbor", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("LocalInterface", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("Is1905Neighbor", db_data_type_tinyint, 0);
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

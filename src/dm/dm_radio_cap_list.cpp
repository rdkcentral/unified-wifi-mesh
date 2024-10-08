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
#include "dm_radio_cap_list.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_radio_cap_list_t::get_config(cJSON *obj_parent, void *parent, bool summary)
{
    dm_radio_cap_t *pradio_cap;
    cJSON *obj;

    pradio_cap = (dm_radio_cap_t *)hash_map_get_first(m_list);
    while (pradio_cap != NULL) {
        obj = cJSON_CreateObject(); 

        //cJSON_AddStringToObject(obj, "HTCapabilities", pradio_cap->m_radio_cap_info.ht_cap);
        //cJSON_AddStringToObject(obj, "VHTCapabilities", pradio_cap->m_radio_cap_info.vht_cap);
        //cJSON_AddStringToObject(obj, "HECapabilities", pradio_cap->m_radio_cap_info.he_cap);
        //cJSON_AddStringToObject(obj, "EHTCapabilities", pradio_cap->m_radio_cap_info.eht_cap);
        //cJSON_AddNumberToObject(obj, "NumberOfOpClass", pradio_cap->m_radio_cap_info.num_op_classes);
        //cJSON_AddObjectToObject(obj, obj_parent);
        pradio_cap = (dm_radio_cap_t *)hash_map_get_next(m_list, pradio_cap);
    }


    return 0;
}

int dm_radio_cap_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    cJSON *obj;
    unsigned int i, size;
    dm_radio_cap_t radio_cap;
    dm_orch_type_t	op;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
        radio_cap.decode(obj, parent_id);
        update_db(db_client, (op = get_dm_orch_type(db_client, radio_cap)), radio_cap.get_radio_cap_info());
        update_list(radio_cap, op);
    }

    return 0;
}


dm_orch_type_t dm_radio_cap_list_t::get_dm_orch_type(db_client_t& db_client, const dm_radio_cap_t& radio_cap)
{
    dm_radio_cap_t *pradio_cap;
    mac_addr_str_t  mac_str;

    dm_easy_mesh_t::macbytes_to_string((unsigned char *)radio_cap.m_radio_cap_info.ruid.mac, mac_str);

    pradio_cap = (dm_radio_cap_t *)hash_map_get(m_list, mac_str);
    if (pradio_cap != NULL) {
        if (*pradio_cap == radio_cap) {
            printf("%s:%d: Device: %s in list\n", __func__, __LINE__,
                    dm_easy_mesh_t::macbytes_to_string(pradio_cap->m_radio_cap_info.ruid.mac, mac_str));
            return dm_orch_type_none;
        }


        printf("%s:%d: Device: %s in list but needs update\n", __func__, __LINE__,
                dm_easy_mesh_t::macbytes_to_string(pradio_cap->m_radio_cap_info.ruid.mac, mac_str));
        return dm_orch_type_cap_update;
    }

    return dm_orch_type_cap_insert;

}

void dm_radio_cap_list_t::update_list(const dm_radio_cap_t& radio_cap, dm_orch_type_t op)
{
    dm_radio_cap_t *pradio_cap;
    mac_addr_str_t	mac_str;

    dm_easy_mesh_t::macbytes_to_string((unsigned char *)radio_cap.m_radio_cap_info.ruid.mac, mac_str);

    switch (op) {
        case dm_orch_type_cap_insert:
            hash_map_put(m_list, strdup(mac_str), new dm_radio_cap_t(radio_cap));	
            break;

        case dm_orch_type_cap_update:
            pradio_cap = (dm_radio_cap_t *)hash_map_get(m_list, mac_str);
            memcpy(&pradio_cap->m_radio_cap_info, &radio_cap.m_radio_cap_info, sizeof(em_radio_cap_info_t));
            break;

        case dm_orch_type_cap_delete:
            pradio_cap = (dm_radio_cap_t *)hash_map_remove(m_list, mac_str);
            delete(pradio_cap);
            break;
    }

}

void dm_radio_cap_list_t::delete_list()
{       
    dm_radio_cap_t *pradio_cap, *tmp;
    mac_addr_str_t  mac_str = {0};

    pradio_cap = (dm_radio_cap_t *)hash_map_get_first(m_list);
    while (pradio_cap != NULL) {
        tmp = pradio_cap;
        pradio_cap = (dm_radio_cap_t *)hash_map_get_next(m_list, pradio_cap);
        dm_easy_mesh_t::macbytes_to_string((unsigned char *)tmp->m_radio_cap_info.ruid.mac, mac_str);

        hash_map_remove(m_list, mac_str);
        delete(tmp);
    }
}

bool dm_radio_cap_list_t::operator == (const db_easy_mesh_t& obj)
{
    return true;
}

int dm_radio_cap_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t mac_str;
    em_radio_cap_info_t *info = (em_radio_cap_info_t *)data;
    int ret = 0;
    unsigned int i;

    printf("%s:%d: Opeartion:%d\n", __func__, __LINE__, op);

    switch (op) {
        case dm_orch_type_cap_insert:
            ret = insert_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->ruid.mac, mac_str), 
                    info->ht_cap, info->vht_cap, info->he_cap, info->eht_cap, info->num_op_classes);
            break;

        case dm_orch_type_cap_update:
            ret = update_row(db_client, info->ht_cap, info->vht_cap, info->he_cap, info->eht_cap, info->num_op_classes,
                    dm_easy_mesh_t::macbytes_to_string(info->ruid.mac, mac_str));
            break;

        case dm_orch_type_cap_delete:
            ret = delete_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->ruid.mac, mac_str));
            break;

        default:
            break;
    }

    return ret;
}

bool dm_radio_cap_list_t::search_db(db_client_t& db_client, void *ctx, void *key)
{
    return false;
}

int dm_radio_cap_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_radio_cap_info_t info;
    mac_addr_str_t	mac_str;
    int rc = 0;

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_radio_cap_info_t));

        db_client.get_string(ctx, mac_str, 1);
        dm_easy_mesh_t::string_to_macbytes(mac_str, info.ruid.mac);

        //db_client.get_string(ctx, info.ht_cap, 2);
        //db_client.get_string(ctx, info.vht_cap, 3);
        //db_client.get_string(ctx, info.he_cap, 4);
        //db_client.get_string(ctx, info.eht_cap, 5);

        update_list(dm_radio_cap_t(&info), dm_orch_type_cap_insert);
    }
    return rc;
}

void dm_radio_cap_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "Capabilities");
}

void dm_radio_cap_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("HTCapabilities", db_data_type_char, 255);
    m_columns[m_num_cols++] = db_column_t("VHTCapabilities", db_data_type_char, 255);
    m_columns[m_num_cols++] = db_column_t("HECapabilities", db_data_type_char, 255);
    m_columns[m_num_cols++] = db_column_t("EHTCapabilities", db_data_type_char, 255);
    m_columns[m_num_cols++] = db_column_t("NumberOfOpClass", db_data_type_tinyint, 0);
}

int dm_radio_cap_list_t::init()
{
    m_list = hash_map_create();
    init_table();
    init_columns();
    return 0;
}

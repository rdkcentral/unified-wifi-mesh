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
#include "dm_csi_container_list.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_csi_container_list_t::get_data(cJSON *parent, void *key)
{
    em_csi_container_id_t id;
    dm_csi_container_t *cont = NULL;
    cJSON *obj;
    mac_addr_t null_mac = {0};
    bool get_all = false;

    dm_csi_container_t::parse_csi_container_id_from_key((char *)key, &id);
    if (memcmp(id.sounding_mac, null_mac, sizeof(mac_address_t)) == 0) {
        get_all = true;
    }

    cont = get_first_csi_container();
    while (cont != NULL) {
        if (memcmp(cont->m_csi_container.id.dev_mac, id.dev_mac, sizeof(mac_address_t)) == 0) {
            if (get_all == true) {
                obj = cJSON_CreateObject();
                cont->encode_data(obj);
                cJSON_AddItemToArray(parent, obj);
            } else if (memcmp(cont->m_csi_container.id.sounding_mac, id.sounding_mac, sizeof(mac_address_t)) == 0) {
                obj = cJSON_CreateObject();
                cont->encode_data(obj);
                cJSON_AddItemToArray(parent, obj);
            }
        }

        cont = get_next_csi_container(cont);
    }

    return 0;
}

int dm_csi_container_list_t::get_config(cJSON *obj_arr, void *parent)
{
    return 0;
}

int dm_csi_container_list_t::get_config(cJSON *obj_arr, void *parent, bool summary)
{
    dm_csi_container_t *cont = NULL;
    cJSON *obj;
    mac_address_t parent_mac = {0};

    if (parent != NULL) {
        dm_easy_mesh_t::string_to_macbytes((char *)parent, parent_mac);
    }

    cont = get_first_csi_container();
    while (cont != NULL) {
        if (memcmp(cont->m_csi_container.id.sounding_mac, cont->m_csi_container.id.dev_mac, sizeof(mac_address_t)) != 0) {
            cont = get_next_csi_container(cont);
            continue;
        }

        obj = cJSON_CreateObject();
        cont->encode(obj);

        cJSON_AddItemToArray(obj_arr, obj);
        cont = get_next_csi_container(cont);
    }

    return 0;
}

int dm_csi_container_list_t::analyze_config(const cJSON *obj_arr, void *parent_id, em_cmd_t *pcmd[], em_cmd_params_t *param)
{
    printf("%s:%d: Enter\n", __func__, __LINE__);

    return 0;
}

dm_orch_type_t dm_csi_container_list_t::get_dm_orch_type(db_client_t& db_client, const dm_csi_container_t& csi_container)
{
    return dm_orch_type_db_insert;
}

void dm_csi_container_list_t::update_list(const dm_csi_container_t& csi_container, dm_orch_type_t op)
{

}

void dm_csi_container_list_t::delete_list()
{
       
}   

int dm_csi_container_list_t::load_data()
{
    return 0;
}

int dm_csi_container_list_t::init()
{
    return 0;
}

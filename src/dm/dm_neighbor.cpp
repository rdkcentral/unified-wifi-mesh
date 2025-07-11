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
#include "dm_neighbor.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_neighbor_t::decode(const cJSON *obj, void *parent_id)
{
    cJSON *tmp, *tmp_arr;
    mac_addr_str_t  mac_str;
    unsigned int i;

    memset(&m_neighbor_info, 0, sizeof(em_neighbor_info_t));

    if ((tmp = cJSON_GetObjectItem(obj, "Neighbor")) != NULL) {
		snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
		dm_easy_mesh_t::string_to_macbytes(mac_str, m_neighbor_info.nbr);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "POS_I")) != NULL) {
        m_neighbor_info.pos_x = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "POS_J")) != NULL) {
        m_neighbor_info.pos_y = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "POS_K")) != NULL) {
        m_neighbor_info.pos_z = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "NextHop")) != NULL) {
		snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
		dm_easy_mesh_t::string_to_macbytes(mac_str, m_neighbor_info.next_hop);
    }
    
	if ((tmp = cJSON_GetObjectItem(obj, "NumHops")) != NULL) {
        m_neighbor_info.num_hops = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "PathLoss")) != NULL) {
        m_neighbor_info.path_loss = tmp->valuedouble;
    }

    return 0;

}

void dm_neighbor_t::encode(cJSON *obj, bool summary)
{
    mac_addr_str_t  mac_str;

	dm_easy_mesh_t::macbytes_to_string(m_neighbor_info.nbr, mac_str);
    cJSON_AddStringToObject(obj, "Neighbor", mac_str);
    
    cJSON_AddNumberToObject(obj, "POS_X", m_neighbor_info.pos_x);
    cJSON_AddNumberToObject(obj, "POS_Y", m_neighbor_info.pos_y);
    cJSON_AddNumberToObject(obj, "POS_Z", m_neighbor_info.pos_z);

	dm_easy_mesh_t::macbytes_to_string(m_neighbor_info.next_hop, mac_str);
    cJSON_AddStringToObject(obj, "NextHop", mac_str);
    
    cJSON_AddNumberToObject(obj, "NumHops", m_neighbor_info.num_hops);
    cJSON_AddNumberToObject(obj, "PathLoss", m_neighbor_info.path_loss);

}

void dm_neighbor_t::operator = (const dm_neighbor_t& obj)
{
	if (this == &obj) { return; }
	
	memcpy(this->m_neighbor_info.nbr, obj.m_neighbor_info.nbr, sizeof(mac_address_t));
	this->m_neighbor_info.pos_x = obj.m_neighbor_info.pos_x;
	this->m_neighbor_info.pos_y = obj.m_neighbor_info.pos_y;
	this->m_neighbor_info.pos_z = obj.m_neighbor_info.pos_z;
	memcpy(this->m_neighbor_info.next_hop, obj.m_neighbor_info.next_hop, sizeof(mac_address_t));
	this->m_neighbor_info.num_hops = obj.m_neighbor_info.num_hops;
	this->m_neighbor_info.path_loss = obj.m_neighbor_info.path_loss;

}


bool dm_neighbor_t::operator == (const dm_neighbor_t& obj)
{
	int ret = 0;

	ret += (memcmp(this->m_neighbor_info.nbr, obj.m_neighbor_info.nbr, sizeof(mac_address_t)) != 0);
    ret += !(this->m_neighbor_info.pos_x == obj.m_neighbor_info.pos_x);
    ret += !(this->m_neighbor_info.pos_y == obj.m_neighbor_info.pos_y);
    ret += !(this->m_neighbor_info.pos_z == obj.m_neighbor_info.pos_z);
	ret += (memcmp(this->m_neighbor_info.next_hop, obj.m_neighbor_info.next_hop, sizeof(mac_address_t)) != 0);
    ret += !(this->m_neighbor_info.num_hops == obj.m_neighbor_info.num_hops);
    ret += !(this->m_neighbor_info.path_loss == obj.m_neighbor_info.path_loss);

    if (ret > 0)
        return false;
    else
        return true;
}

dm_neighbor_t::dm_neighbor_t(em_neighbor_info_t *bss)
{
    memcpy(&m_neighbor_info, bss, sizeof(em_neighbor_info_t));
}

dm_neighbor_t::dm_neighbor_t(const dm_neighbor_t& bss)
{
	memcpy(&m_neighbor_info, &bss.m_neighbor_info, sizeof(em_neighbor_info_t));
}

dm_neighbor_t::dm_neighbor_t()
{

}

dm_neighbor_t::~dm_neighbor_t()
{

}

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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include "dm_csi_container.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"
#include "util.h"

int dm_csi_container_t::decode(const cJSON *obj, void *parent_id)
{

    return 0;
}

void dm_csi_container_t::encode_data(cJSON *obj)
{
	mac_addr_str_t mac_str;
	cJSON *cov_arr, *cov_row, *cov_col;
        cJSON *csi_obj, *csi_info;
	unsigned int i, j;

	dm_easy_mesh_t::macbytes_to_string(m_csi_container.id.sounding_mac, mac_str);
	cJSON_AddStringToObject(obj, "MACAddress", mac_str);
	csi_obj = cJSON_AddArrayToObject(obj, "CsiData");
        csi_info = cJSON_CreateObject();
        cJSON_AddNumberToObject(csi_info, "Angle", m_csi_container.angle);
        cJSON_AddNumberToObject(csi_info, "Distance", m_csi_container.distance);
        cJSON_AddItemToArray(csi_obj, csi_info);
}

void dm_csi_container_t::encode(cJSON *obj)
{
	mac_addr_str_t mac_str;

	dm_easy_mesh_t::macbytes_to_string(m_csi_container.id.sounding_mac, mac_str);
	cJSON_AddStringToObject(obj, "MACAddress", mac_str);
}

bool dm_csi_container_t::operator == (const dm_csi_container_t& obj)
{

}

void dm_csi_container_t::operator = (const dm_csi_container_t& obj)
{
	memcpy(&m_csi_container, &obj.m_csi_container, sizeof(em_csi_container_t));
}

int dm_csi_container_t::parse_csi_container_id_from_key(const char *key, em_csi_container_id_t *id)
{
    em_long_string_t   str;
    char *tmp, *remain;
    unsigned int i = 0;

    strncpy(str, key, strlen(key) + 1);
    remain = str;
    while ((tmp = strchr(remain, '@')) != NULL) {
        if (i == 0) {
            *tmp = 0;
            strncpy(id->net_id, remain, strlen(remain) + 1);
            tmp++;  
            remain = tmp;
        } else if (i == 1) {
            *tmp = 0;
            dm_easy_mesh_t::string_to_macbytes(remain, id->dev_mac);
            tmp++;
            dm_easy_mesh_t::string_to_macbytes(tmp, id->sounding_mac);
        }  
        i++;
    }

    return 0;
}

dm_csi_container_t::dm_csi_container_t(em_csi_container_t *cont)
{
    memcpy(&m_csi_container, cont, sizeof(em_csi_container_t));
}

dm_csi_container_t::dm_csi_container_t(const dm_csi_container_t& cont)
{
    memcpy(&m_csi_container, &cont.m_csi_container, sizeof(em_csi_container_t));
}

dm_csi_container_t::dm_csi_container_t()
{

}

dm_csi_container_t::~dm_csi_container_t()
{

}

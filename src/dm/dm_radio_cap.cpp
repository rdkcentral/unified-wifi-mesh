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
#include "dm_radio_cap.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"
#include "util.h"

int dm_radio_cap_t::decode(const cJSON *obj, void *parent_id)
{
    cJSON *tmp;
    unsigned int i;
    em_interface_t	*id = static_cast<em_interface_t *>(parent_id);
    
    memset(&m_radio_cap_info, 0, sizeof(em_radio_cap_info_t));

    memcpy(m_radio_cap_info.ruid.mac, id->mac, sizeof(mac_address_t));

/*
    if ((tmp = cJSON_GetObjectItem(obj, "HTCapabilities")) != NULL) {
		strncpy(m_radio_cap_info.ht_cap, cJSON_GetStringValue(tmp), strlen(cJSON_GetStringValue(tmp)));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "VHTCapabilities")) != NULL) {
		strncpy(m_radio_cap_info.vht_cap, cJSON_GetStringValue(tmp), strlen(cJSON_GetStringValue(tmp)));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "HECapabilities")) != NULL) {
		strncpy(m_radio_cap_info.he_cap, cJSON_GetStringValue(tmp), strlen(cJSON_GetStringValue(tmp)));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "EHTCapabilities")) != NULL) {
		strncpy(m_radio_cap_info.eht_cap, cJSON_GetStringValue(tmp), strlen(cJSON_GetStringValue(tmp)));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "NumberOfOpClass")) != NULL) {
        m_radio_cap_info.num_op_classes = tmp->valuedouble;
    }
*/

   return 0;

}

void dm_radio_cap_t::encode(cJSON *obj)
{
    unsigned int i;
/*
    cJSON_AddNumberToObject(obj, "NumberOfOpClass", m_radio_cap_info.num_op_classes);
    cJSON_AddStringToObject(obj, "HTCapabilities", m_radio_cap_info.ht_cap);
    cJSON_AddStringToObject(obj, "VHTCapabilities", m_op_class_info.m_radio_cap_info.vht_cap);
    cJSON_AddStringToObject(obj, "HECapabilities", m_radio_cap_info.he_cap);
    cJSON_AddStringToObject(obj, "EHTCapabilities", m_radio_cap_info.eht_cap);
*/
}

bool dm_radio_cap_t::operator == (const dm_radio_cap_t& obj)
{
    int ret = 0;
    ret += (memcmp(&this->m_radio_cap_info.ruid.mac ,&obj.m_radio_cap_info.ruid.mac,sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_radio_cap_info.ruid.name,&obj.m_radio_cap_info.ruid.name,sizeof(em_interface_name_t)) != 0);
     ret += (memcmp(&this->m_radio_cap_info.ht_cap,&obj.m_radio_cap_info.ht_cap,sizeof(m_radio_cap_info.ht_cap)) != 0);
     ret += (memcmp(&this->m_radio_cap_info.vht_cap,&obj.m_radio_cap_info.vht_cap,sizeof(m_radio_cap_info.vht_cap)) != 0);
     ret += (memcmp(&this->m_radio_cap_info.he_cap,&obj.m_radio_cap_info.he_cap,sizeof(m_radio_cap_info.he_cap)) != 0);
     ret += (memcmp(&this->m_radio_cap_info.eht_cap,&obj.m_radio_cap_info.eht_cap,sizeof(em_long_string_t)) != 0);
     ret += !(this->m_radio_cap_info.num_op_classes == obj.m_radio_cap_info.num_op_classes);
   
     //em_util_info_print(EM_MGR, "%s:%d: MUH ret=%d\n", __func__, __LINE__,ret);

     if (ret > 0)
        return false;
    else
        return true;

}

void dm_radio_cap_t::operator = (const dm_radio_cap_t& obj)
{
    if (this == &obj) { return; }
    memcpy(&this->m_radio_cap_info.ruid.mac ,&obj.m_radio_cap_info.ruid.mac,sizeof(mac_address_t));
    memcpy(&this->m_radio_cap_info.ruid.name,&obj.m_radio_cap_info.ruid.name,sizeof(em_interface_name_t));
    memcpy(&this->m_radio_cap_info.ht_cap,&obj.m_radio_cap_info.ht_cap,sizeof(m_radio_cap_info.ht_cap));
    memcpy(&this->m_radio_cap_info.vht_cap,&obj.m_radio_cap_info.vht_cap,sizeof(m_radio_cap_info.vht_cap));
    memcpy(&this->m_radio_cap_info.he_cap,&obj.m_radio_cap_info.he_cap,sizeof(m_radio_cap_info.he_cap));
    memcpy(&this->m_radio_cap_info.eht_cap,&obj.m_radio_cap_info.eht_cap,sizeof(em_long_string_t));
    this->m_radio_cap_info.num_op_classes = obj.m_radio_cap_info.num_op_classes;

}

dm_radio_cap_t::dm_radio_cap_t(em_radio_cap_info_t *radio_cap)
{
    memcpy(&m_radio_cap_info, radio_cap, sizeof(em_radio_cap_info_t));
}

dm_radio_cap_t::dm_radio_cap_t(const dm_radio_cap_t& radio_cap)
{
	memcpy(&m_radio_cap_info, &radio_cap.m_radio_cap_info, sizeof(em_radio_cap_info_t));
}

dm_radio_cap_t::dm_radio_cap_t()
{

}

dm_radio_cap_t::~dm_radio_cap_t()
{

}

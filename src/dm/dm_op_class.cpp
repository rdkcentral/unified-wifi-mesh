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
#include "dm_op_class.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_op_class_t::decode(const cJSON *obj, void *parent_id)
{
    cJSON *tmp, *non_op_array;
    unsigned int i;

    memset(&m_op_class_info, 0, sizeof(em_op_class_info_t));
    dm_op_class_t::parse_op_class_id_from_key((char *)parent_id, &m_op_class_info.id);
	
    if ((tmp = cJSON_GetObjectItem(obj, "Class")) != NULL) {
        m_op_class_info.op_class = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "Channel")) != NULL) {
        m_op_class_info.channel = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "TxPower")) != NULL) {
        m_op_class_info.tx_power = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "MaxTxPower")) != NULL) {
       m_op_class_info.max_tx_power = tmp->valuedouble;
    }
    
    m_op_class_info.num_non_op_channels = 0;
    if ((non_op_array = cJSON_GetObjectItem(obj, "NonOperable")) != NULL) {
        m_op_class_info.num_non_op_channels = cJSON_GetArraySize(non_op_array);
        for (i = 0; i < m_op_class_info.num_non_op_channels; i++) {
            if ((tmp = cJSON_GetArrayItem(non_op_array, i)) != NULL) {
                m_op_class_info.non_op_channel[i] = tmp->valuedouble;
            }
        }
    }

    return 0;

}

void dm_op_class_t::encode(cJSON *obj)
{
    unsigned int i;

    cJSON_AddNumberToObject(obj, "NumberOfNonOperChan", m_op_class_info.num_non_op_channels);
    cJSON_AddNumberToObject(obj, "Class", m_op_class_info.op_class);
    cJSON_AddNumberToObject(obj, "MaxTxPower", m_op_class_info.max_tx_power);
    cJSON_AddNumberToObject(obj, "TxPower", m_op_class_info.tx_power);
    cJSON_AddNumberToObject(obj, "Channel", m_op_class_info.channel);

    cJSON *non_op_array = cJSON_CreateArray();

    for (i = 0; i < m_op_class_info.num_non_op_channels; i++) {
        cJSON_AddItemToArray(non_op_array, cJSON_CreateNumber(m_op_class_info.non_op_channel[i]));
    }
    // Add the array to the object
    cJSON_AddItemToObject(obj, "NonOperable", non_op_array);

}

bool dm_op_class_t::operator == (const dm_op_class_t& obj)
{
    int ret = 0;
    ret += (memcmp(&this->m_op_class_info.id.ruid ,&obj.m_op_class_info.id.ruid,sizeof(mac_address_t)) != 0);
    ret += !(this->m_op_class_info.id.type == obj.m_op_class_info.id.type);
    ret += !(this->m_op_class_info.id.index == obj.m_op_class_info.id.index);
    ret += !(this->m_op_class_info.op_class == obj.m_op_class_info.op_class);
    ret += !(this->m_op_class_info.channel == obj.m_op_class_info.channel);
    ret += !(this->m_op_class_info.tx_power == obj.m_op_class_info.tx_power);
    ret += !(this->m_op_class_info.max_tx_power == obj.m_op_class_info.max_tx_power);
    ret += !(this->m_op_class_info.num_non_op_channels == obj.m_op_class_info.num_non_op_channels);
    ret += (memcmp(this->m_op_class_info.non_op_channel, obj.m_op_class_info.non_op_channel, sizeof(unsigned int) * EM_MAX_NON_OP_CHANNELS) != 0);
   
    //em_util_info_print(EM_MGR, "%s:%d: MUH ret=%d\n", __func__, __LINE__,ret);
     
    if (ret > 0)
        return false;
    else
        return true;
}

void dm_op_class_t::operator = (const dm_op_class_t& obj)
{
    memcpy(&this->m_op_class_info.id.ruid ,&obj.m_op_class_info.id.ruid,sizeof(mac_address_t));
    this->m_op_class_info.id.type = obj.m_op_class_info.id.type;
    this->m_op_class_info.id.index = obj.m_op_class_info.id.index;
    this->m_op_class_info.op_class = obj.m_op_class_info.op_class;
    this->m_op_class_info.channel = obj.m_op_class_info.channel;
    this->m_op_class_info.tx_power = obj.m_op_class_info.tx_power;
    this->m_op_class_info.max_tx_power = obj.m_op_class_info.max_tx_power;
    this->m_op_class_info.num_non_op_channels = obj.m_op_class_info.num_non_op_channels;
    memcpy(this->m_op_class_info.non_op_channel, obj.m_op_class_info.non_op_channel, sizeof(unsigned int) * EM_MAX_NON_OP_CHANNELS);
}

int dm_op_class_t::parse_op_class_id_from_key(const char *key, em_op_class_id_t *id)
{
    em_long_string_t   str;
    char *tmp;
    unsigned int i = 0;

    strncpy(str, key, strlen(key) + 1);
    while ((tmp = strchr(str, '@')) != NULL) {
	    if (i == 0) {
	        *tmp = 0;
	        dm_easy_mesh_t::string_to_macbytes(str, id->ruid);
	        tmp++;
	        strncpy(str, tmp, strlen(tmp) + 1);	
	    } else if (i == 1) {
	        *tmp = 0;
	        id->type = (em_op_class_type_t)atoi(str);
	        tmp++;
	        id->index = atoi(tmp);
	    }
	    i++;   
    }

}

dm_op_class_t::dm_op_class_t(em_op_class_info_t *op_class)
{
    memcpy(&m_op_class_info, op_class, sizeof(em_op_class_info_t));
}

dm_op_class_t::dm_op_class_t(const dm_op_class_t& op_class)
{
    memcpy(&m_op_class_info, &op_class.m_op_class_info, sizeof(em_op_class_info_t));
}

dm_op_class_t::dm_op_class_t()
{

}

dm_op_class_t::~dm_op_class_t()
{

}

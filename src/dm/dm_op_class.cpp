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

    if ((tmp = cJSON_GetObjectItem(obj, "OpClass")) != NULL) {
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
    
    m_op_class_info.num_channels = 0;
    if ((non_op_array = cJSON_GetObjectItem(obj, "NonOperable")) != NULL) {
        m_op_class_info.num_channels = cJSON_GetArraySize(non_op_array);
        for (i = 0; i < m_op_class_info.num_channels; i++) {
            if ((tmp = cJSON_GetArrayItem(non_op_array, i)) != NULL) {
                m_op_class_info.channels[i] = tmp->valuedouble;
            }
        }
    }

    if ((tmp = cJSON_GetObjectItem(obj, "Minutes")) != NULL) {
       m_op_class_info.mins_since_cac_comp = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "Seconds")) != NULL) {
       m_op_class_info.sec_remain_non_occ_dur = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "Countdown")) != NULL) {
       m_op_class_info.countdown_cac_comp = tmp->valuedouble;
    }
    return 0;

}

void dm_op_class_t::encode(cJSON *obj)
{
    unsigned int i;

    cJSON_AddNumberToObject(obj, "Channel", m_op_class_info.channel);

	if (m_op_class_info.id.type == em_op_class_type_current) {
    	cJSON_AddNumberToObject(obj, "Class", m_op_class_info.op_class);
    	cJSON_AddNumberToObject(obj, "TxPower", m_op_class_info.tx_power);
	} else if (m_op_class_info.id.type == em_op_class_type_capability) {
    	cJSON_AddNumberToObject(obj, "Class", m_op_class_info.op_class);
    	cJSON_AddNumberToObject(obj, "MaxTxPower", m_op_class_info.max_tx_power);
    	cJSON_AddNumberToObject(obj, "NumberOfNonOperChan", m_op_class_info.num_channels);
    	cJSON *non_op_array = cJSON_CreateArray();

    	for (i = 0; i < m_op_class_info.num_channels; i++) {
        	cJSON_AddItemToArray(non_op_array, cJSON_CreateNumber(m_op_class_info.channels[i]));
    	}
    	// Add the array to the object
    	cJSON_AddItemToObject(obj, "NonOperable", non_op_array);
	} else if (m_op_class_info.id.type == em_op_class_type_cac_available) {
    	cJSON_AddNumberToObject(obj, "OpClass", m_op_class_info.op_class);
    	cJSON_AddNumberToObject(obj, "Minutes", m_op_class_info.mins_since_cac_comp);
	} else if (m_op_class_info.id.type == em_op_class_type_cac_non_occ) {
    	cJSON_AddNumberToObject(obj, "OpClass", m_op_class_info.op_class);
    	cJSON_AddNumberToObject(obj, "Seconds", m_op_class_info.sec_remain_non_occ_dur);
	} else if (m_op_class_info.id.type == em_op_class_type_cac_active) {
    	cJSON_AddNumberToObject(obj, "OpClass", m_op_class_info.op_class);
    	cJSON_AddNumberToObject(obj, "Countdown", m_op_class_info.countdown_cac_comp);
    } else if (m_op_class_info.id.type == em_op_class_type_preference) {
    	cJSON_AddNumberToObject(obj, "OpClass", m_op_class_info.op_class);
    	cJSON *chan_array = cJSON_CreateArray();

    	for (i = 0; i < m_op_class_info.num_channels; i++) {
        	cJSON_AddItemToArray(chan_array, cJSON_CreateNumber(m_op_class_info.channels[i]));
    	}
    	// Add the array to the object
    	cJSON_AddItemToObject(obj, "ChannelList", chan_array);
	}
}

bool dm_op_class_t::operator == (const dm_op_class_t& obj)
{
    int ret = 0;
    ret += (memcmp(&this->m_op_class_info.id.ruid ,&obj.m_op_class_info.id.ruid,sizeof(mac_address_t)) != 0);
    ret += !(this->m_op_class_info.id.type == obj.m_op_class_info.id.type);
    ret += !(this->m_op_class_info.id.op_class == obj.m_op_class_info.id.op_class);
    ret += !(this->m_op_class_info.op_class == obj.m_op_class_info.op_class);
    ret += !(this->m_op_class_info.channel == obj.m_op_class_info.channel);
    if (this->m_op_class_info.id.type == em_op_class_type_current) {
        ret += !(this->m_op_class_info.tx_power == obj.m_op_class_info.tx_power);
    } else if (this->m_op_class_info.id.type == em_op_class_type_capability) {
        ret += !(this->m_op_class_info.max_tx_power == obj.m_op_class_info.max_tx_power);
        ret += !(this->m_op_class_info.num_channels == obj.m_op_class_info.num_channels);
        bool isVecEqual = (this->m_op_class_info.channels == obj.m_op_class_info.channels);
        if (!isVecEqual) {
          ret += 1;
        }
    } else if (this->m_op_class_info.id.type == em_op_class_type_cac_available) {
    	ret += !(this->m_op_class_info.mins_since_cac_comp == obj.m_op_class_info.mins_since_cac_comp);
	} else if (this->m_op_class_info.id.type == em_op_class_type_cac_non_occ) {
    	ret += !(this->m_op_class_info.sec_remain_non_occ_dur == obj.m_op_class_info.sec_remain_non_occ_dur);
	} else if (this->m_op_class_info.id.type == em_op_class_type_cac_active) {
    	ret += !(this->m_op_class_info.countdown_cac_comp == obj.m_op_class_info.countdown_cac_comp);
    } else if ((this->m_op_class_info.id.type == em_op_class_type_preference) || 
						(this->m_op_class_info.id.type == em_op_class_type_anticipated) ||
						(this->m_op_class_info.id.type == em_op_class_type_scan_param)) {
        ret += !(this->m_op_class_info.num_channels == obj.m_op_class_info.num_channels);
        bool isVecEqual = (this->m_op_class_info.channels == obj.m_op_class_info.channels);
        if (!isVecEqual) {
          ret += 1;
        }
	} 
     
    if (ret > 0)
        return false;
    else
        return true;
}

void dm_op_class_t::operator = (const dm_op_class_t& obj)
{
    memcpy(&this->m_op_class_info.id.ruid ,&obj.m_op_class_info.id.ruid,sizeof(mac_address_t));
    this->m_op_class_info.id.type = obj.m_op_class_info.id.type;
    this->m_op_class_info.id.op_class = obj.m_op_class_info.id.op_class;
    this->m_op_class_info.op_class = obj.m_op_class_info.op_class;
    this->m_op_class_info.channel = obj.m_op_class_info.channel;
    this->m_op_class_info.tx_power = obj.m_op_class_info.tx_power;
    this->m_op_class_info.max_tx_power = obj.m_op_class_info.max_tx_power;
    this->m_op_class_info.num_channels = obj.m_op_class_info.num_channels;
    this->m_op_class_info.channels = obj.m_op_class_info.channels;
    this->m_op_class_info.mins_since_cac_comp = obj.m_op_class_info.mins_since_cac_comp;
    this->m_op_class_info.sec_remain_non_occ_dur = obj.m_op_class_info.sec_remain_non_occ_dur;
    this->m_op_class_info.countdown_cac_comp = obj.m_op_class_info.countdown_cac_comp;
    this->m_op_class_info.num_channels = obj.m_op_class_info.num_channels;

    this->m_op_class_info.channels = obj.m_op_class_info.channels; // std::vector c++ copying
}

int dm_op_class_t::parse_op_class_id_from_key(const char *key, em_op_class_id_t *id)
{
    em_long_string_t   str;
    char *tmp, *remain;
    unsigned int i = 0;

    strncpy(str, key, strlen(key) + 1);
    remain = str;
    while ((tmp = strchr(remain, '@')) != NULL) {
        if (i == 0) {
            *tmp = 0;
            dm_easy_mesh_t::string_to_macbytes(remain, id->ruid);
            tmp++;
            remain = tmp;
        } else if (i == 1) {
            *tmp = 0;
            id->type = (em_op_class_type_t)atoi(remain);
            tmp++;
            id->op_class = atoi(tmp);
        }
        i++;
    }

	return 0;
}

dm_op_class_t::dm_op_class_t(em_op_class_info_t *op_class)
{
    memcpy(&m_op_class_info, op_class, sizeof(em_op_class_info_t));
}

dm_op_class_t::dm_op_class_t(const dm_op_class_t& op_class)
{
    memcpy(&m_op_class_info, &op_class.m_op_class_info, sizeof(em_op_class_info_t));
}

dm_op_class_t::dm_op_class_t(const em_op_class_info_t& op_class_info)
{
    memcpy(&m_op_class_info, &op_class_info, sizeof(em_op_class_info_t));
}

dm_op_class_t::dm_op_class_t()
{
	memset(&m_op_class_info, 0, sizeof(em_op_class_info_t));
}

dm_op_class_t::~dm_op_class_t()
{
  free(m_op_class_info.channels);
}

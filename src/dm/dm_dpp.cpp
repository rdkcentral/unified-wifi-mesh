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
#include "dm_dpp.h"
#include "em_cmd_start_dpp.h"
#include "dm_easy_mesh.h"

int dm_dpp_t::analyze_config(const cJSON *obj, void *parent, em_cmd_t *pcmd[], em_cmd_params_t *param)
{
	unsigned int num = 0;
	dm_dpp_t dpp;
	dm_orch_type_t op;
	dm_easy_mesh_t	dm;

	if (dpp.decode(obj, parent) != 0) {
		return 0;
	}

	op = dm_orch_type_dpp_insert;
	pcmd[num] = new em_cmd_start_dpp_t(*param);
    pcmd[num]->init(&dm);
    num++;	
	
	return num;
}

int dm_dpp_t::decode(const cJSON *obj, void *parent_id)
{
    cJSON *tmp, *tmp_arr;
    mac_addr_str_t  mac_str;
    unsigned int j;

    char *net_id = (char *)parent_id;

    memset(&m_dpp_info, 0, sizeof(em_dpp_info_t));
		
    if ((tmp = cJSON_GetObjectItem(obj, "V:")) != NULL) {
	m_dpp_info.version = cJSON_GetNumberValue(tmp);
    }
		
    return 0;
}

void dm_dpp_t::encode(cJSON *obj)
{
    cJSON_AddNumberToObject(obj, "V:", m_dpp_info.version);
}


bool dm_dpp_t::operator == (const dm_dpp_t& obj)
{
    int ret = 0;
    ret += !(this->m_dpp_info.version == obj.m_dpp_info.version);
    ret += this->m_dpp_info.ec_data.type != obj.m_dpp_info.ec_data.type;
    ret += memcmp(this->m_dpp_info.ec_data.iPubKey, obj.m_dpp_info.ec_data.iPubKey, sizeof(this->m_dpp_info.ec_data.iPubKey)) != 0;
    ret += memcmp(this->m_dpp_info.ec_data.rPubKey, obj.m_dpp_info.ec_data.rPubKey, sizeof(this->m_dpp_info.ec_data.rPubKey)) != 0;
    ret += memcmp(this->m_dpp_info.ec_data.tran_id, obj.m_dpp_info.ec_data.tran_id, sizeof(this->m_dpp_info.ec_data.tran_id)) != 0;
    ret += this->m_dpp_info.ec_data.match_tran_id != obj.m_dpp_info.ec_data.match_tran_id;
    for (int i = 0; i < DPP_MAX_EN_CHANNELS; i++) {
	ret += this->m_dpp_info.en_chans[i].channel != obj.m_dpp_info.en_chans[i].channel;
	ret += this->m_dpp_info.en_chans[i].band != obj.m_dpp_info.en_chans[i].band;
    }
    if (ret > 0)
        return false;
    else
        return true;

}

void dm_dpp_t::operator = (const dm_dpp_t& obj)
{
    this->m_dpp_info.version == obj.m_dpp_info.version;
    this->m_dpp_info.ec_data.type == obj.m_dpp_info.ec_data.type;
    memcpy(this->m_dpp_info.ec_data.iPubKey, obj.m_dpp_info.ec_data.iPubKey, sizeof(this->m_dpp_info.ec_data.iPubKey));
    memcpy(this->m_dpp_info.ec_data.rPubKey, obj.m_dpp_info.ec_data.rPubKey, sizeof(this->m_dpp_info.ec_data.rPubKey));
    memcpy(this->m_dpp_info.ec_data.tran_id, obj.m_dpp_info.ec_data.tran_id, sizeof(this->m_dpp_info.ec_data.tran_id));
    this->m_dpp_info.ec_data.match_tran_id == obj.m_dpp_info.ec_data.match_tran_id;
    for (int i = 0; i < DPP_MAX_EN_CHANNELS; i++) {
	this->m_dpp_info.en_chans[i].channel == obj.m_dpp_info.en_chans[i].channel; 
        this->m_dpp_info.en_chans[i].band == obj.m_dpp_info.en_chans[i].band;
    }

}


dm_dpp_t::dm_dpp_t(em_dpp_info_t *dpp)
{
    memcpy(&m_dpp_info, dpp, sizeof(em_dpp_info_t));
}

dm_dpp_t::dm_dpp_t(const dm_dpp_t& dpp)
{
	memcpy(&m_dpp_info, &dpp.m_dpp_info, sizeof(em_dpp_info_t));
}

dm_dpp_t::dm_dpp_t()
{

}

dm_dpp_t::~dm_dpp_t()
{

}

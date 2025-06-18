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
#include "dm_tid_to_link.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_tid_to_link_t::decode(const cJSON *obj, void *parent_id)
{
    //TODO: needs to be implemnented

    return 0;
}

void dm_tid_to_link_t::encode(cJSON *obj)
{
    //TODO: needs to be implemnented
}

void dm_tid_to_link_t::operator = (const dm_tid_to_link_t& obj)
{
    if (this == &obj) { return; }
    this->m_tid_to_link_info.is_bsta_config = obj.m_tid_to_link_info.is_bsta_config;
    memcpy(&this->m_tid_to_link_info.mld_mac_addr,&obj.m_tid_to_link_info.mld_mac_addr,sizeof(mac_address_t));
    this->m_tid_to_link_info.tid_to_link_map_neg = obj.m_tid_to_link_info.tid_to_link_map_neg;
    this->m_tid_to_link_info.num_mapping = obj.m_tid_to_link_info.num_mapping;
    memcpy(&this->m_tid_to_link_info.tid_to_link_mapping,&obj.m_tid_to_link_info.tid_to_link_mapping,sizeof(em_tid_to_link_map_info_t));
}

bool dm_tid_to_link_t::operator == (const dm_tid_to_link_t& obj)
{
	int ret = 0;

    ret += !(this->m_tid_to_link_info.is_bsta_config == obj.m_tid_to_link_info.is_bsta_config);
    ret += (memcmp(&this->m_tid_to_link_info.mld_mac_addr,&obj.m_tid_to_link_info.mld_mac_addr,sizeof(mac_address_t)) != 0);
    ret += !(this->m_tid_to_link_info.tid_to_link_map_neg == obj.m_tid_to_link_info.tid_to_link_map_neg);
    ret += !(this->m_tid_to_link_info.num_mapping == obj.m_tid_to_link_info.num_mapping);
    ret += (memcmp(&this->m_tid_to_link_info.tid_to_link_mapping,&obj.m_tid_to_link_info.tid_to_link_mapping,sizeof(em_tid_to_link_map_info_t)) != 0);

    if (ret > 0)
        return false;
    else
        return true;
}

dm_tid_to_link_t::dm_tid_to_link_t(em_tid_to_link_info_t *tid_to_link_info)
{
    memcpy(&m_tid_to_link_info, tid_to_link_info, sizeof(em_tid_to_link_info_t));
}

dm_tid_to_link_t::dm_tid_to_link_t(const dm_tid_to_link_t& tid_to_link)
{
    memcpy(&m_tid_to_link_info, &tid_to_link.m_tid_to_link_info, sizeof(em_tid_to_link_info_t));
}

dm_tid_to_link_t::dm_tid_to_link_t()
{

}

dm_tid_to_link_t::~dm_tid_to_link_t()
{

}

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
#include "dm_assoc_sta_mld.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_assoc_sta_mld_t::decode(const cJSON *obj, void *parent_id)
{
    //TODO: needs to be implemnented

    return 0;
}

void dm_assoc_sta_mld_t::encode(cJSON *obj)
{
    //TODO: needs to be implemnented
}

void dm_assoc_sta_mld_t::operator = (const dm_assoc_sta_mld_t& obj)
{
    memcpy(&this->m_assoc_sta_mld_info.mac_addr ,&obj.m_assoc_sta_mld_info.mac_addr,sizeof(mac_address_t));
    memcpy(&this->m_assoc_sta_mld_info.ap_mld_mac_addr ,&obj.m_assoc_sta_mld_info.ap_mld_mac_addr,sizeof(mac_address_t));
    this->m_assoc_sta_mld_info.str = obj.m_assoc_sta_mld_info.str;
    this->m_assoc_sta_mld_info.nstr = obj.m_assoc_sta_mld_info.nstr;
    this->m_assoc_sta_mld_info.emlsr = obj.m_assoc_sta_mld_info.emlsr;
    this->m_assoc_sta_mld_info.emlmr = obj.m_assoc_sta_mld_info.emlmr;
    this->m_assoc_sta_mld_info.num_affiliated_sta = obj.m_assoc_sta_mld_info.num_affiliated_sta;
    memcpy(&this->m_assoc_sta_mld_info.affiliated_sta,&obj.m_assoc_sta_mld_info.affiliated_sta,sizeof(em_affiliated_sta_info_t));
}

bool dm_assoc_sta_mld_t::operator == (const dm_assoc_sta_mld_t& obj)
{
	int ret = 0;

    ret += (memcmp(&this->m_assoc_sta_mld_info.mac_addr,&obj.m_assoc_sta_mld_info.mac_addr,sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_assoc_sta_mld_info.ap_mld_mac_addr,&obj.m_assoc_sta_mld_info.ap_mld_mac_addr,sizeof(mac_address_t)) != 0);
    ret += !(this->m_assoc_sta_mld_info.str == obj.m_assoc_sta_mld_info.str);
    ret += !(this->m_assoc_sta_mld_info.nstr == obj.m_assoc_sta_mld_info.nstr);
    ret += !(this->m_assoc_sta_mld_info.emlsr == obj.m_assoc_sta_mld_info.emlsr);
    ret += !(this->m_assoc_sta_mld_info.emlmr == obj.m_assoc_sta_mld_info.emlmr);
    ret += !(this->m_assoc_sta_mld_info.num_affiliated_sta == obj.m_assoc_sta_mld_info.num_affiliated_sta);
    ret += (memcmp(&this->m_assoc_sta_mld_info.affiliated_sta,&obj.m_assoc_sta_mld_info.affiliated_sta,sizeof(em_affiliated_ap_info_t)) != 0);

    if (ret > 0)
        return false;
    else
        return true;
}

dm_assoc_sta_mld_t::dm_assoc_sta_mld_t(em_assoc_sta_mld_info_t *assoc_sta_mld_info)
{
    memcpy(&m_assoc_sta_mld_info, assoc_sta_mld_info, sizeof(em_assoc_sta_mld_info_t));
}

dm_assoc_sta_mld_t::dm_assoc_sta_mld_t(const dm_assoc_sta_mld_t& assoc_sta_mld)
{
    memcpy(&m_assoc_sta_mld_info, &assoc_sta_mld.m_assoc_sta_mld_info, sizeof(em_assoc_sta_mld_info_t));
}

dm_assoc_sta_mld_t::dm_assoc_sta_mld_t()
{

}

dm_assoc_sta_mld_t::~dm_assoc_sta_mld_t()
{

}

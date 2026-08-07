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
#include <stdexcept>
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
#include "dm_assoc_sta_mld.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"
#include "util.h"

int dm_assoc_sta_mld_t::decode(const cJSON *obj, void *parent_id)
{
    if (obj == NULL) {
        printf("%s:%d: Error - obj is NULL\n", __func__, __LINE__);
        return -1;
    }
    if (parent_id == NULL) {
        printf("%s:%d: Error - parent_id is NULL\n", __func__, __LINE__);
        return -1;
    }
    if (!cJSON_IsObject(obj) || (cJSON_GetObjectItem(obj, "MACAddress") == NULL)) {
        printf("%s:%d: Error - obj is not a valid assoc sta mld JSON object\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

void dm_assoc_sta_mld_t::encode(cJSON *obj)
{
    if (obj == NULL || !cJSON_IsObject(obj) || (cJSON_GetArraySize(obj) == 0)) {
        throw std::invalid_argument("dm_assoc_sta_mld_t::encode: obj is NULL or empty/invalid JSON object");
    }
}

void dm_assoc_sta_mld_t::operator = (const dm_assoc_sta_mld_t& obj)
{
    if (this == &obj) { return; }
    memcpy(&this->m_assoc_sta_mld_info.mac_addr ,&obj.m_assoc_sta_mld_info.mac_addr,sizeof(mac_address_t));
    memcpy(&this->m_assoc_sta_mld_info.ap_mld_mac_addr ,&obj.m_assoc_sta_mld_info.ap_mld_mac_addr,sizeof(mac_address_t));
    this->m_assoc_sta_mld_info.str = obj.m_assoc_sta_mld_info.str;
    this->m_assoc_sta_mld_info.nstr = obj.m_assoc_sta_mld_info.nstr;
    this->m_assoc_sta_mld_info.emlsr = obj.m_assoc_sta_mld_info.emlsr;
    this->m_assoc_sta_mld_info.emlmr = obj.m_assoc_sta_mld_info.emlmr;
    this->m_assoc_sta_mld_info.num_affiliated_sta = (obj.m_assoc_sta_mld_info.num_affiliated_sta > EM_MAX_AP_MLD)
                                                    ? EM_MAX_AP_MLD : obj.m_assoc_sta_mld_info.num_affiliated_sta;
    for (unsigned int i = 0; i < this->m_assoc_sta_mld_info.num_affiliated_sta; i++) {
        memcpy(&this->m_assoc_sta_mld_info.affiliated_sta[i].bssid,
            &obj.m_assoc_sta_mld_info.affiliated_sta[i].bssid, sizeof(mac_address_t));
        memcpy(&this->m_assoc_sta_mld_info.affiliated_sta[i].mac_addr,
            &obj.m_assoc_sta_mld_info.affiliated_sta[i].mac_addr, sizeof(mac_address_t));
    }
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
    unsigned int num_sta = (this->m_assoc_sta_mld_info.num_affiliated_sta > EM_MAX_AP_MLD)
                           ? EM_MAX_AP_MLD : this->m_assoc_sta_mld_info.num_affiliated_sta;
    for (unsigned int i = 0; i < num_sta; i++) {
        ret += (memcmp(&this->m_assoc_sta_mld_info.affiliated_sta[i].bssid,
            &obj.m_assoc_sta_mld_info.affiliated_sta[i].bssid, sizeof(mac_address_t)) != 0);
        ret += (memcmp(&this->m_assoc_sta_mld_info.affiliated_sta[i].mac_addr,
            &obj.m_assoc_sta_mld_info.affiliated_sta[i].mac_addr, sizeof(mac_address_t)) != 0);
    }

    if (ret > 0)
        return false;
    else
        return true;
}

dm_assoc_sta_mld_t::dm_assoc_sta_mld_t(em_assoc_sta_mld_info_t *assoc_sta_mld_info)
{
    memset(&m_assoc_sta_mld_info, 0, sizeof(em_assoc_sta_mld_info_t));
    if (assoc_sta_mld_info == nullptr) {
        throw std::invalid_argument("dm_assoc_sta_mld_t: assoc_sta_mld_info is null");
    }
    memcpy(&m_assoc_sta_mld_info, assoc_sta_mld_info, sizeof(em_assoc_sta_mld_info_t));
    if (m_assoc_sta_mld_info.num_affiliated_sta > EM_MAX_AP_MLD) {
        printf("%s:%d: Error - num_affiliated_sta %u exceeds max %d, resetting\n", __func__, __LINE__, m_assoc_sta_mld_info.num_affiliated_sta, EM_MAX_AP_MLD);
        m_assoc_sta_mld_info.num_affiliated_sta = 0;
    }
}

dm_assoc_sta_mld_t::dm_assoc_sta_mld_t(const dm_assoc_sta_mld_t& assoc_sta_mld)
{
    memcpy(&m_assoc_sta_mld_info, &assoc_sta_mld.m_assoc_sta_mld_info, sizeof(em_assoc_sta_mld_info_t));
}

dm_assoc_sta_mld_t::dm_assoc_sta_mld_t()
    : m_assoc_sta_mld_info{}
{

}

dm_assoc_sta_mld_t::~dm_assoc_sta_mld_t()
{

}

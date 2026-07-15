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
#include "dm_cac_comp.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"



int dm_cac_comp_t::decode(const cJSON *obj, void *parent_id)
{
    if (obj == NULL) {
        printf("%s:%d: Error - obj is NULL\n", __func__, __LINE__);
        return -1;
    }
    if (parent_id == NULL) {
        printf("%s:%d: Error - parent_id is NULL\n", __func__, __LINE__);
        return -1;
    }
    if (!cJSON_IsObject(obj)) {
        printf("%s:%d: Error - obj is not a valid JSON object\n", __func__, __LINE__);
        return -1;
    }
    if ((cJSON_GetObjectItem(obj, "RUID") == NULL) &&
        (cJSON_GetObjectItem(obj, "OpClass") == NULL) &&
        (cJSON_GetObjectItem(obj, "Channel") == NULL)) {
        printf("%s:%d: Error - missing required CAC completion fields\n", __func__, __LINE__);
        return -1;
    }
    return 0;
}

void dm_cac_comp_t::encode(cJSON *obj)
{
    if (obj == NULL || !cJSON_IsObject(obj)) {
        throw std::invalid_argument("dm_cac_comp_t::encode: obj is NULL or not a valid JSON object");
    }
}

dm_orch_type_t dm_cac_comp_t::get_dm_orch_type(const dm_cac_comp_t& cac_comp)
{
    if ( this == &cac_comp) {
        return dm_orch_type_none;
    } else {
        return dm_orch_type_db_update;
    }
    return dm_orch_type_db_insert;
}

bool dm_cac_comp_t::operator == (const dm_cac_comp_t& obj) 
{   
    int ret = 0;
    ret += (memcmp(m_cac_comp_info.ruid, obj.m_cac_comp_info.ruid, sizeof(mac_address_t)) != 0);
    ret += (m_cac_comp_info.op_class != obj.m_cac_comp_info.op_class);
    ret += (m_cac_comp_info.channel != obj.m_cac_comp_info.channel);
    ret += (m_cac_comp_info.status != obj.m_cac_comp_info.status);
    ret += (m_cac_comp_info.detected_pairs_num != obj.m_cac_comp_info.detected_pairs_num);
    ret += (memcmp(m_cac_comp_info.detected_pairs, obj.m_cac_comp_info.detected_pairs, sizeof(m_cac_comp_info.detected_pairs)) != 0);
    return (ret == 0);
}

void dm_cac_comp_t::operator = (const dm_cac_comp_t& obj)
{
    if (this == &obj) { return; }
    memcpy(&m_cac_comp_info, &obj.m_cac_comp_info, sizeof(em_cac_comp_info_t));
}

dm_cac_comp_t::dm_cac_comp_t(em_cac_comp_info_t *radio)
{
    if (radio == NULL) {
        throw std::invalid_argument("dm_cac_comp_t: radio is NULL");
    }
    memcpy(&m_cac_comp_info, radio, sizeof(em_cac_comp_info_t));
}

dm_cac_comp_t::dm_cac_comp_t(const dm_cac_comp_t& radio)
{
	memcpy(&m_cac_comp_info, &radio.m_cac_comp_info, sizeof(em_cac_comp_info_t));
}

dm_cac_comp_t::dm_cac_comp_t()
{

}

dm_cac_comp_t::~dm_cac_comp_t()
{

}

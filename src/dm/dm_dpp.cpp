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
#include "dm_dpp.h"
#include "em_cmd_start_dpp.h"
#include "dm_easy_mesh.h"
#include "ec_util.h"
#include "util.h"

#include <string>
#include <sstream>

int dm_dpp_t::analyze_config(const cJSON *obj, void *parent, em_cmd_t *pcmd[], em_cmd_params_t *param, void* user_param)
{
	int num = 0;
	dm_easy_mesh_t	dm;

    // Decodes JSON `obj` into `m_dpp_info`
	if (dm.get_dpp()->decode(obj, parent, user_param) != 0) {
		return 0;
	}

	pcmd[num] = new em_cmd_start_dpp_t(*param);
    pcmd[num]->init(&dm);
    num++;	
	
	return num;
}

int dm_dpp_t::decode(const cJSON *obj, void *parent_id, void* user_info)
{
    printf("%s:%d: Decoding DPP\n", __func__, __LINE__);

    std::string country_code = "US";
    if (user_info != NULL) {
        country_code = std::string(static_cast<char*>(user_info));
    }
		
    if (!ec_util::decode_bootstrap_data_json(obj, &m_dpp_info, country_code)){
        printf("%s:%d: Failed to decode DPP data\n", __func__, __LINE__);
        return -1;
    }
		
    return 0;
}

void dm_dpp_t::encode(cJSON *obj)
{
    cJSON_AddNumberToObject(obj, "V:", m_dpp_info.version);
}


bool ec_pub_keys_equal(const SSL_KEY* key1, const SSL_KEY* key2) {
    if (!key1 || !key2) return false;
    
    const EC_POINT* point1 = em_crypto_t::get_pub_key_point(key1);
    const EC_POINT* point2 = em_crypto_t::get_pub_key_point(key2);
    
    if (!point1 || !point2) return false;
    
    const EC_GROUP* group1 = em_crypto_t::get_key_group(key1);
    const EC_GROUP* group2 = em_crypto_t::get_key_group(key2);

    if (EC_GROUP_cmp(group1, group2, NULL) != 0) return false;

    return (EC_POINT_cmp(group1, point1, point2, NULL) == 0);
}

bool dm_dpp_t::operator == (const dm_dpp_t& obj)
{
    int ret = 0;
    ret += !(this->m_dpp_info.version == obj.m_dpp_info.version);
    ret += this->m_dpp_info.type != obj.m_dpp_info.type;
    ret += !(ec_pub_keys_equal(this->m_dpp_info.initiator_boot_key, obj.m_dpp_info.initiator_boot_key));
    ret += !(ec_pub_keys_equal(this->m_dpp_info.responder_boot_key, obj.m_dpp_info.responder_boot_key));
    ret += memcmp(this->m_dpp_info.mac_addr, obj.m_dpp_info.mac_addr, sizeof(this->m_dpp_info.mac_addr));
    ret += memcmp(this->m_dpp_info.ec_freqs, obj.m_dpp_info.ec_freqs, DPP_MAX_EN_CHANNELS * sizeof(int));

    if (ret > 0) return false;
    
    return true;

}

void dm_dpp_t::operator = (const dm_dpp_t& obj)
{
    if (this == &obj) { return; }
    this->m_dpp_info.version = obj.m_dpp_info.version;
    this->m_dpp_info.type = obj.m_dpp_info.type;
    this->m_dpp_info.initiator_boot_key = obj.m_dpp_info.initiator_boot_key;
    this->m_dpp_info.responder_boot_key = obj.m_dpp_info.responder_boot_key;

    memcpy(this->m_dpp_info.mac_addr, obj.m_dpp_info.mac_addr, sizeof(this->m_dpp_info.mac_addr));
    memcpy(this->m_dpp_info.ec_freqs, obj.m_dpp_info.ec_freqs, DPP_MAX_EN_CHANNELS * sizeof(int));


}


dm_dpp_t::dm_dpp_t(ec_data_t *dpp)
{
    memcpy(&m_dpp_info, dpp, sizeof(ec_data_t));
}

dm_dpp_t::dm_dpp_t(const dm_dpp_t& dpp)
{
	memcpy(&m_dpp_info, &dpp.m_dpp_info, sizeof(ec_data_t));
}

dm_dpp_t::dm_dpp_t()
{

}

dm_dpp_t::~dm_dpp_t()
{

}

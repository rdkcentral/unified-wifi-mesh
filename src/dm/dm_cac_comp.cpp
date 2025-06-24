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
#include "dm_cac_comp.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"



int dm_cac_comp_t::decode(const cJSON *obj, void *parent_id)
{
    return 0;
}

void dm_cac_comp_t::encode(cJSON *obj)
{
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
	return true;
}

void dm_cac_comp_t::operator = (const dm_cac_comp_t& obj)
{
}

dm_cac_comp_t::dm_cac_comp_t(em_cac_comp_info_t *radio)
{
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

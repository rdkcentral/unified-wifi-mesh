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
#include "dm_scan_result.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_scan_result_t::decode(const cJSON *obj, void *parent_id)
{
	return 0;

}

void dm_scan_result_t::encode(cJSON *obj, em_scan_result_id_t id)
{

}

bool dm_scan_result_t::operator == (const dm_scan_result_t& obj)
{
    int ret = 0;
    
	return (ret > 0) ? false:true;
}

void dm_scan_result_t::operator = (const dm_scan_result_t& obj)
{

}

int dm_scan_result_t::parse_scan_result_id_from_key(const char *key, em_scan_result_id_t *id)
{
    return 0;
}

dm_scan_result_t::dm_scan_result_t(em_scan_result_t *scan_result)
{
    memcpy(&m_scan_result, scan_result, sizeof(em_scan_result_t));
}

dm_scan_result_t::dm_scan_result_t(const dm_scan_result_t& scan_result)
{
    memcpy(&m_scan_result, &scan_result.m_scan_result, sizeof(em_scan_result_t));
}

dm_scan_result_t::dm_scan_result_t(const em_scan_result_t& scan_result)
{
    memcpy(&m_scan_result, &scan_result, sizeof(em_scan_result_t));
}

dm_scan_result_t::dm_scan_result_t()
{
	memset(&m_scan_result, 0, sizeof(em_scan_result_t));
}

dm_scan_result_t::~dm_scan_result_t()
{

}

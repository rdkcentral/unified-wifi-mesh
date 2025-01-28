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
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <pthread.h>
#include "em_simulator.h"
#include "util.h"

int em_simulator_t::find_matching_scan_result_index(dm_easy_mesh_agent_t& dm, 
					unsigned char *mac, unsigned int op_class, unsigned int channel)
{
	dm_scan_result_t *res;
	unsigned int i;
	mac_addr_str_t mac_str;

	dm_easy_mesh_t::macbytes_to_string(mac, mac_str);
	//printf("%s:%d: Comparing with mac: %s, op_class: %d, channel: %d\n", __func__, __LINE__, mac_str, op_class, channel);		
	for (i = 0; i < dm.m_num_scan_results; i++) {
		res = &dm.m_scan_result[i];

		if ((memcmp(res->m_scan_result.id.ruid, mac, sizeof(mac_address_t)) == 0) &&
				(res->m_scan_result.id.op_class == op_class) && (res->m_scan_result.id.channel == channel)) {
			return i;	
		}
	}

	return -1;
}

bool em_simulator_t::run(dm_easy_mesh_agent_t& dm)
{
	char time_date[EM_DATE_TIME_BUFF_SZ];
	unsigned int i, j, k;
	int index = 0;
	dm_scan_result_t *res;
	mac_address_t nbr_mac_base = {0x00, 0x01, 0x03, 0x04, 0x05, 0x06};

	if (m_can_run_scan_res == false) {
		return false;
	}

	for (i = 0; i < m_param.u.scan_params.num_op_classes; i++) {

        for (j = 0; j < m_param.u.scan_params.op_class[i].num_channels; j++) {
			if ((index = find_matching_scan_result_index(dm, m_param.u.scan_params.ruid, 
						m_param.u.scan_params.op_class[i].op_class, m_param.u.scan_params.op_class[i].channels[j])) == -1) {
				res = &dm.m_scan_result[dm.m_num_scan_results];
				dm.m_num_scan_results++;	 
			} else {
				res = &dm.m_scan_result[index];
			}
			
			strncpy(res->m_scan_result.id.net_id, dm.m_network.m_net_info.id, strlen(dm.m_network.m_net_info.id) + 1);
			memcpy(res->m_scan_result.id.dev_mac, dm.m_device.m_device_info.id.mac, sizeof(mac_address_t));
			memcpy(res->m_scan_result.id.ruid, m_param.u.scan_params.ruid, sizeof(mac_address_t));
			res->m_scan_result.id.op_class = m_param.u.scan_params.op_class[i].op_class;
			res->m_scan_result.id.channel = m_param.u.scan_params.op_class[i].channels[j];
			res->m_scan_result.scan_status = 0;

			get_date_time_rfc3399(time_date, sizeof(time_date));

			strncpy(res->m_scan_result.timestamp, time_date, strlen(time_date) + 1);
			res->m_scan_result.util = 20;
			res->m_scan_result.noise = 10;

			res->m_scan_result.num_neighbors = 2;

			for (k = 0; k < res->m_scan_result.num_neighbors; k++) {
				nbr_mac_base[5]++;
				memcpy(res->m_scan_result.neighbor[k].bssid, nbr_mac_base, sizeof(mac_address_t));
				strncpy(res->m_scan_result.neighbor[k].ssid, "test", strlen("test") + 1);
				res->m_scan_result.neighbor[k].signal_strength = 30;
				res->m_scan_result.neighbor[k].bandwidth = WIFI_CHANNELBANDWIDTH_40MHZ;
				res->m_scan_result.neighbor[k].bss_color = 0x8f;
				res->m_scan_result.neighbor[k].channel_util =70;
				res->m_scan_result.neighbor[k].sta_count = 5;
			}

        }
    }

	return true;
}

void em_simulator_t::configure(dm_easy_mesh_agent_t& dm, em_scan_params_t *params)
{
	mac_addr_str_t  radio_mac_str;
    unsigned int i, j;

	memcpy(&m_param.u.scan_params, params, sizeof(em_scan_params_t));

    dm_easy_mesh_t::macbytes_to_string(m_param.u.scan_params.ruid, radio_mac_str);
    printf("%s:%d: Radio: %s Num of Op Classes: %d\n", __func__, __LINE__, radio_mac_str, m_param.u.scan_params.num_op_classes);
	m_can_run_scan_res = true;

	for (i = 0; i < m_param.u.scan_params.num_op_classes; i++) {
        printf("%s:%d: Op Class: %d\n", __func__, __LINE__, m_param.u.scan_params.op_class[i].op_class);
        printf("%s:%d: Channels: ", __func__, __LINE__);

        for (j = 0; j < m_param.u.scan_params.op_class[i].num_channels; j++) {
            printf("%d ", m_param.u.scan_params.op_class[i].channels[j]);
        }
        printf("\n");
    }

}

em_simulator_t::em_simulator_t()
{
	m_can_run_scan_res = false;
}

em_simulator_t::~em_simulator_t()
{

}

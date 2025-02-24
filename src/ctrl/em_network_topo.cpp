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
#include <pthread.h>
#include <cjson/cJSON.h>
#include "em_network_topo.h"

void em_network_topo_t::encode(cJSON *parent)
{
	cJSON *dev_obj, *child_obj, *radio_list_obj, *radio_obj, *bss_list_obj, *bss_obj, *bh_obj;
	unsigned int i, j;
	char *tmp;

	dev_obj = cJSON_AddObjectToObject(parent, "Device");
	m_data_model->m_device.encode(dev_obj, true);

	radio_list_obj = cJSON_AddArrayToObject(dev_obj, "RadioList");
	for (i = 0; i < m_data_model->m_num_radios; i++) {
		radio_obj = cJSON_CreateObject();
		m_data_model->m_radio[i].encode(radio_obj, em_get_radio_list_reason_radio_summary);
		cJSON_AddItemToArray(radio_list_obj, radio_obj);
		bss_list_obj = cJSON_AddArrayToObject(radio_obj, "BSSList");
		for (j = 0; j < m_data_model->m_num_bss; j++) {
			if (memcmp(m_data_model->m_bss[j].m_bss_info.id.ruid, 
							m_data_model->m_radio[i].m_radio_info.id.ruid, sizeof(mac_address_t)) == 0) {
				bss_obj = cJSON_CreateObject();
				m_data_model->m_bss[j].encode(bss_obj, true);
				cJSON_AddItemToArray(bss_list_obj, bss_obj);
			}
		}
		
	}

	bh_obj = cJSON_GetObjectItem(dev_obj, "Backhaul");

	for (i = 0; i < m_num_topologies; i++) {
		child_obj = cJSON_AddObjectToObject(bh_obj, "Device");
		m_topology[i]->encode(child_obj);
	}	
}

em_network_topo_t *em_network_topo_t::find_topology_by_bh_associated(mac_address_t sta_mac)
{
	unsigned int i;
	dm_sta_t *sta;
	em_network_topo_t *topo;

	for (i = 0; i < m_data_model->m_num_bss; i++) {
		if (m_data_model->m_bss[i].m_bss_info.id.haul_type == em_haul_type_backhaul) {
			sta = (dm_sta_t *)hash_map_get_first(m_data_model->m_sta_map);
			while (sta != NULL) {
				if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) && 
						(memcmp(sta->m_sta_info.bssid, m_data_model->m_bss[i].m_bss_info.id.bssid, sizeof(mac_address_t)) == 0)) {
					return this;
				}
				sta = (dm_sta_t *)hash_map_get_next(m_data_model->m_sta_map, sta);
			}	
		}
	}

	for (i = 0; i < m_num_topologies; i++) {
		if ((topo = m_topology[i]->find_topology_by_bh_associated(sta_mac)) != NULL) {
			return topo;	
		}
	}

	return NULL;
}

em_network_topo_t *em_network_topo_t::find_topology(dm_easy_mesh_t *dm)
{
	unsigned int i;
	em_network_topo_t *topo;
	mac_addr_str_t tgt_dev_mac_str, src_dev_mac_str;

	dm_easy_mesh_t::macbytes_to_string(dm->m_device.m_device_info.intf.mac, tgt_dev_mac_str);
	dm_easy_mesh_t::macbytes_to_string(m_data_model->m_device.m_device_info.intf.mac, src_dev_mac_str);
	printf("%s:%d: Trying to find topology: %s in branch: %s\n", __func__, __LINE__, tgt_dev_mac_str, src_dev_mac_str);

	if (m_data_model == dm) {
		printf("%s:%d: Found topology: %s in branch: %s\n", __func__, __LINE__, tgt_dev_mac_str, src_dev_mac_str);
		return this;
	}

	for (i = 0; i < m_num_topologies; i++) {
		if ((topo = m_topology[i]->find_topology(dm)) != NULL) {
			return topo;
		}	
	}

	return NULL;
}

void em_network_topo_t::add_network_topo(dm_easy_mesh_t *dm)
{
	m_topology[m_num_topologies] = new em_network_topo_t(dm);
	m_num_topologies++;
}

void em_network_topo_t::add(dm_easy_mesh_t *dm)
{
	em_network_topo_t *topo;

	// find the BH bss where al_mac of this device of data model is attached to.
	if ((topo = find_topology_by_bh_associated(dm->m_device.m_device_info.intf.mac)) != NULL) {
		topo->add_network_topo(dm);
	} else {
		printf("%s:%d: Could not find topology in backhaul association tree, must be ethernet\n", __func__, __LINE__);
		this->add_network_topo(dm);
	}
	
}

void em_network_topo_t::remove(dm_easy_mesh_t *dm)
{
	unsigned int i, index = 0;
	bool found = false;

	for (i = 0; i < m_num_topologies; i++) {
		if (m_topology[i]->get_data_model() == dm) {
			found = true;
			index = i;
			break;
		}
	} 

	if (found == false) {
		return;
	}

	delete m_topology[i];

	for (i = index; i < m_num_topologies - 1; i++) {
		m_topology[i] = m_topology[i + 1];
	}

	m_num_topologies--;
}

em_network_topo_t::em_network_topo_t(dm_easy_mesh_t *dm)
{
	m_num_topologies  = 0;
	m_data_model = dm;
}

em_network_topo_t::em_network_topo_t()
{
	m_data_model = NULL;
	m_num_topologies  = 0;
}

em_network_topo_t::~em_network_topo_t()
{
	m_data_model = NULL;
}


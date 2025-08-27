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
#include "util.h"
#include "dm_sta_list.h"
#include "dm_easy_mesh_ctrl.h"
#include "em_ctrl.h"

extern em_ctrl_t g_ctrl;
extern em_network_topo_t *g_network_topology;

void em_network_topo_t::encode(cJSON *parent)
{
	cJSON *dev_obj, *child_obj, *radio_list_obj, *radio_obj, *bss_list_obj, *bss_obj, *bh_obj, *sta_list_obj;
	unsigned int i, j;

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
				sta_list_obj = cJSON_AddArrayToObject(bss_obj, "STAList");
				dm_easy_mesh_ctrl_t *dm_ctrl = reinterpret_cast<dm_easy_mesh_ctrl_t *>(g_ctrl.get_data_model(GLOBAL_NET_ID));
				if (dm_ctrl != NULL) {
					// Get the Station associated with this bss
					std::string bss_mac_str = util::mac_to_string(m_data_model->m_bss[j].m_bss_info.bssid.mac);
					dm_ctrl->dm_sta_list_t::get_config(sta_list_obj, static_cast<void*>(const_cast<char*> (bss_mac_str.c_str())),
						em_get_sta_list_reason_topology);
				}
				cJSON_AddItemToArray(bss_list_obj, bss_obj);
			}
		}
	}

	bh_obj = cJSON_GetObjectItem(dev_obj, "Backhaul");
	child_obj = cJSON_AddArrayToObject(bh_obj, "Child");
	for (i = 0; i < m_num_topologies; i++) {
		if (child_obj != NULL) {
			m_topology[i]->encode(child_obj);
		}
	}	
}

em_network_topo_t *em_network_topo_t::find_topology_by_bh_associated(mac_address_t sta_mac)
{
	unsigned int i;
	dm_sta_t *sta;
	em_network_topo_t *topo;
	std::string sta_mac_str, dev_mac_str;

	sta_mac_str = util::mac_to_string(sta_mac);
	dev_mac_str = util::mac_to_string(m_data_model->m_device.m_device_info.intf.mac);
	for (i = 0; i < m_data_model->m_num_bss; i++) {
		if (m_data_model->m_bss[i].m_bss_info.id.haul_type == em_haul_type_backhaul) {
			sta = static_cast<dm_sta_t *> (hash_map_get_first(m_data_model->m_sta_map));
			while (sta != NULL) {
				if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) && 
					(memcmp(sta->m_sta_info.bssid, m_data_model->m_bss[i].m_bss_info.id.bssid, sizeof(mac_address_t)) == 0)) {
					em_printfout("Found topology of sta mac: %s dev_mac:%s", sta_mac_str.c_str(), dev_mac_str.c_str());
					return this;
				}
				sta = static_cast<dm_sta_t *> (hash_map_get_next(m_data_model->m_sta_map, sta));
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

em_network_topo_t *em_network_topo_t::find_topology_by_bh_associated(dm_easy_mesh_t *dm)
{
	if (dm == NULL)	{
		em_printfout("dm is NULL, return NULL");
		return NULL;
	}

	std::string dev_mac_str = util::mac_to_string(dm->m_device.m_device_info.intf.mac);
	// Obtain the mesh_sta information of this dm.
	em_bss_info_t *bss = dm->get_bsta_bss_info();
	if (bss == NULL) {
		em_printfout("Backhaul sta bss not found for dev_mac:%s, return NULL", dev_mac_str.c_str());
		dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee8023ab;
		return NULL;
	}
	// From the bss info obtained, find the appropriate em_network_topo_t containing this bss
	// and return that topology object.
	mac_address_t bss_mac;
	memcpy(bss_mac, bss->id.bssid, sizeof(mac_address_t));
	if (dm->get_colocated() == false) {
		// Update the backhaul of the dm object with the bss mac address
		memcpy(dm->m_device.m_device_info.backhaul_mac.mac, bss_mac, sizeof(mac_address_t));
		dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee80211ac_5;
		// check if backhaul mac is 00:00:00:00:00:00, then change the media type to em_media_type_ieee8023ab
		if (memcmp(bss_mac, ZERO_MAC_ADDR, sizeof(mac_address_t)) == 0) {
			dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee8023ab;
		}
	}
	em_printfout("Find topology associated with bss mac: %s", util::mac_to_string(bss_mac).c_str());
	if (memcmp(bss_mac, ZERO_MAC_ADDR, sizeof(mac_address_t)) == 0) {
		em_printfout("bss mac is zero, return NULL");
		return NULL;
	}
	// Now search for the topology containing this bss mac address.
	return g_network_topology->find_topology_by_bss_mac(bss_mac);
}

em_network_topo_t *em_network_topo_t::find_topology_by_bss_mac(mac_address_t bss_mac)
{
	unsigned int i;
	em_network_topo_t *topo;

	std::string bss_mac_str = util::mac_to_string(bss_mac);
	em_bss_info_t* bss_info = m_data_model->get_bss_info_with_mac(bss_mac);
	if (bss_info) {
		// If we found the bss info, then return the current topology.
		em_printfout("Found topology of bss mac: %s num_child_topo:%d", bss_mac_str.c_str(),
			this->m_num_topologies);
		return this;
	}

	// If not found in the current topology check recursively other child topologies.
	em_printfout("Could not find bss mac: %s, continuing with child topologies", bss_mac_str.c_str());
	for (i = 0; i < m_num_topologies; i++) {
		if ((topo = m_topology[i]->find_topology_by_bss_mac(bss_mac)) != NULL) {
			em_printfout("Returning Found topology of bss mac: %s num_child_topo:%d",
				   bss_mac_str.c_str(), topo->m_num_topologies);
			return topo;
		}
	}
	em_printfout("Could not find bss mac: %s in all topologies, return NULL", bss_mac_str.c_str());
	return NULL;
}

void em_network_topo_t::print_topology()
{
	std::string dev_mac_str = util::mac_to_string(m_data_model->m_device.m_device_info.intf.mac);
	em_printfout("Network Topology of dev_mac:%s num_child_topologies:%d", dev_mac_str.c_str(), m_num_topologies);
	em_printfout("---- Child Topologies[%s] <start> -----", dev_mac_str.c_str());
	for (unsigned int i = 0; i < m_num_topologies; i++) {
		m_topology[i]->print_topology();
	}
	em_printfout("---- Child Topologies[%s] <end> -----", dev_mac_str.c_str());
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

void em_network_topo_t::add_network_topo(dm_easy_mesh_t *dm, em_network_topo_t **child_topos, unsigned int num_child_topos)
{
	std::string dev_mac_str = util::mac_to_string(dm->m_device.m_device_info.intf.mac);
	if (m_num_topologies >= EM_MAX_NETWORKS) {
		em_printfout("Cannot add more topologies, max limit reached");
		return;
	}
	for (unsigned int i = 0; i < m_num_topologies; i++) {
		if (m_topology[i]->get_data_model() == dm) {
			// If the topology already exists for this data model,
			// we do not add it again, just return.
			// This is to avoid duplicate entries in the topology.
			// This can happen if the same data model is added multiple times.
			em_printfout("Topology for dev_mac:%s already exists, not adding again", dev_mac_str.c_str());
			return;
		}
	}
	m_topology[m_num_topologies] = new em_network_topo_t(dm);
	em_printfout("Adding new topology for dev_mac:%s parent dev_mac:%s", dev_mac_str.c_str(),
		util::mac_to_string(m_data_model->m_device.m_device_info.intf.mac).c_str());
	//Add child topologies if any
	if (child_topos != NULL && num_child_topos > 0) {
		memcpy(m_topology[m_num_topologies]->m_topology, child_topos, sizeof(em_network_topo_t *) * num_child_topos);
		m_topology[m_num_topologies]->m_num_topologies = num_child_topos;
		em_printfout("Added %d child topologies to the new topo: %s", num_child_topos, dev_mac_str.c_str());
	} else {
		em_printfout("No child topologies to add to the new topo: %s", dev_mac_str.c_str());
	}
	m_num_topologies++;
}

void em_network_topo_t::add(dm_easy_mesh_t *dm, em_network_topo_t **child_topos, unsigned int num_child_topos)
{
	em_network_topo_t *topo;

	// find the BH bss where al_mac of this device of data model is attached to.
	if ((topo = find_topology_by_bh_associated(dm)) != NULL) {
		em_printfout("Found topology in backhaul association tree, adding to it");
		topo->add_network_topo(dm, child_topos, num_child_topos);
	}
	else {
		em_printfout("Could not find topology in backhaul association tree, must be ethernet");
		this->add_network_topo(dm, child_topos, num_child_topos);
	}
}

bool em_network_topo_t::remove(dm_easy_mesh_t *dm, em_network_topo_t **child_topos, unsigned int *num_child_topos)
{
	unsigned int i, index = 0;
	bool found = false;

	std::string dev_mac_str = util::mac_to_string(dm->m_device.m_device_info.intf.mac);
	std::string parent_dev_mac_str = util::mac_to_string(m_data_model->m_device.m_device_info.intf.mac);
	for (i = 0; i < m_num_topologies; i++) {
		if (m_topology[i]->get_data_model() == dm) {
			found = true;
			index = i;
			break;
		}
	}
	if (found == true) {
		if (child_topos != NULL && num_child_topos != NULL) {
			memcpy(child_topos, m_topology[i]->m_topology, sizeof(m_topology[i]->m_topology));
			*num_child_topos = m_topology[i]->m_num_topologies;
		}
		delete m_topology[i];
		for (i = index; i < m_num_topologies - 1; i++) {
			m_topology[i] = m_topology[i + 1];
		}
		em_printfout("Found and Removed topology of dev_mac:%s in parent dm:%s num_child_topos:%d",
			dev_mac_str.c_str(), parent_dev_mac_str.c_str(), m_num_topologies);
		m_num_topologies--;
		return found;
	}

	//If the control comes here then dm is not found in topologies, check within each topologies further
	em_printfout("Could not find topology for dev_mac:%s in parent dm:%s, checking each child topologies",
		dev_mac_str.c_str(), parent_dev_mac_str.c_str());
	//search recursively in the child topologies
	for (i = 0; i < m_num_topologies; i++) {
		if ((found = m_topology[i]->remove(dm, child_topos, num_child_topos)) == true) {
			return found;
		}
	}
	em_printfout("Could not find topology for dev_mac:%s in any child topologies of parent dm:%s",
		dev_mac_str.c_str(), parent_dev_mac_str.c_str());
	return false;
}

em_network_topo_t::em_network_topo_t(dm_easy_mesh_t *dm)
{
	m_num_topologies  = 0;
	m_data_model = dm;
	memset(m_topology, 0, sizeof(m_topology));
}

em_network_topo_t::em_network_topo_t()
{
	m_data_model = NULL;
	m_num_topologies  = 0;
	memset(m_topology, 0, sizeof(m_topology));
}

em_network_topo_t::~em_network_topo_t()
{
	m_data_model = NULL;
}


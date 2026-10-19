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
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <cjson/cJSON.h>
#include "em_network_topo.h"
#include "em.h"
#include "util.h"
#include "dm_sta_list.h"
#include "dm_easy_mesh_ctrl.h"
#include "em_ctrl.h"
#include "em_cmd_ctrl.h"

extern em_network_topo_t *g_network_topology;

void em_network_topo_t::encode(cJSON *parent)
{
	cJSON *dev_obj, *child_obj, *radio_list_obj, *radio_obj, *bss_list_obj, *bss_obj, *bh_obj, *sta_list_obj;
	unsigned int i, j;

	if (m_data_model == NULL) {
		em_printfout("Data model is NULL, cannot encode topology");
		return;
	}

	dev_obj = cJSON_AddObjectToObject(parent, "Device");
	m_data_model->m_device.encode(dev_obj, true);

	radio_list_obj = cJSON_AddArrayToObject(dev_obj, "RadioList");
	for (i = 0; i < m_data_model->m_num_radios; i++) {
		radio_obj = cJSON_CreateObject();
		m_data_model->m_radio[i].encode(radio_obj, em_get_radio_list_reason_radio_summary);
		for (j = 0; j < m_data_model->m_num_opclass; j++){
			em_op_class_info_t *op_class_info = &m_data_model->m_op_class[j].m_op_class_info;
			if ((memcmp(op_class_info->id.ruid, m_data_model->m_radio[i].get_radio_interface_mac(), sizeof(mac_address_t)) == 0) &&
				(op_class_info->id.type == em_op_class_type_current)) {
				cJSON_AddNumberToObject(radio_obj, "Class", op_class_info->op_class);
				cJSON_AddNumberToObject(radio_obj, "Channel", op_class_info->channel);
				em_printfout("Radio %s Current Operating Class: %d Channel: %d",
					util::mac_to_string(m_data_model->m_radio[i].get_radio_interface_mac()).c_str(),
					op_class_info->op_class, op_class_info->channel);
			}
		}
		cJSON_AddItemToArray(radio_list_obj, radio_obj);
		bss_list_obj = cJSON_AddArrayToObject(radio_obj, "BSSList");
		for (j = 0; j < m_data_model->m_num_bss; j++) {
			if (memcmp(m_data_model->m_bss[j].m_bss_info.id.ruid, 
							m_data_model->m_radio[i].m_radio_info.id.ruid, sizeof(mac_address_t)) == 0) {
				bss_obj = cJSON_CreateObject();
				m_data_model->m_bss[j].encode(bss_obj, true);
				const em_network_ssid_info_t* network_ssid_info = m_data_model->get_network_ssid_info_by_haul_type(m_data_model->m_bss[j].m_bss_info.id.haul_type);
				if (network_ssid_info != NULL) {
				    cJSON_AddNumberToObject(bss_obj, "VlanID", network_ssid_info->vlan_id);
				}
				sta_list_obj = cJSON_AddArrayToObject(bss_obj, "STAList");
				dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();
				if (dm_ctrl != NULL) {
					// Get the Station associated with this bss only if vap mode is ap
					if (m_data_model->m_bss[j].m_bss_info.vap_mode == em_vap_mode_ap) {
						std::string bss_mac_str = util::mac_to_string(m_data_model->m_bss[j].m_bss_info.bssid.mac);
						dm_ctrl->dm_sta_list_t::get_config(sta_list_obj,
							static_cast<void*>(const_cast<char*> (bss_mac_str.c_str())),
							em_get_sta_list_reason_topology);
					}
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
	// bss->id.bssid  = local bSTA interface MAC (used to locate the parent topology node)
	// bss->bssid.mac = upstream AP BSSID the bSTA is associated to (shown in Backhaul.MACAddress)
	mac_address_t bss_mac;
	memcpy(bss_mac, bss->id.bssid, sizeof(mac_address_t));
	// If bSTA BSS bssid is zero (e.g. after M1 BSS rebuild during bhreconfig),
	// fall back to the device's backhaul_mac which was set during M1 processing.
	if (memcmp(bss_mac, ZERO_MAC_ADDR, sizeof(mac_address_t)) == 0 &&
		memcmp(dm->m_device.m_device_info.backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(mac_address_t)) != 0) {
		memcpy(bss_mac, dm->m_device.m_device_info.backhaul_mac.mac, sizeof(mac_address_t));
		em_printfout("bSTA BSS bssid is zero, using device backhaul_mac: %s", util::mac_to_string(bss_mac).c_str());
	}
	if (dm->is_controller() == false) {
		// Set BackhaulMACAddress to the upstream AP BSSID, not the local bSTA MAC
		memcpy(dm->m_device.m_device_info.backhaul_mac.mac, bss->bssid.mac, sizeof(mac_address_t));
		dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee80211ac_5;
		if (memcmp(bss->bssid.mac, ZERO_MAC_ADDR, sizeof(mac_address_t)) == 0) {
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

	if (m_data_model == dm) {
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
	if (g_network_topology != NULL) {
		g_network_topology->apply_restored_bh_progress(m_topology[m_num_topologies]);
	}
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
	if (dm == NULL) {
		em_printfout("dm is NULL, cannot add topology");
		return;
	}

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

bool em_network_topo_t::is_bh_reconfig_complete()
{
	if (m_data_model != NULL && m_data_model->is_controller() &&
 			m_data_model->get_num_radios() == 0) {
 		for (unsigned int i = 0; i < m_num_topologies; i++) {
 			if (!m_topology[i]->is_bh_reconfig_complete()) {
 				return false;
 			}
 		}
 		return true;
 	}
	return m_bh_processed;
}

void em_network_topo_t::reset_bh_state()
{
	m_bh_restored.clear();
	m_bh_m8_validated.clear();
	m_bh_processed = false;
	m_bh_reconfig_incomplete = false;
	for (unsigned int i = 0; i < m_num_topologies; i++) {
		m_topology[i]->reset_bh_state();
	}
}

void em_network_topo_t::reset_bh_reconfig()
{
	reset_bh_state();
	persist_bh_reconfig_pending();
}

void em_network_topo_t::set_bh_reconfig_active(bool active)
{
	m_bh_reconfig_active = active;
	persist_bh_reconfig_pending();
}

void em_network_topo_t::set_bh_reconfig_incomplete(bool incomplete)
{
	m_bh_reconfig_incomplete = incomplete;
	persist_bh_reconfig_pending();
}

void em_network_topo_t::set_bh_processed(bool processed)
{
	m_bh_processed = processed;
	if (g_network_topology != NULL) {
		g_network_topology->persist_bh_reconfig_pending();
	}
}

void em_network_topo_t::collect_bh_processed(std::string &out)
{
	if (m_bh_processed && m_data_model != NULL) {
		out += "P " + util::mac_to_string(m_data_model->m_device.m_device_info.intf.mac) + "\n";
	}
	for (unsigned int i = 0; i < m_num_topologies; i++) {
		m_topology[i]->collect_bh_processed(out);
	}
}

/* Root only: a file exists exactly while a reconfiguration is running or stopped part-way. It lists
 * the devices that already applied the credentials, which are already in the database, so after a
 * restart the same request resumes with only the remaining devices. */
void em_network_topo_t::persist_bh_reconfig_pending()
{
	if (m_bh_reconfig_active || m_bh_reconfig_incomplete) {
		std::string progress;
		collect_bh_processed(progress);
		for (const std::string& mac : m_bh_restored) {
 			const std::string record = "P " + mac + "\n";
 			if (progress.find(record) == std::string::npos) {
 				progress += record;
 			}
 		}
		for (const std::string& mac : m_bh_m8_validated) {
			progress += "M " + mac + "\n";
		}// Credentials changed: devices that applied the previous set must receive this one too,
        // so progress is deliberately discarded. An unchanged repeat resumes via the path above.
		char temp_path[] = EM_BH_RECONFIG_PENDING_FILE ".XXXXXX";
 		int fd = mkstemp(temp_path);
		if (fd < 0) {
			em_printfout("Failed to create backhaul recovery checkpoint: %s", strerror(errno));
			return;
		}
		int write_error = 0;
 		size_t offset = 0;
 		while (offset < progress.size()) {
 			ssize_t written = write(fd, progress.data() + offset, progress.size() - offset);
 			if (written < 0 && errno == EINTR) {
 				continue;
 			}
 			if (written <= 0) {
 				write_error = (written < 0) ? errno : EIO;
 				break;
 			}
 			offset += static_cast<size_t>(written);
		}
		if (write_error == 0 && fsync(fd) != 0) {
 			write_error = errno;
 		}
 		if (close(fd) != 0 && write_error == 0) {
 			write_error = errno;
 		}
 		if (write_error == 0 && rename(temp_path, EM_BH_RECONFIG_PENDING_FILE) != 0) {
 			write_error = errno;
 		}
 		if (write_error != 0) {
 			em_printfout("Failed to persist backhaul recovery checkpoint: %s", strerror(write_error));
 			unlink(temp_path);
 			return;
 		}
 		const std::string checkpoint_path = EM_BH_RECONFIG_PENDING_FILE;
 		const std::string directory = checkpoint_path.substr(0, checkpoint_path.find_last_of('/'));
 		int dir_fd = open(directory.c_str(), O_RDONLY | O_DIRECTORY);
 		if (dir_fd < 0) {
 			em_printfout("Failed to open backhaul checkpoint directory: %s", strerror(errno));
 			return;
 		}
 		if (fsync(dir_fd) != 0) {
 			em_printfout("Failed to sync backhaul checkpoint directory: %s", strerror(errno));
 		}
 		close(dir_fd);
	} else if ((unlink(EM_BH_RECONFIG_PENDING_FILE) != 0) && (errno != ENOENT)) {
		em_printfout("Failed to clear pending backhaul reconfiguration: %s", strerror(errno));
	}
}

void em_network_topo_t::restore_bh_reconfig_pending()
{
	FILE *fp = fopen(EM_BH_RECONFIG_PENDING_FILE, "r");
	char line[64];

	if (fp == NULL) {
		return;
	}
	em_printfout("Unfinished backhaul reconfiguration found, a repeated SetBhCfg will resume it");
	m_bh_reconfig_active = false;
	m_bh_reconfig_incomplete = true;
	m_bh_restored.clear();
	m_bh_m8_validated.clear();
	while (fgets(line, sizeof(line), fp) != NULL) {
		line[strcspn(line, "\r\n")] = '\0';
		if (line[0] == 'M' && line[1] == ' ') {
			m_bh_m8_validated.push_back(line + 2);
		} else if (line[0] == 'P' && line[1] == ' ') {
			m_bh_restored.push_back(line + 2);
		} else if (line[0] != '\0') {
			m_bh_restored.push_back(line);
		}
	}
	fclose(fp);
	apply_restored_bh_progress(this);
}

void em_network_topo_t::set_bh_m8_validated(const std::vector<std::string>& macs)
{
	m_bh_m8_validated = macs;
	persist_bh_reconfig_pending();
}

bool em_network_topo_t::is_bh_m8_validated(const std::string& mac)
{
	return std::find(m_bh_m8_validated.begin(), m_bh_m8_validated.end(), mac) != m_bh_m8_validated.end();
}

void em_network_topo_t::apply_restored_bh_progress(em_network_topo_t *node)
{
	if (m_bh_restored.empty() || node == NULL || node->m_data_model == NULL) {
		return;
	}
	std::string mac = util::mac_to_string(node->m_data_model->m_device.m_device_info.intf.mac);
	if (std::find(m_bh_restored.begin(), m_bh_restored.end(), mac) != m_bh_restored.end()) {
		node->m_bh_processed = true;
	}
}

bool em_network_topo_t::is_bh_reconfig_candidate()
{
	if (m_bh_processed) {
		return false;
	}

	for (unsigned int i = 0; i < m_num_topologies; i++) {
		if (!m_topology[i]->m_bh_processed) {
			return false;
		}
	}

	return true;
}

void em_network_topo_t::mark_bh_leaves_processed()
{
	for (unsigned int i = 0; i < m_num_topologies; i++) {
		m_topology[i]->mark_bh_leaves_processed();
	}
	if (is_bh_reconfig_candidate()) {
		m_bh_processed = true;
	}
}

void em_network_topo_t::send_bh_reconfig_event()
{
	em_ctrl_t *ctrl = em_ctrl_t::get_em_ctrl_instance();
	em_cmd_params_t params;
	memset(&params, 0, sizeof(em_cmd_params_t));
	ctrl->io_process(em_bus_event_type_set_bh_cfg, static_cast<char *>(NULL), 0, &params);
}

em_network_topo_t::em_network_topo_t(dm_easy_mesh_t *dm)
{
	m_num_topologies  = 0;
	m_data_model = dm;
	m_bh_processed = false;
	m_bh_reconfig_active = false;
	m_bh_reconfig_incomplete = false;
	memset(m_topology, 0, sizeof(m_topology));
}

em_network_topo_t::em_network_topo_t()
{
	m_data_model = NULL;
	m_num_topologies  = 0;
	m_bh_processed = false;
	m_bh_reconfig_active = false;
	m_bh_reconfig_incomplete = false;
	memset(m_topology, 0, sizeof(m_topology));
}

bool em_network_topo_t::is_direct_child(dm_easy_mesh_t *dm)
{
	for (unsigned int i = 0; i < m_num_topologies; i++) {
		if (m_topology[i]->get_data_model() == dm) {
			return true;
		}
	}
	return false;
}

em_network_topo_t::~em_network_topo_t()
{
	m_data_model = NULL;
}


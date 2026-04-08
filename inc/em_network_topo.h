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

#ifndef EM_NETWORK_TOPO_H
#define EM_NETWORK_TOPO_H

#include "em_base.h"
#include "dm_easy_mesh.h"

class em_orch_t;
class em_cmd_t;

class em_network_topo_t {

	dm_easy_mesh_t	*m_data_model;
	unsigned int m_num_topologies;	
	em_network_topo_t	*m_topology[EM_MAX_NETWORKS];

	// Backhaul reconfig state (per-node):
	// Tracks whether this node's radios have been submitted as candidates
	// during the current multi-phase backhaul reconfiguration.
	bool m_bh_processed;

	// Backhaul reconfig state (root-only):
	// Set to true when a multi-phase backhaul reconfiguration is in progress.
	// Used by handle_set_bh_cfg to distinguish re-triggered bus events from
	// the initial ioprocess call.
	bool m_bh_reconfig_active;

public:
	
	/**!
	 * @brief Finds the network topology associated with a given MAC address.
	 *
	 * This function searches for and returns the network topology that is associated
	 * with the specified MAC address of a station (STA).
	 *
	 * @param[in] sta The MAC address of the station for which the network topology
	 *                is to be found.
	 *
	 * @returns A pointer to the network topology associated with the given MAC address.
	 * @retval NULL if no associated topology is found.
	 *
	 * @note Ensure that the MAC address provided is valid and corresponds to a station
	 *       within the network.
	 */
	em_network_topo_t *find_topology_by_bh_associated(mac_address_t sta);
	
	/**!
	 * @brief Finds the network topology associated with a given data model.
	 *
	 * This function searches within the data model, the associated backhaul
	 * sta and returns the network topology of the corresponding bssID which is
	 * associated with that sta. This is required when the AL_SAP define is
	 * enabled as the al_interface is associated with a virtual MAC address
	 *
	 * @param[in] dm The data model for which the network topology is to be found.
	 *
	 * @returns A pointer to the network topology associated with the given data model.
	 * @retval NULL if no associated topology is found.
	 *
	 */
	em_network_topo_t *find_topology_by_bh_associated(dm_easy_mesh_t *dm);

	/**!
	 * @brief Finds the network topology associated with a given BSS MAC address.
	 *
	 * This function searches for and returns the network topology that is associated
	 * with the specified BSS MAC address.
	 *
	 * @param[in] bss_mac The MAC address of the BSS for which the network topology
	 *                    is to be found.
	 *
	 * @returns A pointer to the network topology associated with the given BSS MAC address.
	 * @retval NULL if no associated topology is found.
	 *
	 * @note Ensure that the BSS MAC address provided is valid and corresponds to a BSS
	 *       within the network.
	 */
	em_network_topo_t *find_topology_by_bss_mac(mac_address_t bss_mac);

	/**!
	 * @brief Prints the network topology tree.
	 *
	 * This function recursively prints the network topology tree, starting from the
	 * root node.
	 */
	void print_topology();

	/**!
	 * @brief Finds the network topology based on the provided EasyMesh data.
	 *
	 * This function searches for and returns the network topology structure
	 * associated with the given EasyMesh data.
	 *
	 * @param[in] dm Pointer to the EasyMesh data structure.
	 *
	 * @returns Pointer to the network topology structure.
	 * @retval NULL if the topology cannot be found or an error occurs.
	 *
	 * @note Ensure that the EasyMesh data is properly initialized before calling this function.
	 */
	em_network_topo_t *find_topology(dm_easy_mesh_t *dm);
	
	/**!
	 * @brief Retrieves the data model instance.
	 *
	 * This function returns a pointer to the current data model instance used in the network topology.
	 *
	 * @returns A pointer to the `dm_easy_mesh_t` data model instance.
	 * @note Ensure that the returned pointer is not null before using it.
	 */
	dm_easy_mesh_t *get_data_model() { return m_data_model; }

	/**!
	 * @brief Builds candidates for the next unprocessed leaf layer during backhaul reconfig.
	 *
	 * Recursively walks the topology tree. A node is eligible when it has not
	 * yet been processed and all of its children are already processed (leaf
	 * nodes have zero children, so they always qualify first). Eligible nodes
	 * get their radios pushed into the command's candidate queue and are
	 * marked processed so subsequent calls skip them.
	 *
	 * @param[in] em_map Hash map of em_t nodes keyed by radio MAC string.
	 * @param[in] pcmd   Command whose m_em_candidates queue will be populated.
	 *
	 * @returns Number of radios added as candidates in this call.
	 */
	int backhaul_reconfig(hash_map_t *em_map, em_cmd_t *pcmd);

	/**!
	 * @brief Checks whether the entire topology tree has been processed.
	 *
	 * @returns true if the root node (this) is marked processed, meaning all
	 *          layers including the co-located agent have been handled.
	 */
	bool is_bh_reconfig_complete();

	/**!
	 * @brief Returns whether a multi-phase backhaul reconfig is currently active.
	 *
	 * Only meaningful on the root topology node (g_network_topology).
	 *
	 * @returns true if set_bh_cfg multi-phase reconfig is in progress.
	 */
	bool is_bh_reconfig_active() { return m_bh_reconfig_active; }

	/**!
	 * @brief Sets the multi-phase backhaul reconfig active flag.
	 *
	 * @param[in] active true to mark reconfig as active, false to deactivate.
	 */
	void set_bh_reconfig_active(bool active) { m_bh_reconfig_active = active; }

	/**!
	 * @brief Marks this node as processed for backhaul reconfig.
	 *
	 * @param[in] processed true to mark as processed, false to clear.
	 */
	void set_bh_processed(bool processed) { m_bh_processed = processed; }

	/**!
	 * @brief Sends an internal em_bus_event_type_set_bh_cfg bus event.
	 *
	 * Used after a leaf layer completes to re-trigger handle_set_bh_cfg so
	 * the next unprocessed layer gets submitted.
	 */
	void send_bh_reconfig_event();

	/**!
	 * @brief Resets m_bh_processed to false on all nodes in the topology tree.
	 *
	 * Called before starting a new backhaul reconfig cycle and after the
	 * final layer completes.
	 */
	void reset_bh_reconfig();

	/**!
	 * @brief Checks if this topology node is a current-layer leaf for backhaul reconfig.
	 *
	 * A node is a current-layer leaf when it has not yet been processed and
	 * all of its children are already processed (true leaves have zero children).
	 *
	 * @returns true if this node should contribute candidates in the current phase.
	 */
	bool is_bh_reconfig_candidate();

	/**!
	 * @brief Marks all current-layer leaf nodes as processed.
	 *
	 * Walks the tree and marks nodes whose children are all processed.
	 * Called after build_candidates has pushed all leaf-layer radios.
	 */
	void mark_bh_leaves_processed();
	
	
	/**!
	 * @brief Adds a new mesh network to the system.
	 *
	 * This function integrates a new mesh network into the existing topology.
	 *
	 * @param[in] dm Pointer to the mesh network structure to be added.
	 * @param[in] child_topos Array of child topologies to be added under the new mesh network.
	 * @param[in] num_child_topos Number of child topologies to be added.
	 *
	 * @note Ensure that the mesh network structure is properly initialized before calling this function.
	 */
	void add(dm_easy_mesh_t *dm, em_network_topo_t **child_topos = NULL, unsigned int num_child_topos = 0);
	
	/**!
	 * @brief Removes a specified easy mesh network.
	 *
	 * This function is responsible for removing the easy mesh network
	 * associated with the provided `dm_easy_mesh_t` pointer.
	 *
	 * @param[in] dm A pointer to the `dm_easy_mesh_t` structure representing
	 * the easy mesh network to be removed.
	 * @param[out] child_topos An array of pointers to `em_network_topo_t` structures
	 *
	 * @returns The number of child topologies of the removed parent topology.
	 * @note Ensure that the `dm` pointer is valid and properly initialized
	 * before calling this function.
	 */
	bool remove(dm_easy_mesh_t *dm, em_network_topo_t **child_topos = NULL, unsigned int *num_child_topos = NULL);

	
	/**!
	 * @brief Adds a network topology to the specified EasyMesh instance.
	 *
	 * This function integrates a new network topology into the provided EasyMesh instance, allowing for enhanced network management and configuration.
	 *
	 * @param[in] dm Pointer to the EasyMesh instance where the network topology will be added.
	 * @param[in] child_topos Optional. An array of child topologies to be added under the new network topology.
	 * @param[in] num_child_topos Optional. The number of child topologies to be added.
	 *
	 * @note Ensure that the EasyMesh instance is properly initialized before calling this function.
	 */
	void add_network_topo(dm_easy_mesh_t *dm, em_network_topo_t **child_topos = NULL, unsigned int num_child_topos = 0);
	
	/**!
	 * @brief Encodes the given cJSON object.
	 *
	 * This function takes a cJSON object and performs encoding operations.
	 *
	 * @param[in] obj The cJSON object to be encoded.
	 *
	 * @note Ensure the cJSON object is properly initialized before calling this function.
	 */
	void encode(cJSON *obj);

    
	/**!
	 * @brief Creates a network topology object from the given EasyMesh object.
	 *
	 * This function initializes a network topology object using the provided
	 * EasyMesh object. It is responsible for setting up the necessary
	 * configurations and parameters to represent the network topology.
	 *
	 * @param[in] dm Pointer to the EasyMesh object used to create the network topology.
	 *
	 * @returns A network topology object initialized with the given EasyMesh object.
	 *
	 * @note Ensure that the EasyMesh object is properly initialized before
	 * calling this function.
	 */
	em_network_topo_t(dm_easy_mesh_t *dm);
    
	/**!
	 * @brief Constructor for the em_network_topo_t class.
	 *
	 * Initializes a new instance of the em_network_topo_t class.
	 *
	 * @note This constructor does not take any parameters and does not return any values.
	 */
	em_network_topo_t();
    
	/**!
	 * @brief Destructor for the em_network_topo_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the em_network_topo_t instance.
	 *
	 * @note Ensure that all dynamically allocated resources are properly released.
	 */
	~em_network_topo_t();
};

#endif

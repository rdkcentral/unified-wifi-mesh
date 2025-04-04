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


#ifndef DM_EM_LIST_H
#define DM_EM_LIST_H

#include "em_base.h"
#include "dm_easy_mesh.h"

class em_mgr_t;

class dm_easy_mesh_list_t {
    em_long_string_t	m_network_list[EM_MAX_NETWORKS];
    unsigned int m_num_networks;
    hash_map_t  *m_list;
    em_mgr_t *m_mgr;

public:

    
	/**!
	 * @brief Retrieves the data model associated with a given network ID and AL MAC address.
	 *
	 * This function searches for the data model corresponding to the specified network
	 * identifier and AL MAC address, returning a pointer to the data model if found.
	 *
	 * @param[in] net_id The network identifier for which the data model is requested.
	 * @param[in] al_mac The AL MAC address associated with the network.
	 *
	 * @returns A pointer to the `dm_easy_mesh_t` structure representing the data model.
	 * @retval NULL if the data model is not found or if the inputs are invalid.
	 *
	 * @note Ensure that `net_id` and `al_mac` are valid and correctly formatted before
	 * calling this function.
	 */
	dm_easy_mesh_t *get_data_model(const char *net_id, const unsigned char *al_mac);
    
	/**!
	 * @brief Creates a data model for the EasyMesh network.
	 *
	 * This function initializes and returns a data model object for the specified
	 * network identifier and interface, with the given profile type. Optionally,
	 * the data model can be marked as colocated.
	 *
	 * @param[in] net_id The network identifier for which the data model is created.
	 * @param[in] al_intf Pointer to the interface structure used for the data model.
	 * @param[in] profile The profile type to be used for the data model.
	 * @param[in] colocated_dm Optional parameter to specify if the data model is colocated.
	 *
	 * @returns Pointer to the created data model object.
	 * @retval NULL if the creation fails.
	 *
	 * @note Ensure that the network identifier and interface are valid before calling this function.
	 */
	dm_easy_mesh_t *create_data_model(const char *net_id, const em_interface_t *al_intf, em_profile_type_t profile, bool colocated_dm = false);
    
	/**!
	 * @brief Deletes a data model associated with a given network ID and AL MAC address.
	 *
	 * This function removes the data model identified by the specified network ID and AL MAC address from the system.
	 *
	 * @param[in] net_id The network identifier for the data model to be deleted.
	 * @param[in] al_mac The AL MAC address associated with the data model.
	 *
	 * @note Ensure that the network ID and AL MAC address are valid and correspond to an existing data model.
	 */
	void delete_data_model(const char *net_id, const unsigned char *al_mac);
    
	/**!
	 * @brief Deletes all data models from the system.
	 *
	 * This function removes all existing data models, ensuring that the system is reset to a state without any data models.
	 *
	 * @note Use this function with caution as it will remove all data models permanently.
	 */
	void delete_all_data_models();

    
	/**!
	 * @brief Debugs the probe functionality.
	 *
	 * This function is used to initiate a debug sequence for the probe.
	 *
	 * @note Ensure that the system is in a stable state before calling this function.
	 */
	void debug_probe();

    
	/**!
	 * @brief Initializes the Easy Mesh manager.
	 *
	 * This function sets up the necessary configurations and state for the Easy Mesh manager.
	 *
	 * @param[in] mgr Pointer to the Easy Mesh manager structure.
	 *
	 * @note Ensure that the manager structure is properly allocated before calling this function.
	 */
	void init(em_mgr_t *mgr);

    
	/**!
	 * @brief Retrieves the first element from the mesh list.
	 *
	 * This function returns the first element in the mesh list by utilizing the
	 * hash_map_get_first function to access the initial entry.
	 *
	 * @returns A pointer to the first dm_easy_mesh_t element in the list.
	 * @retval nullptr If the list is empty or an error occurs.
	 *
	 * @note Ensure that the list is properly initialized before calling this function.
	 */
	dm_easy_mesh_t *get_first_dm() { return static_cast<dm_easy_mesh_t *>(hash_map_get_first(m_list)); }
    
	/**!
	 * @brief Retrieves the next dm_easy_mesh_t object from the list.
	 *
	 * This function returns the next dm_easy_mesh_t object in the list
	 * following the provided dm_easy_mesh_t object.
	 *
	 * @param[in] dm The current dm_easy_mesh_t object from which the next
	 * object is to be retrieved.
	 *
	 * @returns A pointer to the next dm_easy_mesh_t object in the list.
	 *
	 * @note If the provided dm object is the last in the list, the function
	 * will return nullptr.
	 */
	dm_easy_mesh_t *get_next_dm(dm_easy_mesh_t *dm) { return static_cast<dm_easy_mesh_t *>(hash_map_get_next(m_list, dm)); }

    
	/**!
	 * @brief Retrieves the first network from the list.
	 *
	 * This function returns a pointer to the first network in the list of networks.
	 *
	 * @returns A pointer to the first network in the list.
	 * @retval NULL if the list is empty or an error occurs.
	 *
	 * @note Ensure that the list is initialized before calling this function.
	 */
	dm_network_t *get_first_network();
    
	/**!
	 * @brief Retrieves the next network in the list.
	 *
	 * This function takes a pointer to a network and returns a pointer to the next network in the list.
	 *
	 * @param[in] net Pointer to the current network.
	 *
	 * @returns Pointer to the next network in the list.
	 * @retval NULL if there is no next network.
	 *
	 * @note Ensure that the provided network pointer is valid before calling this function.
	 */
	dm_network_t *get_next_network(dm_network_t *net);
    
	/**!
	 * @brief Retrieves the network associated with the given key.
	 *
	 * This function searches for and returns the network object that corresponds
	 * to the specified key.
	 *
	 * @param[in] key A constant character pointer representing the key used to
	 * identify the network.
	 *
	 * @returns A pointer to the dm_network_t structure representing the network
	 * associated with the key. Returns NULL if no matching network is found.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing
	 * network.
	 */
	dm_network_t *get_network(const char *key);
    
	/**!
	 * @brief Removes a network from the list based on the provided key.
	 *
	 * This function searches for the network associated with the given key and removes it from the list.
	 *
	 * @param[in] key A pointer to a character string representing the key of the network to be removed.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing network in the list.
	 */
	void remove_network(const char *key);
    
	/**!
	 * @brief Adds a network to the list using the specified key.
	 *
	 * This function inserts a network into the list, associating it with the given key.
	 *
	 * @param[in] key A pointer to a character string representing the key for the network.
	 * @param[in] net A pointer to a dm_network_t structure containing the network details to be added.
	 *
	 * @note Ensure that the key and network are valid and properly initialized before calling this function.
	 */
	void put_network(const char *key, const dm_network_t *net);

    
	/**!
	 * @brief Retrieves the first device from the list.
	 *
	 * This function returns a pointer to the first device in the mesh list.
	 *
	 * @returns A pointer to the first device in the list.
	 * @retval NULL if the list is empty or an error occurs.
	 *
	 * @note Ensure that the list is initialized before calling this function.
	 */
	dm_device_t *get_first_device();
    
	/**!
	 * @brief Retrieves the next device in the list.
	 *
	 * This function takes a device as input and returns the next device in the list.
	 *
	 * @param[in] dev Pointer to the current device.
	 *
	 * @returns Pointer to the next device in the list.
	 * @retval NULL if there are no more devices.
	 *
	 * @note Ensure that the device list is properly initialized before calling this function.
	 */
	dm_device_t *get_next_device(dm_device_t *dev);
    
	/**!
	 * @brief Retrieves a device based on the provided key.
	 *
	 * This function searches for a device using the specified key and returns a pointer to the device if found.
	 *
	 * @param[in] key A constant character pointer representing the key used to search for the device.
	 *
	 * @returns A pointer to the `dm_device_t` structure if the device is found, otherwise `nullptr`.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing device.
	 */
	dm_device_t *get_device(const char *key);
    
	/**!
	 * @brief Removes a device from the list using the specified key.
	 *
	 * This function searches for a device in the list that matches the given key and removes it.
	 *
	 * @param[in] key A constant character pointer representing the key of the device to be removed.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing device in the list.
	 */
	void remove_device(const char *key);
    
	/**!
	 * @brief Adds a device to the mesh network.
	 *
	 * This function associates a device with a given key and adds it to the mesh network.
	 *
	 * @param[in] key A unique identifier for the device.
	 * @param[in] dev A pointer to the device structure to be added.
	 *
	 * @note Ensure that the key is unique and the device structure is properly initialized before calling this function.
	 */
	void put_device(const char *key, const dm_device_t *dev);

    
	/**!
	 * @brief Retrieves the first radio from the list.
	 *
	 * This function returns a pointer to the first radio in the list of radios.
	 *
	 * @returns A pointer to the first `dm_radio_t` object.
	 * @retval NULL if the list is empty or an error occurs.
	 *
	 * @note Ensure that the list is initialized before calling this function.
	 */
	dm_radio_t *get_first_radio();
    
	/**!
	 * @brief Retrieves the next radio in the list.
	 *
	 * This function takes a pointer to a radio and returns a pointer to the next radio in the list.
	 *
	 * @param[in] radio Pointer to the current radio.
	 *
	 * @returns Pointer to the next radio in the list.
	 * @retval NULL if there is no next radio.
	 *
	 * @note Ensure that the radio list is properly initialized before calling this function.
	 */
	dm_radio_t *get_next_radio(dm_radio_t *radio);
    
	/**!
	 * @brief Retrieves a radio object associated with the given key.
	 *
	 * This function searches for a radio object using the specified key and returns a pointer to the radio object if found.
	 *
	 * @param[in] key A constant character pointer representing the key used to search for the radio object.
	 *
	 * @returns A pointer to the dm_radio_t object associated with the given key.
	 * @retval NULL if no radio object is found for the specified key.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing radio object.
	 */
	dm_radio_t *get_radio(const char *key);
    
	/**!
	 * @brief Removes a radio entry identified by the given key.
	 *
	 * This function searches for a radio entry in the list using the provided key
	 * and removes it if found.
	 *
	 * @param[in] key A constant character pointer representing the key of the radio
	 * entry to be removed. It must not be NULL.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing
	 * radio entry in the list.
	 */
	void remove_radio(const char *key);
    
	/**!
	 * @brief Puts a radio configuration into the system.
	 *
	 * This function stores the radio configuration specified by the `radio` parameter
	 * into the system using the provided `key`.
	 *
	 * @param[in] key A string representing the key associated with the radio configuration.
	 * @param[in] radio A pointer to a `dm_radio_t` structure containing the radio configuration.
	 *
	 * @note Ensure that the `key` is unique and the `radio` pointer is valid before calling this function.
	 */
	void put_radio(const char *key, const dm_radio_t *radio);
    
	/**!
	 * @brief Retrieves the first radio associated with a given network ID and AL MAC address.
	 *
	 * This function searches for the first radio that matches the specified network ID and AL MAC address.
	 *
	 * @param[in] net_id The network identifier to search for.
	 * @param[in] al_mac The AL MAC address associated with the radio.
	 *
	 * @returns A pointer to the first matching dm_radio_t structure.
	 * @retval NULL if no matching radio is found.
	 *
	 * @note Ensure that the net_id and al_mac are valid and correspond to an existing radio.
	 */
	dm_radio_t *get_first_radio(const char *net_id, mac_address_t al_mac);
    
	/**!
	 * @brief Retrieves the next radio in the list based on the network ID and AL MAC address.
	 *
	 * This function searches for the next available radio in the list that matches the given network ID and AL MAC address.
	 *
	 * @param[in] net_id The network identifier used to filter radios.
	 * @param[in] al_mac The AL MAC address used to filter radios.
	 * @param[out] radio Pointer to the current radio structure. This will be updated to point to the next radio.
	 *
	 * @returns Pointer to the next dm_radio_t structure if found, otherwise NULL.
	 *
	 * @note Ensure that the radio list is properly initialized before calling this function.
	 */
	dm_radio_t *get_next_radio(const char *net_id, mac_address_t al_mac, dm_radio_t *radio);

    
	/**!
	 * @brief Retrieves the first BSS (Basic Service Set) from the list.
	 *
	 * @returns A pointer to the first `dm_bss_t` structure in the list.
	 * @retval NULL if the list is empty or an error occurs.
	 *
	 * @note Ensure that the list is initialized before calling this function.
	 */
	dm_bss_t *get_first_bss();
    
	/**!
	 * @brief Retrieves the next BSS (Basic Service Set) in the list.
	 *
	 * This function takes a pointer to a BSS and returns a pointer to the next BSS in the list.
	 *
	 * @param[in] bss Pointer to the current BSS from which the next BSS is to be retrieved.
	 *
	 * @returns Pointer to the next BSS in the list.
	 * @retval NULL if there is no next BSS or if the input BSS is NULL.
	 *
	 * @note Ensure that the input BSS is valid and part of a list before calling this function.
	 */
	dm_bss_t *get_next_bss(dm_bss_t *bss);
    
	/**!
	 * @brief Retrieves the BSS (Basic Service Set) associated with the given key.
	 *
	 * This function searches for and returns a pointer to the BSS structure
	 * that matches the specified key.
	 *
	 * @param[in] key A constant character pointer representing the key used to
	 * identify the desired BSS.
	 *
	 * @returns A pointer to the `dm_bss_t` structure if a matching BSS is found,
	 * otherwise returns `nullptr`.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing
	 * BSS in the system.
	 */
	dm_bss_t *get_bss(const char *key);
    
	/**!
	 * @brief Removes a BSS entry identified by the given key.
	 *
	 * This function searches for a BSS (Basic Service Set) entry using the provided key and removes it from the list.
	 *
	 * @param[in] key A constant character pointer representing the key of the BSS entry to be removed.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing BSS entry.
	 */
	void remove_bss(const char *key);
    
	/**!
	 * @brief Adds a BSS entry to the list.
	 *
	 * This function inserts a BSS (Basic Service Set) entry into the list using the specified key.
	 *
	 * @param[in] key A constant character pointer representing the key associated with the BSS entry.
	 * @param[in] bss A pointer to a dm_bss_t structure containing the BSS information to be added.
	 *
	 * @note Ensure that the key and bss parameters are valid and properly initialized before calling this function.
	 */
	void put_bss(const char *key, const dm_bss_t *bss);

    
	/**!
	 * @brief Retrieves the first station from the list.
	 *
	 * This function returns a pointer to the first station in the list.
	 *
	 * @returns A pointer to the first station (`dm_sta_t`).
	 * @retval NULL if the list is empty or an error occurs.
	 *
	 * @note Ensure that the list is initialized before calling this function.
	 */
	dm_sta_t *get_first_sta();
    
	/**!
	 * @brief Retrieves the next station in the list.
	 *
	 * This function takes a pointer to a station and returns a pointer to the next station in the list.
	 *
	 * @param[in] sta Pointer to the current station.
	 *
	 * @returns Pointer to the next station in the list.
	 * @retval NULL if there is no next station.
	 *
	 * @note Ensure that the provided station pointer is valid and part of the list.
	 */
	dm_sta_t *get_next_sta(dm_sta_t *sta);
    
	/**!
	 * @brief Retrieves the station information associated with the given key.
	 *
	 * This function searches for and returns the station information that corresponds to the specified key.
	 *
	 * @param[in] key A constant character pointer representing the key used to find the station.
	 *
	 * @returns A pointer to a dm_sta_t structure containing the station information if found, otherwise NULL.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing station.
	 */
	dm_sta_t *get_sta(const char *key);
    
	/**!
	 * @brief Removes a station identified by the given key.
	 *
	 * This function removes a station from the list using the specified key.
	 *
	 * @param[in] key A constant character pointer representing the key of the station to be removed.
	 *
	 * @note Ensure that the key provided is valid and exists in the list.
	 */
	void remove_sta(const char *key);
    
	/**!
	 * @brief Adds a station to the mesh list.
	 *
	 * This function inserts a station identified by the given key into the mesh list.
	 *
	 * @param[in] key A pointer to a character string representing the station's unique key.
	 * @param[in] sta A pointer to a dm_sta_t structure containing the station's details.
	 *
	 * @note Ensure that the key and sta pointers are valid before calling this function.
	 */
	void put_sta(const char *key, const dm_sta_t *sta);

    
	/**!
	 * @brief Retrieves the first network SSID from the list.
	 *
	 * @returns A pointer to the first network SSID.
	 * @retval NULL if the list is empty or an error occurs.
	 */
	dm_network_ssid_t *get_first_network_ssid();
    
	/**!
	 * @brief Retrieves the next network SSID in the list.
	 *
	 * This function takes a pointer to a network SSID and returns a pointer to the next network SSID in the list.
	 *
	 * @param[in] network_ssid Pointer to the current network SSID.
	 *
	 * @returns Pointer to the next network SSID in the list.
	 * @retval NULL if there are no more SSIDs in the list.
	 *
	 * @note Ensure that the provided network_ssid is valid and part of the list.
	 */
	dm_network_ssid_t *get_next_network_ssid(dm_network_ssid_t *network_ssid);
    
	/**!
	 * @brief Retrieves the network SSID associated with the given key.
	 *
	 * This function searches for the network SSID using the provided key and returns a pointer to the corresponding dm_network_ssid_t structure.
	 *
	 * @param[in] key A constant character pointer representing the key used to search for the network SSID.
	 *
	 * @returns A pointer to a dm_network_ssid_t structure if the key is found, otherwise NULL.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing network SSID.
	 */
	dm_network_ssid_t *get_network_ssid(const char *key);
    
	/**!
	 * @brief Removes a network SSID from the list.
	 *
	 * This function removes the specified network SSID identified by the key.
	 *
	 * @param[in] key A pointer to a character string representing the SSID key to be removed.
	 *
	 * @note Ensure that the key is valid and exists in the list before calling this function.
	 */
	void remove_network_ssid(const char *key);
    
	/**!
	 * @brief Puts the network SSID into the specified key.
	 *
	 * This function associates a given network SSID with a specified key.
	 *
	 * @param[in] key The key to associate with the network SSID.
	 * @param[in] network_ssid Pointer to the network SSID structure to be stored.
	 *
	 * @note Ensure that the key and network_ssid are valid and properly initialized before calling this function.
	 */
	void put_network_ssid(const char *key, const dm_network_ssid_t *network_ssid);

    
	/**!
	 * @brief Retrieves the first operational class.
	 *
	 * This function returns a pointer to the first operational class available.
	 *
	 * @returns A pointer to the first operational class of type `dm_op_class_t`.
	 * @retval NULL if no operational class is available.
	 *
	 * @note Ensure that the returned pointer is not NULL before dereferencing.
	 */
	dm_op_class_t *get_first_op_class();
    
	/**!
	 * @brief Retrieves the next operational class from the given operational class.
	 *
	 * This function takes a pointer to an operational class and returns a pointer to the next operational class in the sequence.
	 *
	 * @param[in] op_class Pointer to the current operational class.
	 *
	 * @returns Pointer to the next operational class.
	 * @retval NULL if there is no next operational class.
	 *
	 * @note Ensure that the provided operational class pointer is valid before calling this function.
	 */
	dm_op_class_t *get_next_op_class(dm_op_class_t *op_class);
    
	/**!
	 * @brief Retrieves the operational class associated with the given key.
	 *
	 * This function searches for the operational class that corresponds to the specified key.
	 *
	 * @param[in] key A constant character pointer representing the key to search for.
	 *
	 * @returns A pointer to the dm_op_class_t structure if the key is found, otherwise NULL.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing operational class.
	 */
	dm_op_class_t *get_op_class(const char *key);
    
	/**!
	 * @brief Removes an operational class based on the provided key.
	 *
	 * This function deletes the operational class associated with the given key from the list.
	 *
	 * @param[in] key A pointer to a character string representing the key of the operational class to be removed.
	 *
	 * @note Ensure that the key is valid and corresponds to an existing operational class.
	 */
	void remove_op_class(const char *key);
    
	/**!
	 * @brief Adds or updates the operational class associated with a given key.
	 *
	 * This function stores the operational class information in a data structure
	 * that can be retrieved later using the provided key.
	 *
	 * @param[in] key A string representing the key associated with the operational class.
	 * @param[in] op_class A pointer to a dm_op_class_t structure containing the operational class data.
	 *
	 * @note Ensure that the key is unique to avoid overwriting existing operational class data.
	 */
	void put_op_class(const char *key, const dm_op_class_t *op_class);
	
	/**!
	* @brief Retrieves the first pre-set operation class of a specified type.
	*
	* This function searches for and returns the first operation class that matches the given type.
	*
	* @param[in] type The type of operation class to search for.
	*
	* @returns A pointer to the first pre-set operation class of the specified type.
	* @retval NULL if no matching operation class is found.
	*
	* @note Ensure that the operation class type is valid before calling this function.
	*/
	dm_op_class_t *get_first_pre_set_op_class_by_type(em_op_class_type_t type);
    
	/**!
	 * @brief Retrieves the next pre-set operation class based on the specified type.
	 *
	 * This function searches for the next operation class that matches the given type
	 * and returns a pointer to it.
	 *
	 * @param[in] type The type of operation class to search for.
	 * @param[out] op_class Pointer to the current operation class. This will be updated
	 *                      to point to the next operation class of the specified type.
	 *
	 * @returns A pointer to the next operation class of the specified type.
	 * @retval NULL if no matching operation class is found.
	 *
	 * @note Ensure that the op_class pointer is valid before calling this function.
	 */
	dm_op_class_t *get_next_pre_set_op_class_by_type(em_op_class_type_t type, dm_op_class_t *op_class);

	
	/**!
	 * @brief Retrieves the first policy from the list.
	 *
	 * This function returns a pointer to the first policy object in the list.
	 *
	 * @returns A pointer to the first `dm_policy_t` object.
	 * @retval NULL if the list is empty or an error occurs.
	 *
	 * @note Ensure that the list is initialized before calling this function.
	 */
	dm_policy_t *get_first_policy();
    
	/**!
	 * @brief Retrieves the next policy in the list.
	 *
	 * This function takes a pointer to a policy and returns a pointer to the next policy in the list.
	 *
	 * @param[in] policy A pointer to the current policy.
	 *
	 * @returns A pointer to the next policy in the list.
	 * @retval NULL if there is no next policy.
	 *
	 * @note Ensure that the policy list is not modified while iterating through it.
	 */
	dm_policy_t *get_next_policy(dm_policy_t *policy);
    
	/**!
	 * @brief Retrieves the policy associated with the given key.
	 *
	 * This function searches for the policy corresponding to the specified key and returns it.
	 *
	 * @param[in] key The key for which the policy is to be retrieved.
	 *
	 * @returns A pointer to the dm_policy_t structure associated with the key.
	 * @retval NULL if no policy is found for the given key.
	 *
	 * @note Ensure the key is valid and properly formatted before calling this function.
	 */
	dm_policy_t *get_policy(const char *key);
    
	/**!
	 * @brief Removes a policy associated with the given key.
	 *
	 * This function deletes the policy identified by the specified key from the list.
	 *
	 * @param[in] key The key associated with the policy to be removed.
	 *
	 * @note Ensure that the key exists before calling this function to avoid undefined behavior.
	 */
	void remove_policy(const char *key);
    
	/**!
	 * @brief Puts a policy into the system with the specified key.
	 *
	 * This function associates a given policy with a key, allowing the system to manage
	 * and apply the policy as needed.
	 *
	 * @param[in] key A constant character pointer representing the key associated with the policy.
	 * @param[in] policy A pointer to a dm_policy_t structure containing the policy details to be stored.
	 *
	 * @note Ensure that the key is unique and the policy is properly initialized before calling this function.
	 */
	void put_policy(const char *key, const dm_policy_t *policy);

    
	/**!
	 * @brief Retrieves the first scan result from the list.
	 *
	 * This function returns a pointer to the first scan result available in the list.
	 *
	 * @returns A pointer to the first `dm_scan_result_t` structure in the list.
	 * @retval NULL if the list is empty or if an error occurs.
	 *
	 * @note Ensure that the list is initialized and populated before calling this function.
	 */
	dm_scan_result_t *get_first_scan_result();
    
	/**!
	 * @brief Retrieves the next scan result from the list.
	 *
	 * This function takes a pointer to a current scan result and returns a pointer to the next scan result in the list.
	 *
	 * @param[in] scan_result Pointer to the current scan result.
	 *
	 * @returns Pointer to the next scan result in the list.
	 * @retval NULL if there are no more scan results.
	 *
	 * @note Ensure that the scan_result is not NULL before calling this function.
	 */
	dm_scan_result_t *get_next_scan_result(dm_scan_result_t *scan_result);
    
	/**!
	 * @brief Retrieves the scan result associated with the specified key.
	 *
	 * This function searches for the scan result that matches the given key and returns a pointer to it.
	 *
	 * @param[in] key A constant character pointer representing the key used to find the scan result.
	 *
	 * @returns A pointer to a dm_scan_result_t structure containing the scan result.
	 * @retval NULL if no scan result is found for the given key.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing scan result.
	 */
	dm_scan_result_t *get_scan_result(const char *key);
    
	/**!
	 * @brief Removes a scan result identified by the given key.
	 *
	 * This function deletes the scan result associated with the specified key from the list.
	 *
	 * @param[in] key A pointer to a character string representing the key of the scan result to be removed.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing scan result.
	 */
	void remove_scan_result(const char *key);
    
	/**!
	 * @brief Puts the scan result into the list using the specified key.
	 *
	 * This function stores the scan result associated with the given key into the mesh list.
	 *
	 * @param[in] key The key associated with the scan result.
	 * @param[in] scan_result Pointer to the scan result structure to be stored.
	 *
	 * @note Ensure that the key and scan_result are valid and properly initialized before calling this function.
	 */
	void put_scan_result(const char *key, const dm_scan_result_t *scan_result);

    
	/**!
	 * @brief Constructor for the dm_easy_mesh_list_t class.
	 *
	 * Initializes a new instance of the dm_easy_mesh_list_t class.
	 *
	 * @note This constructor does not take any parameters and does not return any values.
	 */
	dm_easy_mesh_list_t();
    
	/**!
	 * @brief Destructor for the dm_easy_mesh_list_t class.
	 *
	 * This function is responsible for cleaning up resources used by the dm_easy_mesh_list_t instance.
	 *
	 * @note Ensure that all dynamically allocated memory is properly released.
	 */
	~dm_easy_mesh_list_t();
};

#endif


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

#ifndef DM_NETWORK_H
#define DM_NETWORK_H

#include "em_base.h"

class dm_network_t {
public:
    em_network_info_t   m_net_info;

public:
    
	/**!
	 * @brief Initializes the network module.
	 *
	 * This function sets up the necessary configurations and prepares the network module for operation.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the network module is not already initialized before calling this function.
	 */
	int init();
    
	/**!
	 * @brief Retrieves the network information.
	 *
	 * This function returns a pointer to the network information structure.
	 *
	 * @returns A pointer to the network information structure.
	 *
	 * @note Ensure that the returned pointer is not null before accessing the structure.
	 */
	em_network_info_t *get_network_info() { return &m_net_info; }
    
    
	/**!
	 * @brief Decodes a JSON object and associates it with a parent ID.
	 *
	 * This function takes a JSON object and a parent identifier, performing
	 * necessary operations to decode the JSON data and link it to the specified
	 * parent.
	 *
	 * @param[in] obj The JSON object to be decoded.
	 * @param[out] parent_id The identifier of the parent to associate with the decoded data.
	 *
	 * @returns int Status code indicating success or failure of the decoding operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object and parent ID are valid before calling this function.
	 */
	int decode(const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Encodes a cJSON object.
	 *
	 * This function encodes a given cJSON object, with an option to include a summary.
	 *
	 * @param[in] obj The cJSON object to be encoded.
	 * @param[in] summary A boolean flag indicating whether to include a summary in the encoding.
	 *
	 * @note Ensure that the cJSON object is properly initialized before calling this function.
	 */
	void encode(cJSON *obj, bool summary = false);

    
	/**!
	 * @brief Retrieves the network ID.
	 *
	 * This function returns the network ID associated with the current network information.
	 *
	 * @returns A pointer to a character string representing the network ID.
	 *
	 * @note Ensure that the network information is initialized before calling this function.
	 */
	char *get_network_id() { return m_net_info.id; }

    
	/**!
	 * @brief Retrieves the controller interface.
	 *
	 * This function returns a pointer to the controller interface structure.
	 *
	 * @returns A pointer to the `em_interface_t` structure representing the controller interface.
	 */
	em_interface_t *get_controller_interface() { return &m_net_info.ctrl_id; }
    
	/**!
	 * @brief Retrieves the MAC address of the controller interface.
	 *
	 * @returns A pointer to an unsigned char array containing the MAC address.
	 *
	 * @note The returned MAC address is part of the network information structure.
	 */
	unsigned char *get_controller_interface_mac() { return m_net_info.ctrl_id.mac; }
    
	/**!
	 * @brief Sets the controller ID using the provided MAC address.
	 *
	 * This function copies the MAC address from the input parameter to the
	 * controller ID structure within the network information.
	 *
	 * @param[in] mac Pointer to the MAC address to be set.
	 *
	 * @note Ensure that the MAC address provided is valid and correctly formatted.
	 */
	void set_controller_id(unsigned char *mac) { memcpy(m_net_info.ctrl_id.mac, mac, sizeof(mac_address_t)); }
	
	/**!
	 * @brief Sets the media type for the network interface.
	 *
	 * This function assigns the specified media type to the network interface's media attribute.
	 *
	 * @param[in] media The media type to be set for the network interface.
	 *
	 * @note Ensure that the media type provided is valid and supported by the network interface.
	 */
	void set_controller_intf_media(em_media_type_t media) { m_net_info.media = media; }

    
	/**!
	 * @brief Retrieves the colocated agent interface.
	 *
	 * This function returns a pointer to the colocated agent interface
	 * from the network information structure.
	 *
	 * @returns A pointer to the colocated agent interface.
	 *
	 * @note Ensure that the network information structure is properly
	 * initialized before calling this function.
	 */
	em_interface_t *get_colocated_agent_interface() { return &m_net_info.colocated_agent_id; }
    
	/**!
	 * @brief Retrieves the MAC address of the colocated agent interface.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 *
	 * @note The returned pointer points to the MAC address stored in the network information structure.
	 */
	unsigned char *get_colocated_agent_interface_mac() { return m_net_info.colocated_agent_id.mac; }
    
	/**!
	 * @brief Retrieves the name of the colocated agent interface.
	 *
	 * This function returns the name of the interface associated with the colocated agent.
	 *
	 * @returns A pointer to a character string representing the name of the colocated agent interface.
	 *
	 * @note Ensure that the returned pointer is not null before using it.
	 */
	char *get_colocated_agent_interface_name() { return m_net_info.colocated_agent_id.name; }
    
	/**!
	 * @brief Sets the MAC address for the colocated agent interface.
	 *
	 * This function copies the provided MAC address into the network information structure's colocated agent ID.
	 *
	 * @param[in] mac Pointer to the MAC address to be set.
	 *
	 * @note Ensure that the MAC address provided is valid and the memory is properly allocated.
	 */
	void set_colocated_agent_interface_mac(unsigned char *mac) { memcpy(m_net_info.colocated_agent_id.mac, mac, sizeof(mac_address_t)); }
    
	/**!
	 * @brief Sets the name of the colocated agent interface.
	 *
	 * This function assigns the provided name to the colocated agent interface.
	 *
	 * @param[in] name The name to be set for the colocated agent interface.
	 *
	 * @note Ensure that the name is null-terminated and does not exceed the buffer size.
	 */
	void set_colocated_agent_interface_name(char *name) { snprintf(m_net_info.colocated_agent_id.name, sizeof(m_net_info.colocated_agent_id.name), "%s", name); }

    bool operator == (const dm_network_t& obj);
    //void operator = (const dm_network_t& obj) { memcpy(&m_net_info, &obj.m_net_info, sizeof(em_network_info_t)); }
    void operator = (const dm_network_t& obj);

    
	/**!
	 * @brief Initializes the network with the provided network information.
	 *
	 * This function sets up the network using the details provided in the
	 * em_network_info_t structure. It is essential to ensure that the
	 * network information is correctly populated before calling this function.
	 *
	 * @param[in] net Pointer to an em_network_info_t structure containing
	 * the network information to be used for initialization.
	 *
	 * @returns dm_network_t
	 * @retval A valid dm_network_t object if the initialization is successful.
	 * @retval NULL if the initialization fails due to invalid parameters or
	 * other errors.
	 *
	 * @note Ensure that the network information is valid and complete
	 * before calling this function to avoid unexpected behavior.
	 */
	dm_network_t(em_network_info_t *net);
    
	/**!
	 * @brief Copy constructor for dm_network_t.
	 *
	 * This constructor creates a new instance of dm_network_t by copying an existing one.
	 *
	 * @param[in] net The dm_network_t object to copy from.
	 *
	 * @note This is a deep copy constructor.
	 */
	dm_network_t(const dm_network_t& net);
    
	/**!
	 * @brief Default constructor for the dm_network_t class.
	 *
	 * This constructor initializes a new instance of the dm_network_t class.
	 *
	 * @note This constructor does not take any parameters and does not return any values.
	 */
	dm_network_t();
    
	/**!
	 * @brief Destructor for the dm_network_t class.
	 *
	 * This virtual destructor ensures that derived class destructors are called
	 * when an object is deleted through a pointer to the base class.
	 *
	 * @note This is a virtual destructor.
	 */
	virtual ~dm_network_t();
};

#endif

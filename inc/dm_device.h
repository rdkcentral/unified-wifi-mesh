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

#ifndef DM_DEVICE_H
#define DM_DEVICE_H

#include "em_base.h"
#include <cstring>

class dm_device_t {
public:
    em_device_info_t    m_device_info;

public:
    
	/**!
	 * @brief Initializes the device information structure.
	 *
	 * This function sets the device information structure to zero.
	 *
	 * @returns int
	 * @retval 0 on successful initialization.
	 *
	 * @note This function does not take any parameters and always returns 0.
	 */
	int init() { memset(&m_device_info, 0, sizeof(em_device_info_t)); return 0; }
    
	/**!
	 * @brief Retrieves the device information.
	 *
	 * This function returns a pointer to the device information structure.
	 *
	 * @returns A pointer to the em_device_info_t structure containing the device information.
	 *
	 * @note Ensure that the returned pointer is not null before accessing the structure members.
	 */
	em_device_info_t *get_device_info() { return &m_device_info; }
	
    
	/**!
	 * @brief Decodes a JSON object and associates it with a parent identifier.
	 *
	 * This function takes a JSON object and a parent identifier, performing the necessary
	 * operations to decode the JSON data and link it to the specified parent.
	 *
	 * @param[in] obj The JSON object to be decoded.
	 * @param[out] parent_id The identifier of the parent to which the decoded data will be linked.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note Ensure that the JSON object is valid and the parent identifier is correctly initialized
	 * before calling this function.
	 */
	int decode(const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Encodes a cJSON object.
	 *
	 * This function takes a cJSON object and encodes it, optionally providing a summary.
	 *
	 * @param[in] obj The cJSON object to be encoded.
	 * @param[in] summary A boolean flag indicating whether to provide a summary.
	 *
	 * @note Ensure the cJSON object is properly initialized before calling this function.
	 */
	void encode(cJSON *obj, bool summary = false);

    
	/**!
	 * @brief Retrieves the device interface.
	 *
	 * @returns A pointer to the device interface.
	 */
	em_interface_t *get_dev_interface() { return &m_device_info.intf; }
    
	/**!
	 * @brief Retrieves the MAC address of the device interface.
	 *
	 * This function returns the MAC address associated with the device interface.
	 *
	 * @returns A pointer to an unsigned char array containing the MAC address.
	 *
	 * @note Ensure that the returned MAC address is valid and properly formatted.
	 */
	unsigned char *get_dev_interface_mac() { return m_device_info.intf.mac; }
    
	/**!
	 * @brief Retrieves the device interface name.
	 *
	 * This function returns the name of the device interface from the device information structure.
	 *
	 * @returns A pointer to a character string representing the device interface name.
	 *
	 * @note Ensure that the device information structure is properly initialized before calling this function.
	 */
	char *get_dev_interface_name() { return m_device_info.intf.name; }
    
	/**!
	 * @brief Sets the MAC address for the device interface.
	 *
	 * This function copies the provided MAC address into the device's interface MAC address field.
	 *
	 * @param[in] mac Pointer to the MAC address to be set.
	 *
	 * @note Ensure that the MAC address provided is valid and correctly formatted.
	 */
	void set_dev_interface_mac(unsigned char *mac) { memcpy(m_device_info.intf.mac, mac, sizeof(mac_address_t)); }
    
	/**!
	 * @brief Sets the device interface name.
	 *
	 * This function copies the provided name into the device interface structure.
	 *
	 * @param[in] name The name to set for the device interface.
	 *
	 * @note Ensure that the name is null-terminated and does not exceed the buffer size.
	 */
	void set_dev_interface_name(char *name) { strncpy(m_device_info.intf.name, name, strlen(name) + 1); }
	
    
	/**!
	 * @brief Retrieves the AL interface.
	 *
	 * This function returns a pointer to the AL interface associated with the device.
	 *
	 * @returns A pointer to the `em_interface_t` structure representing the AL interface.
	 *
	 * @note Ensure that the returned pointer is not null before using it.
	 */
	em_interface_t *get_al_interface() { return &m_device_info.backhaul_alid; }
    
	/**!
	 * @brief Retrieves the MAC address of the AL interface.
	 *
	 * @returns A pointer to an unsigned char array containing the MAC address.
	 *
	 * @note The returned pointer points to the internal MAC address storage and should not be freed by the caller.
	 */
	unsigned char *get_al_interface_mac() { return m_device_info.backhaul_alid.mac; }
    
	/**!
	 * @brief Retrieves the AL interface name.
	 *
	 * This function returns the name of the AL interface from the device information.
	 *
	 * @returns A pointer to a character string representing the AL interface name.
	 *
	 * @note Ensure that the returned pointer is not null before using it.
	 */
	char *get_al_interface_name() { return m_device_info.backhaul_alid.name; }

    
	/**!
	 * @brief Retrieves the manufacturer of the device.
	 *
	 * This function returns the manufacturer name of the device as a string.
	 *
	 * @returns A pointer to a character string containing the manufacturer name.
	 *
	 * @note The returned string is managed internally and should not be freed by the caller.
	 */
	char *get_manufacturer() { return m_device_info.manufacturer; }
    
	/**!
	 * @brief Retrieves the manufacturer model of the device.
	 *
	 * This function returns a pointer to a string containing the manufacturer model
	 * of the device. It accesses the `manufacturer_model` field from the `m_device_info`
	 * structure.
	 *
	 * @returns A pointer to a character string representing the manufacturer model.
	 *
	 * @note Ensure that the returned string is not modified or freed by the caller.
	 */
	char *get_manufacturer_model() { return m_device_info.manufacturer_model; }
    
	/**!
	 * @brief Retrieves the software version of the device.
	 *
	 * @returns A pointer to a character string containing the software version.
	 *
	 * @note Ensure the returned pointer is not modified.
	 */
	char *get_software_version() { return m_device_info.software_ver; }
    
	/**!
	 * @brief Retrieves the serial number of the device.
	 *
	 * @returns A pointer to a character array containing the serial number.
	 *
	 * @note The returned serial number is stored in the device information structure.
	 */
	char *get_serial_number() { return m_device_info.serial_number; }
    
	/**!
	 * @brief Retrieves the primary device type.
	 *
	 * This function returns the primary device type as a string.
	 *
	 * @returns A pointer to a character string representing the primary device type.
	 *
	 * @note The returned string is managed internally and should not be freed by the caller.
	 */
	char *get_primary_device_type() { return m_device_info.primary_device_type; }
	
    
	/**!
	 * @brief Sets the manufacturer name for the device.
	 *
	 * This function assigns the provided manufacturer name to the device's manufacturer field.
	 *
	 * @param[in] manufacturer A pointer to a character string representing the manufacturer's name.
	 *
	 * @note The input string should be null-terminated and should not exceed the buffer size of the manufacturer field.
	 */
	void set_manufacturer(char *manufacturer) { snprintf(m_device_info.manufacturer, sizeof(m_device_info.manufacturer), "%s", manufacturer); }
    
	/**!
	 * @brief Sets the manufacturer model for the device.
	 *
	 * This function updates the manufacturer model information in the device info structure.
	 *
	 * @param[in] model A pointer to a character string representing the model name.
	 *
	 * @note Ensure that the model string is null-terminated and does not exceed the buffer size.
	 */
	void set_manufacturer_model(char *model) { snprintf(m_device_info.manufacturer_model, sizeof(m_device_info.manufacturer_model), "%s", model); }
    
	/**!
	 * @brief Sets the software version for the device.
	 *
	 * This function updates the software version information stored in the device info structure.
	 *
	 * @param[in] version A pointer to a character array containing the new software version.
	 *
	 * @note The version string should be null-terminated and should not exceed the buffer size of the software version field.
	 */
	void set_software_version(char *version) { snprintf(m_device_info.software_ver, sizeof(m_device_info.software_ver), "%s", version); }
    
	/**!
	 * @brief Sets the serial number for the device.
	 *
	 * This function assigns a new serial number to the device by copying the provided
	 * serial string into the device's serial number field.
	 *
	 * @param[in] serial A pointer to a character array containing the new serial number.
	 *
	 * @note Ensure that the serial number provided is null-terminated and does not
	 * exceed the maximum size of the device's serial number field.
	 */
	void set_serial_number(char *serial) { snprintf(m_device_info.serial_number, sizeof(m_device_info.serial_number), "%s", serial); }
    
	/**!
	 * @brief Sets the primary device type.
	 *
	 * This function assigns the given device type to the primary device type field
	 * of the device information structure.
	 *
	 * @param[in] type A pointer to a character string representing the device type.
	 *
	 * @note The input string should be null-terminated and should not exceed the
	 *       size of the primary_device_type field.
	 */
	void set_primary_device_type(char *type) { snprintf(m_device_info.primary_device_type, sizeof(m_device_info.primary_device_type), "%s", type); }
    bool operator == (const dm_device_t& obj);
    void operator = (const dm_device_t& obj);
    //void operator = (const dm_device_t& obj) { memcpy(&m_device_info, &obj.m_device_info, sizeof(em_device_info_t)); }
    
	/**!
	 * @brief Retrieves the orchestration type for a given device.
	 *
	 * This function determines the orchestration type associated with the specified device.
	 *
	 * @param[in] device The device for which the orchestration type is to be retrieved.
	 *
	 * @returns The orchestration type of the device.
	 *
	 * @note Ensure the device is properly initialized before calling this function.
	 */
	dm_orch_type_t get_dm_orch_type(const dm_device_t& device);

    
	/**!
	 * @brief Parses the device ID from the given key.
	 *
	 * This function extracts the device ID from a provided key string and stores it in the specified device ID structure.
	 *
	 * @param[in] key The key string from which the device ID is to be parsed.
	 * @param[out] id Pointer to the device ID structure where the parsed ID will be stored.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the key is valid and the id pointer is not null before calling this function.
	 */
	static int parse_device_id_from_key(const char *key, em_device_id_t *id);
    
	/**!
	 * @brief Updates the EasyMesh JSON configuration.
	 *
	 * This function updates the configuration settings for EasyMesh based on the provided mode.
	 *
	 * @param[in] colocated_mode A boolean flag indicating whether the device is in colocated mode.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the configuration file is accessible and writable before calling this function.
	 */
	int update_easymesh_json_cfg(bool colocated_mode);

    
	/**!
	 * @brief Initializes a device with the given device information.
	 *
	 * This function sets up a device using the provided device information structure.
	 *
	 * @param[in] dev Pointer to the device information structure to initialize the device.
	 *
	 * @returns A handle to the initialized device.
	 *
	 * @note Ensure that the device information structure is properly populated before calling this function.
	 */
	dm_device_t(em_device_info_t *dev);
    
	/**!
	 * @brief Copy constructor for dm_device_t.
	 *
	 * This constructor initializes a new instance of dm_device_t by copying
	 * the state from an existing instance.
	 *
	 * @param[in] dev The dm_device_t instance to copy from.
	 *
	 * @note This is a deep copy operation.
	 */
	dm_device_t(const dm_device_t& dev);
    
	/**!
	* @brief Default constructor for the dm_device_t class.
	*
	* This constructor initializes a new instance of the dm_device_t class.
	*
	* @note This constructor does not take any parameters and does not return any values.
	*/
	dm_device_t();
    
	/**!
	 * @brief Destructor for the dm_device_t class.
	 *
	 * This is a virtual destructor to ensure proper cleanup of derived class objects.
	 *
	 * @note This destructor is automatically called when an object of the class goes out of scope or is explicitly deleted.
	 */
	virtual ~dm_device_t();
};

#endif

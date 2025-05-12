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

#ifndef EM_ONEWIFI_H
#define EM_ONEWIFI_H

#include "em_base.h"

class em_onewifi_t {
public:
    webconfig_subdoc_data_t m_wifi_data;

public:

    
	/**!
	 * @brief Constructor for the em_onewifi_t class.
	 *
	 * Initializes a new instance of the em_onewifi_t class.
	 *
	 * @note This constructor does not take any parameters and does not return any values.
	 */
	em_onewifi_t();
    
	/**!
	 * @brief Destructor for the em_onewifi_t class.
	 *
	 * This function cleans up any resources used by the em_onewifi_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	~em_onewifi_t();

    
	/**!
	 * @brief Converts a MAC address to a string representation.
	 *
	 * This function takes a MAC address in the form of a `mac_address_t` and converts it into a human-readable string format.
	 *
	 * @param[in] mac The MAC address to be converted.
	 * @param[out] string The buffer where the resulting string representation of the MAC address will be stored.
	 *
	 * @returns A pointer to the resulting string representation of the MAC address.
	 *
	 * @note Ensure that the `string` buffer is large enough to hold the MAC address string.
	 */
	static char *macbytes_to_string(mac_address_t mac, char* string);
    
	/**!
	 * @brief Converts a string representation of a MAC address to a byte array.
	 *
	 * This function takes a string containing a MAC address and converts it into
	 * a byte array representation.
	 *
	 * @param[in] key The string containing the MAC address.
	 * @param[out] bmac The byte array where the MAC address will be stored.
	 *
	 * @note Ensure that the `key` is a valid MAC address string.
	 */
	static void string_to_macbytes (char *key, mac_address_t bmac);
    
	/**!
	 * @brief Retrieves the MAC address associated with a given network interface name.
	 *
	 * This function attempts to find the MAC address for the specified network interface
	 * name and stores it in the provided mac_address_t structure.
	 *
	 * @param[in] ifname The name of the network interface whose MAC address is to be retrieved.
	 * @param[out] mac A pointer to a mac_address_t structure where the MAC address will be stored.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure, such as if the interface name is not found.
	 *
	 * @note Ensure that the mac_address_t structure is properly initialized before calling this function.
	 */
	static int mac_address_from_name(const char *ifname, mac_address_t mac);
};

#endif

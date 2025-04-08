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

#ifndef DM_IEEE_1905_SECURITY_H
#define DM_IEEE_1905_SECURITY_H

#include "em_base.h"
#include "db_easy_mesh.h"

class dm_ieee_1905_security_t {
public:
    em_ieee_1905_security_info_t    m_ieee_1905_security_info;

public:
    
	/**!
	 * @brief Initializes the IEEE 1905 security information structure.
	 *
	 * This function sets the IEEE 1905 security information structure to zero.
	 *
	 * @returns int
	 * @retval 0 on successful initialization.
	 *
	 * @note This function does not take any parameters and always returns 0.
	 */
	int init() { memset(&m_ieee_1905_security_info, 0, sizeof(em_ieee_1905_security_info_t)); return 0; }

    
	/**!
	 * @brief Retrieves the IEEE 1905 security information.
	 *
	 * This function returns a pointer to the structure containing the IEEE 1905 security information.
	 *
	 * @returns A pointer to the `em_ieee_1905_security_info_t` structure.
	 */
	em_ieee_1905_security_info_t *get_ieee_1905_security_info() { return &m_ieee_1905_security_info; }
    
	/**!
	 * @brief Retrieves the IEEE 1905 security capabilities.
	 *
	 * @returns A pointer to the IEEE 1905 security capabilities structure.
	 */
	em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() { return &m_ieee_1905_security_info.sec_cap; }

    bool operator == (const dm_ieee_1905_security_t& obj);
    void operator = (const dm_ieee_1905_security_t& obj);
    
	/**!
	 * @brief Decodes a cJSON object.
	 *
	 * This function takes a cJSON object and performs decoding operations.
	 *
	 * @param[in] obj The cJSON object to be decoded.
	 *
	 * @returns int The result of the decoding operation.
	 *
	 * @note Ensure the cJSON object is properly initialized before calling this function.
	 */
	int decode(const cJSON *obj);
    
	/**!
	 * @brief Encodes the given JSON object.
	 *
	 * This function takes a cJSON object and encodes it according to the
	 * IEEE 1905 security specifications.
	 *
	 * @param[in] obj The cJSON object to be encoded.
	 *
	 * @note Ensure that the cJSON object is properly initialized before
	 * calling this function.
	 */
	void encode(cJSON *obj);

    
	/**!
	 * @brief Initializes the IEEE 1905 security context.
	 *
	 * This function sets up the security parameters for the given network SSID.
	 *
	 * @param[in] net_ssid Pointer to the network SSID information structure.
	 *
	 * @returns dm_ieee_1905_security_t
	 *
	 * @note Ensure that the net_ssid is properly initialized before calling this function.
	 */
	dm_ieee_1905_security_t(em_ieee_1905_security_info_t *net_ssid);
    
	/**!
	 * @brief Copy constructor for dm_ieee_1905_security_t.
	 *
	 * This constructor creates a new instance of dm_ieee_1905_security_t by copying
	 * the data from an existing instance.
	 *
	 * @param[in] net_ssid The instance of dm_ieee_1905_security_t to copy from.
	 *
	 * @note This is a deep copy constructor.
	 */
	dm_ieee_1905_security_t(const dm_ieee_1905_security_t& net_ssid);
    
	/**!
	 * @brief Constructor for the dm_ieee_1905_security_t class.
	 *
	 * This constructor initializes the dm_ieee_1905_security_t object.
	 *
	 * @note Ensure that the object is properly initialized before use.
	 */
	dm_ieee_1905_security_t();
    
	/**!
	 * @brief Destructor for the dm_ieee_1905_security_t class.
	 *
	 * This virtual destructor ensures that the derived class destructors are called properly.
	 *
	 * @note This is a virtual destructor and does not take any parameters or return any values.
	 */
	virtual ~dm_ieee_1905_security_t();
};

#endif

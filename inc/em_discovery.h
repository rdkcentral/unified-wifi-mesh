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

#ifndef EM_DISCOVERY_H
#define EM_DISCOVERY_H

#include "em_base.h"

class em_cmd_t;
class em_discovery_t {

    
	/**!
	 * @brief Creates a topology discovery message.
	 *
	 * This function generates a topology discovery message and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the discovery message will be stored.
	 *
	 * @returns The size of the discovery message in bytes.
	 *
	 * @note Ensure that the buffer is large enough to hold the discovery message.
	 */
	unsigned int create_topo_discovery_msg(unsigned char *buff);
    
	/**!
	 * @brief Creates a topology query message.
	 *
	 * This function generates a topology query message and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the message will be stored.
	 *
	 * @returns The size of the message stored in the buffer.
	 */
	unsigned int create_topo_query_msg(unsigned char *buff);
    
	/**!
	 * @brief Creates a topology response message.
	 *
	 * This function generates a topology response message and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the response message will be stored.
	 *
	 * @returns unsigned int The size of the message stored in the buffer.
	 *
	 * @note Ensure the buffer is allocated with sufficient size to hold the message.
	 */
	unsigned int create_topo_rsp_msg(unsigned char *buff);

    
	/**!
	 * @brief Analyzes the topology discovery message.
	 *
	 * This function processes the given buffer containing a topology discovery message
	 * and performs necessary analysis based on the message content.
	 *
	 * @param[in] buff Pointer to the buffer containing the message to be analyzed.
	 * @param[in] len Length of the buffer in bytes.
	 *
	 * @returns int Status code indicating the result of the analysis.
	 * @retval 0 Success.
	 * @retval -1 Failure due to invalid input.
	 *
	 * @note Ensure that the buffer is properly initialized and contains valid data
	 * before calling this function.
	 */
	int analyze_topo_disc_msg(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Analyzes the topology query message.
	 *
	 * This function processes the given buffer containing a topology query message
	 * and performs necessary analysis based on its content.
	 *
	 * @param[in] buff Pointer to the buffer containing the message data.
	 * @param[in] len Length of the buffer in bytes.
	 *
	 * @returns int Status code indicating the result of the analysis.
	 * @retval 0 Success.
	 * @retval -1 Failure due to invalid input.
	 *
	 * @note Ensure that the buffer is properly initialized and the length is accurate
	 * before calling this function.
	 */
	int analyze_topo_query_msg(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Analyzes the topology response message.
	 *
	 * This function processes the buffer containing the topology response message
	 * and performs necessary analysis based on the provided length.
	 *
	 * @param[in] buff Pointer to the buffer containing the message.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int Status code indicating the result of the analysis.
	 * @retval 0 Success.
	 * @retval -1 Failure due to invalid input.
	 *
	 * @note Ensure the buffer is properly initialized before calling this function.
	 */
	int analyze_topo_resp_msg(unsigned char *buff, unsigned int len);
    
    
	/**!
	 * @brief Retrieves the current state of the entity.
	 *
	 * @returns The current state as an em_state_t value.
	 */
	virtual em_state_t get_state() = 0;
    
	/**!
	 * @brief Retrieves the MAC address of the radio interface.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual unsigned char   *get_radio_interface_mac() = 0;
    
	/**!
	 * @brief Retrieves the MAC address of the AL interface.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual unsigned char *get_al_interface_mac() = 0;

    
	/**!
	 * @brief Sends a frame of data.
	 *
	 * This function is responsible for sending a frame of data over the network.
	 *
	 * @param[in] buff Pointer to the buffer containing the data to be sent.
	 * @param[in] len Length of the data in the buffer.
	 * @param[in] multicast Flag indicating whether the data should be sent as multicast.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
    
	/**!
	 * @brief Retrieves the current command.
	 *
	 * This function returns a pointer to the current command being processed.
	 *
	 * @returns A pointer to the current em_cmd_t object.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual em_cmd_t *get_current_cmd() = 0;
    
public:

	/**!
	 * @brief Retrieves the manager instance.
	 *
	 * This function returns a pointer to the manager instance associated with the steering module.
	 *
	 * @returns A pointer to the manager instance of type `em_mgr_t`.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual em_mgr_t *get_mgr() = 0;

	/**!
	 * @brief Processes a message with the given data and length.
	 *
	 * This function takes a pointer to data and its length, and performs
	 * necessary operations to process the message.
	 *
	 * @param[in] data Pointer to the message data to be processed.
	 * @param[in] len Length of the message data.
	 *
	 * @note Ensure that the data pointer is valid and the length is correct
	 * before calling this function.
	 */
	void    process_msg(unsigned char *data, unsigned int len);
    
	/**!
	* @brief Processes the current state.
	*
	* This function is responsible for handling the current state of the system.
	* It performs necessary operations based on the state.
	*
	* @note Ensure that the system is initialized before calling this function.
	*/
	void    process_state();

    
	/**!
	 * @brief Constructor for em_discovery_t class.
	 *
	 * Initializes a new instance of the em_discovery_t class.
	 *
	 * @note This constructor does not take any parameters.
	 */
	em_discovery_t();
    
	/**!
	 * @brief Destructor for the em_discovery_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the em_discovery_t instance.
	 *
	 * @note Ensure that all dynamically allocated resources are properly released.
	 */
	virtual ~em_discovery_t();

};

#endif

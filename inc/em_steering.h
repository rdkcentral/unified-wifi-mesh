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

#ifndef EM_STEERING_H
#define EM_STEERING_H

#include "em_base.h"

class em_steering_t {

    unsigned int m_client_steering_req_tx_cnt;
    unsigned int m_client_assoc_ctrl_req_tx_cnt;

    
	/**!
	 * @brief Sends a client steering request message.
	 *
	 * This function is responsible for initiating a steering request to the client.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the client is ready to receive the steering request before calling this function.
	 */
	int send_client_steering_req_msg();
    
	/**!
	 * @brief Sends a client association control request message.
	 *
	 * This function is responsible for initiating a control request to associate a client.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the client is ready to receive the association request before calling this function.
	 */
	int send_client_assoc_ctrl_req_msg();
    
	/**!
	 * @brief Sends a client association control request message.
	 *
	 * This function is responsible for sending a control request message to the client
	 * to manage association parameters.
	 *
	 * @param[in] assoc_ctrl Pointer to the association control request structure.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Success
	 * @retval -1 Failure
	 *
	 * @note Ensure that the assoc_ctrl structure is properly initialized before calling this function.
	 */
	int send_client_assoc_ctrl_req_msg(em_client_assoc_ctrl_req_t *assoc_ctrl);
    
	/**!
	 * @brief Sends a BTM report message.
	 *
	 * This function is responsible for sending a BTM (BSS Transition Management) report message to a specified station.
	 *
	 * @param[in] sta The MAC address of the station to which the report is sent.
	 * @param[in] bss The BSSID of the BSS involved in the report.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the station and BSS are valid and reachable before calling this function.
	 */
	int send_btm_report_msg(mac_address_t sta, bssid_t bss);
    
	/**!
	 * @brief Sends a 1905 acknowledgment message to a specified station.
	 *
	 * This function is responsible for sending an acknowledgment message
	 * to the station identified by the provided MAC address.
	 *
	 * @param[in] sta_mac The MAC address of the station to which the acknowledgment
	 * message will be sent.
	 * @param[in] msg_id The message ID of the original message being acknowledged.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the MAC address is valid and the station is reachable
	 * before calling this function.
	 */
	int send_1905_ack_message(mac_addr_t sta_mac, unsigned short msg_id);
    
	/**!
	 * @brief Handles the client steering request.
	 *
	 * This function processes the steering request received from a client.
	 *
	 * @param[in] buff Pointer to the buffer containing the request data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Success.
	 * @retval -1 Failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_client_steering_req(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the client steering report.
	 *
	 * This function processes the client steering report received in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the client steering report data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_client_steering_report(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the acknowledgment message.
	 *
	 * This function processes the acknowledgment message contained in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the message.
	 * @param[in] len Length of the message in the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 Success.
	 * @retval -1 Failure.
	 *
	 * @note Ensure the buffer is properly allocated and the length is correct before calling this function.
	 */
	int handle_ack_msg(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Creates an error code TLV (Type-Length-Value) structure.
	 *
	 * This function populates the provided buffer with a TLV structure
	 * representing an error code, using the given value and station MAC address.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 * @param[in] val Integer value representing the error code to be included in the TLV.
	 * @param[in] sta_mac MAC address of the station, used in the TLV.
	 *
	 * @returns short The length of the TLV written to the buffer.
	 *
	 * @note Ensure the buffer is large enough to hold the TLV structure.
	 */
	short create_error_code_tlv(unsigned char *buff, int val, mac_addr_t sta_mac);
    
	/**!
	 * @brief Creates a BTM report TLV.
	 *
	 * This function generates a BTM (Backhaul Traffic Management) report TLV (Type-Length-Value) and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the BTM report TLV will be stored.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is adequately sized to hold the TLV data.
	 */
	short create_btm_report_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a BTM (Backhaul Traffic Management) request TLV (Type-Length-Value).
	 *
	 * This function constructs a BTM request TLV and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns The size of the TLV created.
	 * @retval -1 if the buffer is null or if an error occurs during creation.
	 *
	 * @note Ensure the buffer is sufficiently large to hold the TLV.
	 */
	short create_btm_request_tlv(unsigned char *buff);

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
	 * @brief Sends a frame of data.
	 *
	 * This function is responsible for sending a frame of data through the network.
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
	 * @brief Retrieves the data model.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns A pointer to the data model of type dm_easy_mesh_t.
	 *
	 * @note This function does not take any parameters and returns a pointer to the data model.
	 */
	virtual dm_easy_mesh_t *get_data_model() = 0;
    
	/**!
	 * @brief Retrieves the MAC address of the radio interface.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual unsigned char *get_radio_interface_mac() = 0;
    
	/**!
	 * @brief Retrieves the current state of the steering mechanism.
	 *
	 * @returns The current state as an em_state_t enumeration.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual em_state_t get_state() = 0;
    
	/**!
	 * @brief Sets the state of the steering mechanism.
	 *
	 * This function is responsible for updating the current state of the steering
	 * mechanism to the specified state.
	 *
	 * @param[in] state The new state to set for the steering mechanism.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void set_state(em_state_t state) = 0;
    
	/**!
	 * @brief Retrieves the current command.
	 *
	 * This function returns a pointer to the current command being processed.
	 *
	 * @returns A pointer to the current command of type em_cmd_t.
	 */
	virtual em_cmd_t *get_current_cmd() = 0;

public:

    
	/**!
	 * @brief Retrieves the client steering request transmission count.
	 *
	 * This function returns the number of client steering requests that have been transmitted.
	 *
	 * @returns The number of client steering request transmissions as an integer.
	 */
	int get_client_steering_req_tx_count() { return static_cast<int>(m_client_steering_req_tx_cnt); }
    
	/**!
	 * @brief Sets the client steering request transmission count.
	 *
	 * This function assigns the provided count to the member variable
	 * responsible for tracking the number of client steering requests
	 * transmitted.
	 *
	 * @param[in] cnt The count of client steering requests to be set.
	 *
	 * @note Ensure that the count is a valid unsigned integer.
	 */
	void set_client_steering_req_tx_count(unsigned int cnt) { m_client_steering_req_tx_cnt = cnt; }
    
	/**!
	 * @brief Retrieves the count of client association control request transmissions.
	 *
	 * This function returns the number of times a client association control request
	 * has been transmitted.
	 *
	 * @returns int The count of client association control request transmissions.
	 */
	int get_client_assoc_ctrl_req_tx_count() { return static_cast<int>(m_client_assoc_ctrl_req_tx_cnt); }
    
	/**!
	 * @brief Sets the client association control request transmission count.
	 *
	 * This function assigns the provided count to the member variable
	 * responsible for tracking the number of client association control
	 * request transmissions.
	 *
	 * @param[in] cnt The count to set for client association control request
	 * transmission.
	 */
	void set_client_assoc_ctrl_req_tx_count(unsigned int cnt) { m_client_assoc_ctrl_req_tx_cnt = cnt; }

    
	/**!
	 * @brief Processes a message with the given data and length.
	 *
	 * This function takes a pointer to a data buffer and its length, then processes the message accordingly.
	 *
	 * @param[in] data Pointer to the data buffer containing the message to be processed.
	 * @param[in] len The length of the data buffer.
	 *
	 * @note Ensure that the data buffer is valid and the length is correctly specified to avoid undefined behavior.
	 */
	void    process_msg(unsigned char *data, unsigned int len);
    
	/**!
	* @brief Processes the state of the agent.
	*
	* This function is responsible for handling the current state of the agent and performing necessary actions based on that state.
	*
	* @note Ensure that the agent's state is properly initialized before calling this function.
	*/
	void    process_agent_state();
    
	/**!
	* @brief Processes the control state.
	*
	* This function is responsible for handling the control state of the system.
	*
	* @note Ensure that the system is initialized before calling this function.
	*/
	void    process_ctrl_state();

    
	/**!
	 * @brief Constructor for the em_steering_t class.
	 *
	 * Initializes the steering module.
	 *
	 * @note This constructor does not take any parameters.
	 */
	em_steering_t();
    
	/**!
	 * @brief Destructor for the em_steering_t class.
	 *
	 * This function cleans up any resources used by the em_steering_t instance.
	 *
	 * @note This is a virtual destructor, allowing for proper cleanup of derived classes.
	 */
	virtual ~em_steering_t();

};

#endif

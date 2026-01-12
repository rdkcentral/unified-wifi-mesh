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

#ifndef EM_CHANNEL_H
#define EM_CHANNEL_H

#include "em_base.h"

class em_cmd_t;
class em_channel_t {

    
	/**!
	 * @brief Sends a frame of data.
	 *
	 * This function is responsible for sending a frame of data through the channel.
	 *
	 * @param[in] buff Pointer to the buffer containing the data to be sent.
	 * @param[in] len The length of the data in the buffer.
	 * @param[in] multicast Indicates whether the frame should be sent as multicast.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
	
	/**!
	 * @brief Pushes an event to the event manager.
	 *
	 * This function is responsible for adding an event to the event manager's queue.
	 *
	 * @param[in] evt Pointer to the event to be pushed.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual int push_event(em_event_t *evt) = 0;

public:
	
	/**!
	 * @brief Retrieves the manager instance.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns A pointer to the em_mgr_t instance.
	 *
	 * @note This function does not take any parameters and returns a non-null pointer to the manager instance.
	 */
	virtual em_mgr_t *get_mgr() = 0;
    
	/**!
	 * @brief Retrieves the data model.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns A pointer to a dm_easy_mesh_t object representing the data model.
	 *
	 * @note This function does not take any parameters and must be overridden in derived classes.
	 */
	virtual dm_easy_mesh_t *get_data_model() = 0;
    
	/**!
	 * @brief Retrieves the MAC address of the radio interface.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 *
	 * @note This function is pure virtual and must be implemented by derived classes.
	 */
	virtual unsigned char *get_radio_interface_mac() = 0;
    
	/**!
	 * @brief Retrieves the current state.
	 *
	 * @returns The current state as an em_state_t.
	 */
	virtual em_state_t get_state() = 0;
    
	/**!
	 * @brief Sets the state of the channel.
	 *
	 * This function sets the state of the channel to the specified state.
	 *
	 * @param[in] state The state to set for the channel.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void set_state(em_state_t state) = 0;
    
	/**!
	 * @brief Retrieves the service type.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns The service type as an em_service_type_t.
	 */
	virtual em_service_type_t get_service_type() = 0;
    
	/**!
	 * @brief Retrieves the device information.
	 *
	 * This function is a pure virtual function that must be implemented by the derived class.
	 *
	 * @returns A pointer to an em_device_info_t structure containing the device information.
	 *
	 * @note The caller is responsible for managing the memory of the returned structure.
	 */
	virtual em_device_info_t *get_device_info() = 0;
    
	/**!
	 * @brief Retrieves the current command.
	 *
	 * This function returns a pointer to the current command being processed.
	 *
	 * @returns A pointer to the current command of type em_cmd_t.
	 * @retval nullptr if no command is currently being processed.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual em_cmd_t *get_current_cmd() = 0;

    
	/**!
	* @brief Creates a channel scan request TLV.
	*
	* This function initializes a channel scan request TLV and stores it in the provided buffer.
	*
	* @param[out] buff Pointer to the buffer where the TLV will be stored.
	*
	* @returns short
	* @retval 0 on success
	* @retval -1 on failure
	*
	* @note Ensure the buffer is allocated with sufficient size before calling this function.
	*/
	short create_channel_scan_req_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a channel scan result TLV.
	 *
	 * This function is responsible for creating a channel scan result TLV (Type-Length-Value) structure
	 * and storing it in the provided buffer at the specified index.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 * @param[in] index The index in the buffer where the TLV should be placed.
	 *
	 * @returns short
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer has sufficient space to store the TLV.
	 */
	short create_channel_scan_res_tlv(unsigned char *buff, unsigned int index);
    
	/**!
	 * @brief Creates a channel preference TLV.
	 *
	 * This function is responsible for creating a channel preference TLV (Type-Length-Value) structure and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before calling this function.
	 */
	short create_channel_pref_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates an operating channel report TLV.
	 *
	 * This function generates a TLV (Type-Length-Value) report for the operating channel
	 * and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV report will be stored.
	 *
	 * @returns short The size of the TLV report generated.
	 *
	 * @note Ensure the buffer is allocated with sufficient space to store the TLV report.
	 */
	short create_operating_channel_report_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a spatial reuse report TLV.
	 *
	 * This function generates a spatial reuse report TLV and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns The size of the TLV in bytes.
	 *
	 * @note Ensure that the buffer is large enough to hold the TLV.
	 */
	short create_spatial_reuse_report_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a complete CAC report TLV.
	 *
	 * This function generates a complete CAC (Channel Access Control) report TLV (Type-Length-Value) and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is adequately sized to hold the TLV data.
	 */
	short create_cac_complete_report_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a CAC status report TLV.
	 *
	 * This function generates a CAC (Channel Access Control) status report TLV (Type-Length-Value) and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns short The length of the TLV created.
	 *
	 * @note Ensure that the buffer is large enough to hold the TLV.
	 */
	short create_cac_status_report_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a channel preference TLV agent.
	 *
	 * This function is responsible for creating a channel preference TLV agent using the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the channel preference TLV agent will be created.
	 * @param[in] index The index of the channel preference TLV agent to be created.
	 *
	 * @returns short
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	short create_channel_pref_tlv_agent(unsigned char *buff, unsigned int index);
    
	/**!
	 * @brief Creates a TLV for transmit power limit.
	 *
	 * This function generates a TLV (Type-Length-Value) structure for setting the transmit power limit.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns The size of the TLV in bytes.
	 * @retval -1 if an error occurs during TLV creation.
	 *
	 * @note Ensure the buffer is large enough to hold the TLV.
	 */
	short create_transmit_power_limit_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a spatial reuse request TLV.
	 *
	 * This function initializes a spatial reuse request TLV and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns The size of the TLV created.
	 */
	short create_spatial_reuse_req_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates an EHT operations TLV.
	 *
	 * This function is responsible for creating an EHT (Extremely High Throughput) operations TLV (Type-Length-Value) structure and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before calling this function.
	 */
	virtual unsigned short create_eht_operations_tlv(unsigned char *buff) = 0;
    
	/**!
	 * @brief Sends a channel scan request message.
	 *
	 * This function initiates a scan request on the channel to gather available network information.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the channel is initialized before calling this function.
	 */
	int send_channel_scan_request_msg();
    
	/**!
	 * @brief Sends a channel scan report message.
	 *
	 * This function is responsible for sending a report message after scanning channels.
	 *
	 * @param[in] last_inex Pointer to the last index scanned.
	 *
	 * @returns int Status code of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the pointer is valid before calling this function.
	 */
	int send_channel_scan_report_msg(unsigned int *last_inex);
    
	/**!
	 * @brief Sends a channel selection request message.
	 *
	 * This function is responsible for initiating a request to select a specific channel.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the channel is available before sending the request.
	 */
	int send_channel_sel_request_msg();
    
	/**!
	 * @brief Sends a channel selection response message.
	 *
	 * This function is responsible for sending a response message based on the channel selection response code provided.
	 *
	 * @param[in] code The response code indicating the result of the channel selection process.
	 * @param[in] msg_id The message identifier for the response message.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the response code and message ID are valid before calling this function.
	 */
	int send_channel_sel_response_msg(em_chan_sel_resp_code_type_t code, unsigned short msg_id);
	
	/**!
	 * @brief Sends an operating channel report message.
	 *
	 * This function is responsible for sending a report message regarding the operating channel.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the channel is properly configured before calling this function.
	 */
	int send_operating_channel_report_msg();
	
	/**!
	 * @brief Sends a channel preference query message.
	 *
	 * This function is responsible for sending a query message to determine
	 * the preferred channel for communication.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the communication channel is initialized before calling this function.
	 */
	int send_channel_pref_query_msg();
	
	/**!
	 * @brief Sends a channel preference report message.
	 *
	 * This function is responsible for sending a message that contains
	 * the channel preference report. It is typically used in scenarios
	 * where channel selection or preference needs to be communicated.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the channel configuration is set before calling
	 * this function.
	 */
	int send_channel_pref_report_msg();
    
	/**!
	 * @brief Sends an inquiry message to check available spectrum.
	 *
	 * This function is responsible for sending a message to inquire about the available spectrum.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the communication channel is properly initialized before calling this function.
	 */
	int send_available_spectrum_inquiry_msg();

    
	/**!
	 * @brief Handles the channel scan request.
	 *
	 * This function processes the channel scan request using the provided buffer and length.
	 *
	 * @param[in] buff Pointer to the buffer containing the scan request data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure the buffer is properly initialized before calling this function.
	 */
	int handle_channel_scan_req(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the channel scan report.
	 *
	 * This function processes the channel scan report contained in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the scan report data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is properly allocated and the length is correct.
	 */
	int handle_channel_scan_rprt(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the result of a channel scan.
	 *
	 * This function processes the data obtained from a channel scan and performs necessary actions based on the scan results.
	 *
	 * @param[in] buff Pointer to the buffer containing the scan result data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified to avoid buffer overflow issues.
	 */
	int handle_channel_scan_result(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the channel preference report.
	 *
	 * This function processes the channel preference report contained in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the channel preference report.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is properly allocated and the length is correct before calling this function.
	 */
	int handle_channel_pref_rprt(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the channel preference query.
	 *
	 * This function processes the channel preference query and populates the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the query result will be stored.
	 * @param[in] len The length of the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is allocated with sufficient size to store the query result.
	 */
	int handle_channel_pref_query(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the channel selection response.
	 *
	 * This function processes the response received for channel selection.
	 *
	 * @param[in] buff Pointer to the buffer containing the response data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_channel_sel_rsp(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the operating channel report.
	 *
	 * This function processes the operating channel report from the given buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the channel report data.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_operating_channel_rprt(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the channel selection request.
	 *
	 * This function processes the channel selection request contained in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the channel selection request data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Success.
	 * @retval -1 Failure due to invalid parameters.
	 *
	 * @note Ensure that the buffer is properly initialized and contains valid data before calling this function.
	 */
	int handle_channel_sel_req(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the channel preference TLV.
	 *
	 * This function processes the channel preference TLV from the given buffer
	 * and updates the operation class channel selection structure.
	 *
	 * @param[in] buff Pointer to the buffer containing the TLV data.
	 * @param[out] op_class Pointer to the operation class channel selection structure.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is properly initialized before calling this function.
	 */
	int handle_channel_pref_tlv(unsigned char *buff, op_class_channel_sel *op_class);
    
	/**!
	 * @brief Handles the channel preference TLV control.
	 *
	 * This function processes the channel preference TLV (Type-Length-Value) control message.
	 *
	 * @param[in] buff Pointer to the buffer containing the TLV data.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_channel_pref_tlv_ctrl(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the operation channel report.
	 *
	 * This function processes the channel report data provided in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the channel report data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Success.
	 * @retval -1 Failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_op_channel_report(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the spatial reuse report.
	 *
	 * This function processes the spatial reuse report contained in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the spatial reuse report data.
	 * @param[in] len Length of the buffer in bytes.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_spatial_reuse_report(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles EHT operations TLV.
	 *
	 * This function processes the EHT operations TLV from the provided buffer and populates the
	 * eht_ops structure with the relevant data.
	 *
	 * @param[in] buff Pointer to the buffer containing the EHT operations TLV data.
	 * @param[out] eht_ops Pointer to the em_eht_operations_t structure to be populated.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly initialized and contains valid TLV data before calling this function.
	 */
	int handle_eht_operations_tlv(unsigned char *buff, em_eht_operations_t *eht_ops);
    
	/**!
	 * @brief Handles EHT operations for TLV control.
	 *
	 * This function processes the EHT operations based on the provided TLV control buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing TLV data.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly initialized before calling this function.
	 */
	int handle_eht_operations_tlv_ctrl(unsigned char *buff, unsigned int len);

    
	/**!
	 * @brief Retrieves the channel preference query transmission count.
	 *
	 * This function returns the number of times the channel preference query
	 * has been transmitted.
	 *
	 * @returns The channel preference query transmission count as an integer.
	 */
	int get_channel_pref_query_tx_count() { return static_cast<int>(m_channel_pref_query_tx_cnt); }
    
	/**!
	* @brief Sets the channel preference query transmission count.
	*
	* This function assigns the provided count to the member variable
	* responsible for tracking the number of channel preference query
	* transmissions.
	*
	* @param[in] cnt The count to set for channel preference query transmissions.
	*/
	void set_channel_pref_query_tx_count(unsigned int cnt) { m_channel_pref_query_tx_cnt = cnt; }
    
	/**!
	 * @brief Retrieves the transmission count for channel selection requests.
	 *
	 * This function returns the number of times a channel selection request has been transmitted.
	 *
	 * @returns The transmission count for channel selection requests as an integer.
	 */
	int get_channel_sel_req_tx_count() { return static_cast<int>(m_channel_sel_req_tx_cnt); }
    
	/**!
	* @brief Sets the channel selection request transmission count.
	*
	* This function assigns the provided count to the member variable
	* responsible for tracking the number of channel selection request
	* transmissions.
	*
	* @param[in] cnt The count to set for channel selection request transmissions.
	*/
	void set_channel_sel_req_tx_count(unsigned int cnt) { m_channel_sel_req_tx_cnt = cnt; }

	
	/**!
	 * @brief Fills the scan result structure with data from the channel scan result.
	 *
	 * This function takes the scan result from the channel scan and populates the
	 * provided scan result structure with the relevant data.
	 *
	 * @param[out] scan_res Pointer to the destination scan result structure to be filled.
	 * @param[in] res Pointer to the source channel scan result structure.
	 *
	 * @note Ensure that both structures are properly initialized before calling this function.
	 */
	void fill_scan_result(dm_scan_result_t *scan_res, em_channel_scan_result_t *res);

    
	/**!
	 * @brief Processes a message with the given data and length.
	 *
	 * This function takes a pointer to a data buffer and its length, then processes the message contained within.
	 *
	 * @param[in] data Pointer to the data buffer containing the message.
	 * @param[in] len Length of the data buffer.
	 *
	 * @note Ensure that the data buffer is valid and the length is correct to avoid undefined behavior.
	 */
	void process_msg(unsigned char *data, unsigned int len);
    
	/**!
	* @brief Processes the control state.
	*
	* This function is responsible for handling the current state of the control mechanism.
	*
	* @note Ensure that the control state is initialized before calling this function.
	*/
	void process_ctrl_state();
    
	/**!
	 * @brief Processes the current state.
	 *
	 * This function is responsible for handling the current state of the system.
	 *
	 * @note Ensure the system is initialized before calling this function.
	 */
	void process_state();

    unsigned int m_channel_pref_query_tx_cnt;
    unsigned int m_channel_sel_req_tx_cnt;
	
	/**!
	 * @brief Retrieves the frequency band.
	 *
	 * @returns The frequency band as an em_freq_band_t.
	 */
	virtual em_freq_band_t get_band() = 0;

    
	/**!
	 * @brief Constructor for em_channel_t.
	 *
	 * Initializes a new instance of the em_channel_t class.
	 *
	 * @note This constructor does not take any parameters.
	 */
	em_channel_t();
    
	/**!
	 * @brief Destructor for the em_channel_t class.
	 *
	 * This function cleans up any resources used by the em_channel_t instance.
	 *
	 * @note This is a virtual destructor, allowing for proper cleanup of derived classes.
	 */
	virtual ~em_channel_t();

};

#endif

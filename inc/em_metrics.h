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

#ifndef EM_METRICS_H
#define EM_METRICS_H

#include "em_base.h"
#include "dm_easy_mesh.h"

class em_metrics_t {

    
	/**!
	 * @brief Retrieves the data model instance.
	 *
	 * This function provides access to the data model used within the system.
	 *
	 * @returns A pointer to the data model instance of type `dm_easy_mesh_t`.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_easy_mesh_t *get_data_model() = 0;
    
	/**!
	 * @brief Retrieves the current state.
	 *
	 * @returns The current state as an em_state_t.
	 *
	 * @note This is a pure virtual function that must be implemented by derived classes.
	 */
	virtual em_state_t get_state() = 0;
    
	/**!
	 * @brief Sets the state of the EM.
	 *
	 * This function sets the current state of the EM to the specified state.
	 *
	 * @param[in] state The state to set, represented by em_state_t.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void set_state(em_state_t state) = 0;
    
	/**!
	 * @brief Sends a frame of data.
	 *
	 * This function is responsible for sending a frame of data, which can be multicast or unicast.
	 *
	 * @param[in] buff Pointer to the buffer containing the data to be sent.
	 * @param[in] len Length of the data in the buffer.
	 * @param[in] multicast Flag indicating whether the data should be sent as multicast.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure the buffer is properly allocated and the length is correctly specified.
	 */
	virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
    
	/**!
	 * @brief Retrieves the profile type.
	 *
	 * This function returns the current profile type of the entity.
	 *
	 * @returns The profile type as an em_profile_type_t.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual em_profile_type_t get_profile_type() = 0;
    
	/**!
	 * @brief Retrieves the current command.
	 *
	 * This function returns a pointer to the current command being processed.
	 *
	 * @returns A pointer to the current command of type em_cmd_t.
	 * @retval nullptr If there is no current command.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual em_cmd_t *get_current_cmd() = 0;
    
	/**!
	 * @brief Sends link metrics message to all associated stations.
	 *
	 * This function is responsible for sending link metrics messages to all stations that are currently associated.
	 *
	 * @note Ensure that the station list is up-to-date before calling this function.
	 */
	void send_all_associated_sta_link_metrics_msg();
    
	/**!
	 * @brief Sends a link metrics message to the associated station.
	 *
	 * This function is responsible for sending a link metrics message to a station
	 * identified by its MAC address. The metrics message contains information
	 * about the link quality and other relevant metrics.
	 *
	 * @param[in] sta_mac The MAC address of the station to which the link metrics
	 * message will be sent.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the MAC address is valid and the station is associated
	 * before calling this function.
	 */
	int send_associated_sta_link_metrics_msg(mac_address_t sta_mac);
    
	/**!
	 * @brief Sends a response with associated link metrics for a given station.
	 *
	 * This function is responsible for sending a response that contains the link metrics
	 * associated with a specific station identified by its MAC address.
	 *
	 * @param[in] sta_mac The MAC address of the station for which the link metrics response is to be sent.
	 *
	 * @returns int Status code indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the MAC address provided is valid and that the system is
	 * capable of sending the response before calling this function.
	 */
	int send_associated_link_metrics_response(mac_address_t sta_mac);

    
	/**!
	 * @brief Handles the query for associated station link metrics.
	 *
	 * This function processes the query for link metrics associated with a station.
	 *
	 * @param[in] buff Pointer to the buffer containing the query data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_associated_sta_link_metrics_query(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the response for associated station link metrics.
	 *
	 * This function processes the response data for associated station link metrics
	 * received in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the response data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly
	 * specified to avoid buffer overflows.
	 */
	int handle_associated_sta_link_metrics_resp(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the association station link metrics TLV.
	 *
	 * This function processes the TLV (Type-Length-Value) data related to the link metrics
	 * of an associated station.
	 *
	 * @param[in] buff Pointer to the buffer containing the TLV data.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and contains valid TLV data
	 * before calling this function.
	 */
	int handle_assoc_sta_link_metrics_tlv(unsigned char *buff);
    
	/**!
	 * @brief Handles the association of station external link metrics TLV.
	 *
	 * This function processes the given buffer to handle the association of
	 * station external link metrics TLV.
	 *
	 * @param[in] buff Pointer to the buffer containing the TLV data.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated and contains valid TLV data.
	 */
	int handle_assoc_sta_ext_link_metrics_tlv(unsigned char *buff);
    
	/**!
	 * @brief Handles the association of station vendor link metrics TLV.
	 *
	 * This function processes the given buffer to handle the association
	 * of station vendor link metrics TLV.
	 *
	 * @param[in] buff Pointer to the buffer containing the TLV data.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and contains valid TLV data.
	 */
	int handle_assoc_sta_vendor_link_metrics_tlv(unsigned char *buff);
    
	/**!
	 * @brief Handles the beacon metrics query.
	 *
	 * This function processes the beacon metrics query contained in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the query data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_beacon_metrics_query(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the response for beacon metrics.
	 *
	 * This function processes the beacon metrics response contained in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the beacon metrics response.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_beacon_metrics_response(unsigned char *buff, unsigned int len);

  	/**!
	 * @brief Handles the associated station traffic statistics.
	 *
	 * This function processes the traffic statistics for a given associated station.
	 *
	 * @param[in] buff Pointer to the buffer containing traffic data.
	 * @param[in] bssid The BSSID of the associated station.
	 *
	 * @returns int Status code indicating success or failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the BSSID is valid before calling this function.
	 */
	int handle_assoc_sta_traffic_stats(unsigned char *buff, bssid_t bssid);
    
	/**!
	 * @brief Handles the access point metrics response.
	 *
	 * This function processes the metrics response received from the access point.
	 *
	 * @param[in] buff Pointer to the buffer containing the response data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_ap_metrics_response(unsigned char *buff, unsigned int len);
  
	/**!
	 * @brief Creates an association station link metrics TLV.
	 *
	 * This function generates a TLV (Type-Length-Value) structure for the association
	 * station link metrics and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 * @param[in] sta_mac MAC address of the station for which the metrics are being created.
	 * @param[in] sta Pointer to the station data structure containing metrics information.
	 *
	 * @returns short The length of the TLV created.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is large enough to hold the TLV.
	 */
	short create_assoc_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta);
    
	/**!
	 * @brief Creates an association extension for station link metrics TLV.
	 *
	 * This function is responsible for creating a TLV (Type-Length-Value) structure
	 * for the station link metrics associated with a given station MAC address.
	 *
	 * @param[out] buff Buffer where the TLV will be stored.
	 * @param[in] sta_mac MAC address of the station for which the metrics are being created.
	 * @param[in] sta Pointer to the station data structure containing metrics information.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer provided is large enough to hold the TLV structure.
	 */
	short create_assoc_ext_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta);
    
	/**!
	 * @brief Creates an error code TLV.
	 *
	 * This function generates a TLV (Type-Length-Value) structure for error codes.
	 *
	 * @param[out] buff Buffer where the TLV will be stored.
	 * @param[in] sta MAC address of the station.
	 * @param[in] sta_found Boolean indicating if the station was found.
	 *
	 * @returns Short integer representing the status of the TLV creation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is large enough to hold the TLV.
	 */
	short create_error_code_tlv(unsigned char *buff, mac_address_t sta, bool sta_found);
    
	/**!
	 * @brief Creates an association vendor STA link metrics TLV.
	 *
	 * This function generates a TLV (Type-Length-Value) structure for the association
	 * vendor-specific STA (Station) link metrics and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 * @param[in] sta_mac MAC address of the station for which the TLV is being created.
	 * @param[in] sta Pointer to the station data structure containing metrics information.
	 *
	 * @returns short
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is large enough to hold the TLV structure.
	 */
	short create_assoc_vendor_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta);
    
	/**!
	 * @brief Creates a beacon metrics query TLV.
	 *
	 * This function generates a beacon metrics query TLV and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 * @param[in] sta_mac MAC address of the station.
	 * @param[in] bssid BSSID of the network.
	 *
	 * @returns short The length of the generated TLV.
	 */
	short create_beacon_metrics_query_tlv(unsigned char *buff, mac_address_t sta_mac, bssid_t bssid);
    
	/**!
	 * @brief Sends a beacon metrics query to a specified station.
	 *
	 * This function initiates a query to gather beacon metrics from a station identified by its MAC address.
	 *
	 * @param[in] sta_mac The MAC address of the station to which the beacon metrics query is sent.
	 * @param[in] bssid The BSSID of the network to which the station is connected.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the station is within range and the MAC address is correct before sending the query.
	 */
	short send_beacon_metrics_query(mac_address_t sta_mac, bssid_t bssid);
    
	/**!
	 * @brief Sends a beacon metrics response.
	 *
	 * This function is responsible for sending a response containing beacon metrics.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the beacon metrics are correctly formatted before calling this function.
	 */
	int send_beacon_metrics_response();
    
	/**!
	 * @brief Creates a beacon metrics response TLV.
	 *
	 * This function generates a beacon metrics response TLV and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before calling this function.
	 */
	short create_beacon_metrics_response_tlv(unsigned char *buff);
  
	/**!
	 * @brief Creates an AP metrics TLV.
	 *
	 * This function generates an AP metrics TLV and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns short The length of the created TLV.
	 *
	 * @note Ensure the buffer is large enough to hold the TLV.
	 */
	short create_ap_metrics_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates an AP extension metrics TLV.
	 *
	 * This function initializes and creates a TLV (Type-Length-Value) for AP extension metrics.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is allocated with sufficient space before calling this function.
	 */
	short create_ap_ext_metrics_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a radio metrics TLV.
	 *
	 * This function generates a radio metrics TLV (Type-Length-Value) and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns short The size of the TLV created.
	 *
	 * @note Ensure that the buffer is large enough to hold the TLV.
	 */
	short create_radio_metrics_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates an associated station traffic statistics TLV.
	 *
	 * This function generates a TLV (Type-Length-Value) structure for the traffic statistics
	 * of an associated station and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 * @param[in] sta Constant pointer to the station data structure containing the statistics.
	 *
	 * @returns short The length of the TLV created.
	 *
	 * @note Ensure that the buffer is large enough to hold the TLV data.
	 */
	short create_assoc_sta_traffic_stats_tlv(unsigned char *buff, const dm_sta_t *const sta);
    
	/**!
	 * @brief Creates an association report TLV for a WiFi 6 station.
	 *
	 * This function generates a TLV (Type-Length-Value) report for a WiFi 6 station
	 * and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV report will be stored.
	 * @param[in] sta Constant pointer to the station data structure containing
	 *                information about the WiFi 6 station.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is adequately sized to hold the TLV report.
	 */
	short create_assoc_wifi6_sta_sta_report_tlv(unsigned char *buff, const dm_sta_t *const sta);

public:
    
	/**!
	 * @brief Processes a message.
	 *
	 * This function takes a data buffer and its length, processing the message contained within.
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
	 * This function is responsible for handling the control state of the system.
	 *
	 * @note Ensure that the system is initialized before calling this function.
	 */
	void process_ctrl_state();
    
	/**!
	 * @brief Processes the state of the agent.
	 *
	 * This function is responsible for handling the current state of the agent and performing necessary actions based on that state.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void process_agent_state();

    
	/**!
	 * @brief Constructor for the em_metrics_t class.
	 *
	 * Initializes a new instance of the em_metrics_t class.
	 *
	 * @note This constructor does not take any parameters.
	 */
	em_metrics_t();
    
	/**!
	 * @brief Destructor for the em_metrics_t class.
	 *
	 * This function cleans up any resources used by the em_metrics_t instance.
	 *
	 * @note This is a virtual destructor, allowing for proper cleanup of derived class objects.
	 */
	virtual ~em_metrics_t();
};

#endif

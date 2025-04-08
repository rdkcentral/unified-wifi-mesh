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

#ifndef EM_CAPABILITY_H
#define EM_CAPABILITY_H

#include "em_base.h"
#include "dm_easy_mesh.h"
#include "em.h"

class em_cmd_t;
class em_capability_t {

    
	/**!
	 * @brief Sends a frame of data.
	 *
	 * This function is responsible for sending a frame of data, which can be sent as multicast if specified.
	 *
	 * @param[in] buff Pointer to the buffer containing the data to be sent.
	 * @param[in] len Length of the data in the buffer.
	 * @param[in] multicast Boolean flag indicating if the data should be sent as multicast. Defaults to false.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
    
	/**!
	 * @brief Retrieves the data model.
	 *
	 * This function returns a pointer to the data model used in the easy mesh.
	 *
	 * @returns A pointer to the dm_easy_mesh_t data model.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_easy_mesh_t *get_data_model() = 0;
    
	/**!
	 * @brief Retrieves the current state of the entity.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns The current state of the entity as an em_state_t value.
	 *
	 * @note This function does not modify any member variables.
	 */
	virtual em_state_t get_state() = 0;
    
	/**!
	 * @brief Sets the state of the entity.
	 *
	 * This function sets the current state of the entity to the specified state.
	 *
	 * @param[in] state The new state to be set for the entity.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void set_state(em_state_t state) = 0;
    
	/**!
	 * @brief Retrieves the service type.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes to return the specific service type.
	 *
	 * @returns The service type as an em_service_type_t.
	 */
	virtual em_service_type_t get_service_type() = 0;
    
	/**!
	 * @brief Retrieves the profile type.
	 *
	 * This function returns the profile type associated with the current instance.
	 *
	 * @returns em_profile_type_t The profile type.
	 */
	virtual em_profile_type_t   get_profile_type() = 0;
    
	/**!
	 * @brief Sets the profile type.
	 *
	 * This function sets the profile type using the provided profile parameter.
	 *
	 * @param[in] profile The profile type to be set.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void    set_profile_type(em_profile_type_t profile) = 0;
    
	/**!
	 * @brief Retrieves the MAC address of the radio interface.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 *
	 * @note This function is pure virtual and must be implemented by derived classes.
	 */
	virtual unsigned char   *get_radio_interface_mac() = 0;
    
	/**!
	 * @brief Retrieves the radio interface.
	 *
	 * This function returns a pointer to the radio interface object.
	 *
	 * @returns A pointer to an em_interface_t object representing the radio interface.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual em_interface_t  *get_radio_interface() = 0;
    
	/**!
	 * @brief Retrieves the MAC address of the AL interface.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 *
	 * @note This function is pure virtual and must be implemented by derived classes.
	 */
	virtual unsigned char *get_al_interface_mac() = 0;
    
	/**!
	 * @brief Retrieves the radio data for a specified interface.
	 *
	 * This function is responsible for obtaining the radio data associated with a given
	 * interface, identified by the `radio` parameter.
	 *
	 * @param[in] radio The interface for which the radio data is to be retrieved.
	 *
	 * @returns A pointer to the `rdk_wifi_radio_t` structure containing the radio data.
	 * @retval nullptr If the radio data could not be retrieved or the interface is invalid.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual rdk_wifi_radio_t    *get_radio_data(em_interface_t *radio) = 0;
    
	/**!
	 * @brief Retrieves the IEEE 1905 security capabilities.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns A pointer to an em_ieee_1905_security_cap_t structure containing the security capabilities.
	 * @note The caller is responsible for managing the memory of the returned structure.
	 */
	virtual em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() = 0;
    
	/**!
	 * @brief Retrieves the device information.
	 *
	 * This function is a pure virtual function that must be implemented by the derived class to provide
	 * the necessary device information.
	 *
	 * @returns A pointer to an em_device_info_t structure containing the device information.
	 *
	 * @note The caller is responsible for managing the memory of the returned em_device_info_t pointer.
	 */
	virtual em_device_info_t    *get_device_info() = 0;
    
	/**!
	 * @brief Retrieves the MAC address of the peer.
	 *
	 * This function returns the MAC address of the peer as an unsigned char pointer.
	 *
	 * @returns A pointer to an unsigned char array representing the peer's MAC address.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual unsigned char *get_peer_mac() = 0;
    
	/**!
	 * @brief Retrieves the cryptographic information.
	 *
	 * This function is a pure virtual function that must be implemented by the derived class.
	 *
	 * @returns A pointer to an em_crypto_info_t structure containing the cryptographic information.
	 * @note The caller is responsible for managing the memory of the returned em_crypto_info_t pointer.
	 */
	virtual em_crypto_info_t    *get_crypto_info() = 0;
    
	/**!
	 * @brief Retrieves the cryptographic capabilities.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns A pointer to an em_crypto_t object representing the cryptographic capabilities.
	 *
	 * @note This function does not take any parameters and returns a non-null pointer.
	 */
	virtual em_crypto_t   *get_crypto() = 0;
    
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
	 * @brief Creates the basic capabilities for an AP radio.
	 *
	 * This function is responsible for setting up the basic capabilities
	 * of an Access Point (AP) radio and storing the information in the
	 * provided buffer.
	 *
	 * @param[out] buff A pointer to the buffer where the basic capabilities
	 *                  will be stored. The buffer must be allocated by the
	 *                  caller and should be large enough to hold the data.
	 *
	 * @returns A short integer indicating the success or failure of the
	 *          operation. Typically, a non-negative value indicates success,
	 *          while a negative value indicates an error.
	 *
	 * @note This is a pure virtual function and must be implemented by
	 *       derived classes.
	 */
	virtual short create_ap_radio_basic_cap(unsigned char *buff) = 0;
    
	/**!
	 * @brief Creates an AP capability TLV.
	 *
	 * This function is responsible for creating an AP capability TLV and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the AP capability TLV will be stored.
	 *
	 * @returns short The size of the created TLV.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual short create_ap_cap_tlv(unsigned char *buff) = 0;
    
	/**!
	 * @brief Creates an HT TLV.
	 *
	 * This function is responsible for creating an HT TLV and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the HT TLV will be stored.
	 *
	 * @returns short The size of the created HT TLV.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual short create_ht_tlv(unsigned char *buff) = 0;
    
	/**!
	 * @brief Creates a VHT TLV.
	 *
	 * This function is responsible for creating a VHT (Very High Throughput) TLV (Type-Length-Value) structure.
	 *
	 * @param[out] buff A pointer to the buffer where the VHT TLV will be created.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual short create_vht_tlv(unsigned char *buff) = 0;
    
	/**!
	 * @brief Creates a HE TLV.
	 *
	 * This function is responsible for creating a HE (High Efficiency) TLV (Type-Length-Value) structure.
	 *
	 * @param[out] buff Pointer to the buffer where the HE TLV will be created.
	 *
	 * @returns short The function returns a short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	virtual short create_he_tlv(unsigned char *buff) = 0;
    
	/**!
	 * @brief Creates a WiFi 6 TLV (Type-Length-Value) structure.
	 *
	 * This function is responsible for creating a WiFi 6 TLV structure and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual short create_wifi6_tlv(unsigned char *buff) = 0;
    
	/**!
	 * @brief Creates a WiFi 7 TLV (Type-Length-Value) structure.
	 *
	 * This function is responsible for creating a TLV structure specific to WiFi 7.
	 *
	 * @param[out] buff A pointer to the buffer where the TLV will be created.
	 *
	 * @returns A short integer indicating the success or failure of the TLV creation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	virtual short create_wifi7_tlv(unsigned char *buff) = 0;
    
	/**!
	 * @brief Creates an EHT operations TLV.
	 *
	 * This function is responsible for creating an EHT (Extremely High Throughput) operations TLV (Type-Length-Value) structure.
	 *
	 * @param[out] buff A pointer to the buffer where the TLV will be created.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	virtual short create_eht_operations_tlv(unsigned char *buff) = 0;
    
	/**!
	 * @brief Creates a channel scan TLV.
	 *
	 * This function is responsible for creating a channel scan TLV (Type-Length-Value) structure.
	 *
	 * @param[in,out] buff A pointer to the buffer where the TLV will be created. The buffer should be allocated by the caller.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is large enough to hold the TLV data.
	 */
	virtual short create_channelscan_tlv(unsigned char *buff) = 0;
    
	/**!
	 * @brief Creates a profile 2 TLV.
	 *
	 * This function is responsible for creating a profile 2 TLV (Type-Length-Value) structure.
	 *
	 * @param[in] buff Pointer to the buffer where the TLV will be created.
	 *
	 * @returns A short integer indicating the result of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual short create_prof_2_tlv(unsigned char *buff) = 0;
    
	/**!
	 * @brief Creates a device inventory TLV.
	 *
	 * This function is responsible for creating a device inventory TLV and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns short The size of the TLV created.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual short create_device_inventory_tlv(unsigned char *buff) = 0;
    
	/**!
	 * @brief Creates a radio advertisement TLV.
	 *
	 * This function is responsible for creating a radio advertisement TLV (Type-Length-Value) structure.
	 *
	 * @param[in] buff A pointer to the buffer where the TLV will be created.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	virtual short create_radioad_tlv(unsigned char *buff) = 0;
    
	/**!
	 * @brief Creates a metric collection integer TLV.
	 *
	 * This function is responsible for creating a metric collection integer TLV (Type-Length-Value) structure.
	 *
	 * @param[in] buff A pointer to the buffer where the TLV will be created.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	virtual short create_metric_col_int_tlv(unsigned char *buff) = 0;
    
	/**!
	 * @brief Creates a CAC capability TLV.
	 *
	 * This function is responsible for creating a CAC capability TLV and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns short The size of the created TLV.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual short create_cac_cap_tlv(unsigned char *buff) = 0;

    
	/**!
	 * @brief Sends a query to the client to retrieve capability information.
	 *
	 * This function initiates a request to the client to gather details about its capabilities.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure the client is ready to receive queries before calling this function.
	 */
	int send_client_cap_query();
    
	/**!
	 * @brief Sends a client capability report message.
	 *
	 * This function is responsible for sending a capability report message for a client identified by its MAC address to a specified BSSID.
	 *
	 * @param[in] sta The MAC address of the client station.
	 * @param[in] bss The BSSID to which the report message is sent.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the MAC address and BSSID are valid before calling this function.
	 */
	int send_client_cap_report_msg(mac_address_t sta, bssid_t bss);
    
	/**!
	 * @brief Creates an AP capability report message.
	 *
	 * This function generates a report message for AP capabilities and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the AP capability report message will be stored.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before calling this function.
	 */
	int create_ap_cap_report_msg(unsigned char *buff);
 
    // state handlers 
    
	/**!
	 * @brief Handles the state of the AP capability report.
	 *
	 * This function is responsible for processing and managing the state
	 * of the access point capability report. It ensures that the report
	 * is handled correctly and any necessary actions are taken.
	 *
	 * @note This function does not take any parameters and does not return
	 * any values. It performs its operations internally.
	 */
	void handle_state_ap_cap_report();
    
	/**!
	 * @brief Handles the control capability query.
	 *
	 * This function processes the control capability query based on the provided buffer and message type.
	 *
	 * @param[in] buff Pointer to the buffer containing the query data.
	 * @param[in] len Length of the buffer.
	 * @param[in] msg_type Type of the bus event message.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_ctrl_cap_query(unsigned char *buff, unsigned int len, em_bus_event_type_t msg_type);
    
	/**!
	 * @brief Handles the state of client capability report.
	 *
	 * This function is responsible for processing the client capability report
	 * and updating the system state accordingly.
	 *
	 * @note Ensure that the client capability data is valid before calling this function.
	 */
	void handle_state_client_cap_report();

    //TLV
    
	/**!
	 * @brief Creates an error code TLV.
	 *
	 * This function generates a TLV (Type-Length-Value) structure for error codes
	 * and populates the provided buffer with the necessary data.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 * @param[in] sta MAC address of the station.
	 * @param[in] bssid BSSID of the network.
	 *
	 * @returns short The length of the TLV written to the buffer.
	 *
	 * @note Ensure the buffer is large enough to hold the TLV data.
	 */
	short create_error_code_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid);
    
	/**!
	 * @brief Creates a client capability TLV (Type-Length-Value) structure.
	 *
	 * This function constructs a TLV structure for client capabilities using the provided buffer,
	 * station MAC address, and BSSID.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be created.
	 * @param[in] sta MAC address of the station.
	 * @param[in] bssid BSSID of the network.
	 *
	 * @returns A short integer indicating the success or failure of the TLV creation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is sufficiently large to hold the TLV structure.
	 */
	short create_client_cap_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid);
    
	/**!
	 * @brief Creates a client information TLV (Type-Length-Value) structure.
	 *
	 * This function constructs a TLV structure containing client information
	 * and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 * @param[in] sta MAC address of the station (client).
	 * @param[in] bssid BSSID of the access point.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is large enough to hold the TLV structure.
	 */
	short create_client_info_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid);

    
	/**!
	 * @brief Handles the client capability query.
	 *
	 * This function processes the capability query received from a client.
	 *
	 * @param[in] data Pointer to the data received from the client.
	 * @param[in] len Length of the data received.
	 *
	 * @note Ensure that the data pointer is valid and the length is correct before calling this function.
	 */
	void handle_client_cap_query(unsigned char *data, unsigned int len);
    
	/**!
	 * @brief Handles the client capability report.
	 *
	 * This function processes the capability report received from a client.
	 *
	 * @param[in] data Pointer to the data buffer containing the capability report.
	 * @param[in] len Length of the data buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the data buffer is valid and the length is correctly specified.
	 */
	int handle_client_cap_report(unsigned char *data, unsigned int len);

public:
    
	/**!
	 * @brief Processes a message with the given data and length.
	 *
	 * This function takes a pointer to a data buffer and its length, then processes the message contained within.
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
	 * @note Ensure that the agent is initialized before calling this function.
	 */
	void    process_agent_state();

    
	/**!
	 * @brief Retrieves the capability query transmission count.
	 *
	 * This function returns the number of capability query transmissions that have been made.
	 *
	 * @returns int The capability query transmission count.
	 */
	int get_cap_query_tx_count() { return static_cast<int>(m_cap_query_tx_cnt); }
    
	/**!
	 * @brief Sets the capability query transmission count.
	 *
	 * This function assigns the provided count to the member variable
	 * responsible for tracking the number of capability query transmissions.
	 *
	 * @param[in] cnt The count to set for capability query transmissions.
	 */
	void set_cap_query_tx_count(unsigned int cnt) { m_cap_query_tx_cnt = cnt; }

    unsigned int m_cap_query_tx_cnt;

    
	/**!
	 * @brief Default constructor for the em_capability_t class.
	 *
	 * This constructor initializes the em_capability_t object.
	 *
	 * @note This constructor does not take any parameters and does not return any value.
	 */
	em_capability_t();
    
	/**!
	 * @brief Destructor for em_capability_t class.
	 *
	 * This function cleans up any resources allocated by the em_capability_t instance.
	 *
	 * @note This is a virtual destructor, ensuring proper cleanup in derived classes.
	 */
	virtual ~em_capability_t();

};

#endif

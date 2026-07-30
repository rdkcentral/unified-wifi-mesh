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

#ifndef EM_MSG_H
#define EM_MSG_H
#include "em_base.h"

#define EM_MAX_TLV_MEMBERS 64

class em_tlv_member_t {
public:
    em_tlv_type_t m_type;
    em_tlv_requirement_t m_requirement;
    em_short_string_t m_spec;
    bool m_present;
    int m_tlv_length;
public:
    
	/**!
	 * @brief Constructor for em_tlv_member_t class.
	 *
	 * Initializes a TLV member with the specified type, requirement, specification, and length.
	 *
	 * @param[in] type The type of the TLV.
	 * @param[in] requirement The requirement level of the TLV.
	 * @param[in] spec The specification string for the TLV.
	 * @param[in] tlv_length The length of the TLV.
	 *
	 * @note This constructor sets the TLV member as not present initially.
	 */
	em_tlv_member_t(em_tlv_type_t type, em_tlv_requirement_t requirement, const char *spec,int tlv_length) {
        m_type = type; 
        m_requirement = requirement; 
        snprintf(m_spec, sizeof(m_spec), "%s", spec);
        m_tlv_length = tlv_length; // for tlv size check
        m_present = false;
    }
    
	/**!
	 * @brief Constructor for em_tlv_member_t.
	 *
	 * This function initializes the em_tlv_member_t object.
	 *
	 * @note This constructor does not take any parameters and does not return any value.
	 */
	em_tlv_member_t() { }
    
	/**!
	 * @brief Destructor for the em_tlv_member_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the em_tlv_member_t instance.
	 *
	 * @note Ensure that all dynamically allocated resources are properly released.
	 */
	~em_tlv_member_t() { }
};
class em_msg_t {
    em_msg_type_t m_type;
    em_profile_type_t m_profile;
    unsigned int m_num_tlv;
    em_tlv_member_t m_tlv_member[EM_MAX_TLV_MEMBERS];	
    unsigned int m_num_errors;
    em_short_string_t m_errors[EM_MAX_TLV_MEMBERS];
    unsigned char *m_buff;
    unsigned int m_len;
public:

    
	/**
	 * @brief Add a value to the message
	 *
	 * This function adds an element to the provided buffer and updates the buffer's length.
	 *
	 * @param[out] buff The buffer to add the item to.
	 * @param[in,out] len The current length of the buffer. Updated with the new length after adding the element.
	 * @param[in] element The element to add to the buffer.
	 * @param[in] element_len The length of the element to be added.
	 *
	 * @return unsigned char* The new buffer pointer after the element has been added.
	 *
	 * @note Ensure that the buffer has enough space to accommodate the new element.
	 */
	static unsigned char* add_buff_element(unsigned char *buff, unsigned int *len, unsigned char *element, unsigned int element_len);

    
	/**
	 * @brief Add a TLV to the message.
	 *
	 * This function appends a Type-Length-Value (TLV) to the provided buffer.
	 *
	 * @param[out] buff The buffer to which the TLV will be added. The buffer is updated with the new TLV.
	 * @param[in,out] len The current length of the buffer. This is updated with the new length after the TLV is added.
	 * @param[in] tlv_type The type of the TLV to be added.
	 * @param[in] value The value of the TLV.
	 * @param[in] value_len The length of the value.
	 *
	 * @return unsigned char* A pointer to the updated buffer.
	 *
	 * @note Ensure that the buffer has enough space to accommodate the new TLV.
	 */
	static unsigned char* add_tlv(unsigned char *buff, unsigned int *len, em_tlv_type_t tlv_type, unsigned char *value, unsigned int value_len);

    

	/**
	 * @brief Get a TLV from the message.
	 * 
	 * This function retrieves a TLV (Type-Length-Value) structure from the message buffer based on the specified type.
	 * 
	 * @param[in] tlvs_buff The buffer containing the TLV structures.
	 * @param[in] buff_len The length of the buffer.
	 * @param[in] type The type of the TLV to retrieve.
	 * 
	 * @return em_tlv_t* A pointer to the TLV structure if found, or NULL if not found.
	 * 
	 * @note Ensure that the buffer is properly initialized and contains valid TLV structures before calling this function.
	 */
	static em_tlv_t *get_tlv(em_tlv_t *tlvs_buff, unsigned int buff_len, em_tlv_type_t type);

	/**
	 * @brief Get the first TLV from the buffer.
	 *
	 * This function retrieves the first TLV (Type-Length-Value) structure from the provided buffer.
	 *
	 * @param[in] tlvs_buff The buffer containing the TLV structures.
	 * @param[in] buff_len The length of the buffer.
	 *
	 * @return em_tlv_t* A pointer to the first TLV structure in the buffer, or NULL if the buffer is empty.
	 *
	 * @note Ensure that the buffer is properly initialized and contains valid TLV structures before calling this function.
	 */
	static em_tlv_t *get_first_tlv(em_tlv_t* tlvs_buff, unsigned int buff_len);

	/**
	 * @brief Get the next TLV from the buffer.
	 *
	 * This function retrieves the next TLV (Type-Length-Value) structure from the provided buffer, starting from a given TLV.
	 *
	 * @param[in] tlv The current TLV structure from which to find the next TLV.
	 * @param[in] tlvs_buff The buffer containing the TLV structures.
	 * @param[in] buff_len The length of the buffer.
	 *
	 * @return em_tlv_t* A pointer to the next TLV structure in the buffer, or NULL if there are no more TLVs.
	 *
	 * @note Ensure that the buffer is properly initialized and contains valid TLV structures before calling this function.
	 */
	static em_tlv_t *get_next_tlv(em_tlv_t* tlv, em_tlv_t* tlvs_buff, unsigned int buff_len);

	/**
	 * @brief Add an EOM TLV to the message.
	 *
	 * This function appends an End of Message (EOM) Type-Length-Value (TLV) to the provided buffer.
	 *
	 * @param[in,out] buff The buffer to which the TLV will be added.
	 * @param[in,out] len The current length of the buffer. This parameter is updated with the new length after the TLV is added.
	 *
	 * @return unsigned char* A pointer to the new buffer with the added TLV.
	 */
	inline static unsigned char* add_eom_tlv(unsigned char *buff, unsigned int *len) {
        return add_tlv(buff, len, em_tlv_type_eom, NULL, 0);
    }

    
	/**
	* @brief Add a 1905 header to the message.
	*
	* This function appends a 1905 header to the provided buffer.
	*
	* @param[out] buff The buffer to which the header will be added.
	* @param[in,out] len The current length of the buffer. This will be updated with the new length after the header is added.
	* @param[in] dst The destination MAC address.
	* @param[in] src The source MAC address.
	* @param[in] msg_type The type of message to be added.
	* @param[in] msg_id The message ID.
	*
	* @return unsigned char* A pointer to the new buffer with the added header.
	*
	* @note Ensure that the buffer has enough space to accommodate the new header.
	*/
	static unsigned char* add_1905_header(unsigned char *buff, unsigned int *len, mac_addr_t dst, mac_addr_t src, em_msg_type_t msg_type, unsigned short msg_id);

    
	/**!
	 * @brief Validates the input errors array.
	 *
	 * This function checks the provided array of error messages and performs
	 * necessary validation operations.
	 *
	 * @param[out] errors Array of error messages to be validated.
	 *
	 * @returns unsigned int The result of the validation process.
	 * @retval 0 if validation is successful.
	 * @retval 1 if validation fails.
	 *
	 * @note Ensure that the errors array is properly initialized before calling this function.
	 */
	unsigned int validate(char *errors[]);
    
	/**!
	 * @brief Retrieves the radio ID associated with the given MAC address.
	 *
	 * This function fetches the radio identifier linked to the specified MAC address.
	 *
	 * @param[out] mac Pointer to a mac_address_t structure where the radio ID will be stored.
	 *
	 * @returns True if the radio ID is successfully retrieved, false otherwise.
	 *
	 * @note Ensure that the mac pointer is valid and points to a properly allocated mac_address_t structure.
	 */
	bool get_radio_id(mac_address_t *mac);
    
	/**!
	 * @brief Retrieves the BSS ID.
	 *
	 * This function fetches the BSS ID and stores it in the provided MAC address structure.
	 *
	 * @param[out] mac Pointer to a mac_address_t structure where the BSS ID will be stored.
	 *
	 * @returns true if the BSS ID was successfully retrieved, false otherwise.
	 *
	 * @note Ensure that the mac pointer is valid and points to a properly allocated mac_address_t structure.
	 */
	bool get_bss_id(mac_address_t *mac);
    
	/**!
	* @brief Retrieves the profile information.
	*
	* This function fetches the profile details based on the provided profile type.
	*
	* @param[out] profile Pointer to the profile structure where the profile information will be stored.
	*
	* @returns True if the profile was successfully retrieved, false otherwise.
	*
	* @note Ensure that the profile pointer is valid before calling this function.
	*/
	bool get_profile(em_profile_type_t *profile);
    
	/**!
	 * @brief Retrieves the frequency band.
	 *
	 * This function is responsible for obtaining the current frequency band
	 * and storing it in the provided em_freq_band_t structure.
	 *
	 * @param[out] band Pointer to an em_freq_band_t structure where the
	 *                  frequency band will be stored.
	 *
	 * @returns True if the frequency band was successfully retrieved,
	 *          false otherwise.
	 *
	 * @note Ensure that the band pointer is valid before calling this function.
	 */
	bool get_freq_band(em_freq_band_t *band);
    
	/**!
	 * @brief Retrieves a TLV (Type-Length-Value) structure.
	 *
	 * This function is responsible for obtaining a TLV structure from the system.
	 *
	 * @param[out] tlv Pointer to the TLV structure to be filled.
	 *
	 * @returns True if the TLV was successfully retrieved, false otherwise.
	 *
	 * @note Ensure that the pointer `tlv` is valid and points to a pre-allocated memory space.
	 */
	bool get_tlv(em_tlv_t *tlv);
    
	/**!
	 * @brief Retrieves the profile type.
	 *
	 * This function fetches the profile type and stores it in the provided
	 * profile pointer.
	 *
	 * @param[out] profile Pointer to the profile type that will be filled
	 * with the current profile information.
	 *
	 * @returns True if the profile type was successfully retrieved, false otherwise.
	 *
	 * @note Ensure that the profile pointer is valid before calling this function.
	 */
	bool get_profile_type(em_profile_type_t *profile);
    
	/**!
	 * @brief Retrieves the MAC address of the device.
	 *
	 * This function fetches the MAC address and stores it in the provided buffer.
	 *
	 * @param[out] mac Pointer to a buffer where the MAC address will be stored.
	 *
	 * @returns True if the MAC address was successfully retrieved, false otherwise.
	 *
	 * @note Ensure that the buffer pointed to by `mac` is large enough to hold the MAC address.
	 */
	bool get_al_mac_address(unsigned char *mac);
    
	/**!
	 * @brief Retrieves a TLV (Type-Length-Value) structure based on the specified type.
	 *
	 * This function searches for and returns a pointer to a TLV structure that matches the given type.
	 *
	 * @param[in] type The type of the TLV to retrieve.
	 *
	 * @returns A pointer to the TLV structure if found, otherwise NULL.
	 *
	 * @note Ensure that the TLV type provided is valid and that the TLV structure exists.
	 */
	em_tlv_t *get_tlv(em_tlv_type_t type);
    
	/**!
	 * @brief Initiates the autoconfiguration search process.
	 *
	 * This function triggers the search for available configurations automatically.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void autoconfig_search();
    
	/**!
	 * @brief Handles the response for autoconfiguration.
	 *
	 * This function processes the response received after an autoconfiguration request.
	 * It ensures that the system is configured correctly based on the response data.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void autoconfig_resp();
    
	/**!
	 * @brief Initiates the WSC M1 auto-configuration process.
	 *
	 * This function is responsible for starting the auto-configuration
	 * process using the WSC (Wi-Fi Simple Configuration) M1 message.
	 *
	 * @note Ensure that the system is in the correct state before
	 * calling this function to avoid unexpected behavior.
	 */
	void autoconfig_wsc_m1();
    
	/**!
	 * @brief Initiates the WSC M2 auto-configuration process.
	 *
	 * This function is responsible for starting the auto-configuration
	 * process using the WSC (Wi-Fi Simple Configuration) M2 message.
	 *
	 * @note Ensure that the device is in the correct state before
	 * calling this function to avoid unexpected behavior.
	 */
	void autoconfig_wsc_m2();
    
	/**!
	 * @brief Initiates the topology discovery process.
	 *
	 * This function starts the discovery of network topology.
	 *
	 * @note Ensure that the network is ready for discovery before calling this function.
	 */
	void topo_disc();
    
	/**!
	 * @brief Notifies the topology changes.
	 *
	 * This function is responsible for handling notifications related to topology changes.
	 *
	 * @note Ensure that the notification system is initialized before calling this function.
	 */
	void topo_notif();
    
	/**!
	 * @brief Queries the topology information.
	 *
	 * This function is used to query the current topology information.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void topo_query();
    
	/**!
	 * @brief Handles the topology response.
	 *
	 * This function is responsible for processing the topology response.
	 *
	 * @note Ensure that the topology data is correctly formatted before calling this function.
	 */
	void topo_resp();
    
	/**!
	 * @brief Handles the vendor-specific topology operations.
	 *
	 * This function is responsible for handling vendor-specific topology operations.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void topo_vendor();
    
	/**!
	 * @brief Queries the link metric.
	 *
	 * This function initiates a query to retrieve the current link metrics.
	 *
	 * @note Ensure that the system is initialized before calling this function.
	 */
	void link_metric_query();
    
	/**!
	 * @brief Handles the response for link metric requests.
	 *
	 * This function processes the response received for a link metric request.
	 * It is responsible for interpreting the data and updating the relevant
	 * metrics or state within the system.
	 *
	 * @note Ensure that the response data is validated before calling this function.
	 */
	void link_metric_resp();
    
	/**!
	 * @brief Renews the auto-configuration settings.
	 *
	 * This function is responsible for renewing the auto-configuration settings
	 * of the system. It does not take any parameters and does not return any
	 * values.
	 *
	 * @note This function should be called periodically to ensure that the
	 * configuration settings are up-to-date.
	 */
	void autoconfig_renew();
    
	/**!
	 * @brief Queries the access point capabilities.
	 *
	 * This function is used to query the capabilities of the access point.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void ap_cap_query();
    
	/**!
	 * @brief This function is responsible for handling the access point capability report.
	 *
	 * This function processes the capability report from the access point and updates the system state accordingly.
	 *
	 * @note Ensure that the system is initialized before calling this function.
	 */
	void ap_cap_rprt();
    
	/**!
	 * @brief Configures the policy settings.
	 *
	 * This function is responsible for setting up the necessary policy configurations.
	 *
	 * @note Ensure that the policy settings are initialized before calling this function.
	 */
	void policy_config_req();
    
	/**!
	 * @brief Queries the channel preferences.
	 *
	 * This function is responsible for querying the current channel preferences.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void channel_pref_query();
    
	/**!
	 * @brief Reports the channel preferences.
	 *
	 * This function is responsible for reporting the channel preferences based on the current configuration and status.
	 *
	 * @note Ensure that the channel configuration is updated before calling this function.
	 */
	void channel_pref_rprt();
    
	/**!
	 * @brief Initiates a channel selection request.
	 *
	 * This function is responsible for triggering the process of selecting a communication channel.
	 *
	 * @note Ensure that the system is in the correct state before calling this function.
	 */
	void channel_sel_req();
    
	/**!
	 * @brief Handles the response for channel selection.
	 *
	 * This function is responsible for processing the response received
	 * after a channel selection request is made.
	 *
	 * @note Ensure that the channel selection request was successful
	 * before calling this function.
	 */
	void channel_sel_rsp();
    
	/**!
	 * @brief Handles the channel report.
	 *
	 * This function is responsible for handling the operation of channel report.
	 *
	 * @note 
	 * Ensure that the channel report is initialized before calling this function.
	 */
	void op_channel_rprt();
    
	/**!
	 * @brief Queries the capabilities of the client.
	 *
	 * This function initiates a query to retrieve the capabilities
	 * of the client. It does not take any parameters and does not
	 * return any values.
	 *
	 * @note Ensure the client is initialized before calling this function.
	 */
	void client_cap_query();
    
	/**!
	 * @brief Initiates a client steering request.
	 *
	 * This function is responsible for handling the client steering request
	 * within the system. It does not take any parameters and does not return
	 * any values.
	 *
	 * @note Ensure that the system is in the correct state before calling
	 * this function to avoid unexpected behavior.
	 */
	void client_steering_req();
    
	/**!
	 * @brief Handles the client steering BTM report.
	 *
	 * This function processes the BTM (BSS Transition Management) report for client steering.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void client_steering_btm_rprt();
    
	/**!
	 * @brief Initiates a client association control request.
	 *
	 * This function is responsible for handling the client association control
	 * request within the messaging system.
	 *
	 * @note Ensure that the client is properly initialized before calling this
	 * function.
	 */
	void client_assoc_ctrl_req();
    
	/**!
	 * @brief Completes the steering process.
	 *
	 * This function is called when the steering operation is finished.
	 *
	 * @note Ensure that all necessary conditions are met before calling this function.
	 */
	void steering_complete();
    
	/**!
	 * @brief This function handles higher layer data processing.
	 *
	 * This function is responsible for managing and processing data from higher layers.
	 *
	 * @note Ensure that the data is properly formatted before calling this function.
	 */
	void higher_layer_data();
    
	/**!
	 * @brief Initiates a steering request.
	 *
	 * This function is responsible for handling the steering request process.
	 *
	 * @note Ensure that the system is in the correct state before calling this function.
	 */
	void bh_steering_req();
    
	/**!
	 * @brief Handles the steering response.
	 *
	 * This function processes the steering response received from the system.
	 *
	 * @note Ensure that the steering response is valid before calling this function.
	 */
	void bh_steering_rsp();
    
	/**!
	 * @brief Reports the capabilities of the client.
	 *
	 * This function is responsible for gathering and reporting the capabilities
	 * of the client to the server or other components as required.
	 *
	 * @note Ensure that the client is initialized before calling this function.
	 */
	void client_cap_rprt();
    
	/**!
	 * @brief Queries the access point metrics.
	 *
	 * This function is responsible for querying the metrics related to the access point.
	 *
	 * @note Ensure that the system is initialized before calling this function.
	 */
	void ap_metrics_query();
    
	/**!
	 * @brief Handles the response for access point metrics.
	 *
	 * This function processes the response received for access point metrics.
	 * It does not take any parameters and does not return any value.
	 *
	 * @note Ensure that the response data is valid before calling this function.
	 */
	void ap_metrics_rsp();
    
	/**!
	* @brief Initiates a link metrics query for the station.
	*
	* This function sends a request to gather link metrics for a specific station.
	* It is used to assess the quality and performance of the link.
	*
	* @note Ensure that the station is connected before calling this function.
	*/
	void sta_link_metrics_query();
    
	/**!
	 * @brief 
	 *
	 * This function is responsible for handling the response for station link metrics.
	 *
	 * @note Ensure that the response is processed correctly to maintain link quality.
	 */
	void sta_link_metrics_rsp();
    
	/**!
	 * @brief Queries the link metrics for unassociated stations.
	 *
	 * This function initiates a query to gather link metrics for stations that are not currently associated.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void unassoc_sta_link_metrics_query();
    
	/**!
	 * @brief Sends a response with link metrics for an unassociated station.
	 *
	 * This function is responsible for generating and sending a response
	 * containing link metrics for a station that is not currently associated
	 * with the network.
	 *
	 * @note Ensure that the station is valid and metrics are available
	 * before calling this function.
	 */
	void unassoc_sta_link_metrics_rsp();
    
	/**!
	 * @brief Initiates a query for beacon metrics.
	 *
	 * This function triggers the process to gather metrics related to beacon performance.
	 *
	 * @note Ensure that the system is in the correct state to perform this query.
	 */
	void beacon_metrics_query();
    
	/**!
	 * @brief Handles the response for beacon metrics.
	 *
	 * This function processes the response received for beacon metrics.
	 *
	 * @note Ensure that the response data is validated before calling this function.
	 */
	void beacon_metrics_rsp();
    
	/**!
	 * @brief This function is responsible for handling combined infrastructure metrics.
	 *
	 * This function does not take any parameters and does not return any value.
	 *
	 * @note Ensure that the necessary infrastructure components are initialized before calling this function.
	 */
	void combined_infra_metrics();
    
	/**!
	* @brief Initiates a channel scan request.
	*
	* This function triggers the scanning of available channels.
	*
	* @note Ensure that the system is in the correct state to perform a scan.
	*/
	void channel_scan_req();
    
	/**!
	 * @brief Notifies the management system about the current QoS status.
	 *
	 * This function is responsible for sending notifications related to Quality of Service (QoS) management.
	 *
	 * @note Ensure that the management system is ready to receive notifications before calling this function.
	 */
	void qos_mgmt_notif();
    
	/**!
	 * @brief Reports the anticipated channel usage.
	 *
	 * This function provides information about the expected usage of channels.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void anticipated_channel_usage_rprt();
    
	/**!
	 * @brief This function handles the anticipated channel preference.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void anticipated_channel_pref();
    
	/**!
	 * @brief Lists all agents.
	 *
	 * This function retrieves and displays a list of all agents currently available.
	 *
	 * @note Ensure that the agent system is initialized before calling this function.
	 */
	void agent_list();
    
	/**!
	 * @brief Indicates a failed connection attempt.
	 *
	 * This function is called when a connection attempt fails.
	 * It may trigger error handling routines or logging mechanisms.
	 *
	 * @note Ensure that the connection parameters are correct before retrying.
	 */
	void failed_conn();
    
	/**!
	 * @brief Notifies the system of a new DPP bootstrap URI.
	 *
	 * This function is called when a new Device Provisioning Protocol (DPP) bootstrap URI is available.
	 * It handles the notification process to ensure the URI is processed correctly.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void dpp_bootstrap_uri_notif();
    
	/**!
	 * @brief Encapsulates EAPOL frames for transmission.
	 *
	 * This function is responsible for preparing and encapsulating EAPOL (Extensible Authentication Protocol over LAN) frames
	 * for network transmission. It ensures that the frames are correctly formatted and ready to be sent over the network.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void i1905_encap_eapol();
    
	/**!
	 * @brief Notifies the system of a chirp event.
	 *
	 * This function is used to signal that a chirp event has occurred.
	 *
	 * @note Ensure that the system is ready to handle chirp notifications before calling this function.
	 */
	void chirp_notif();
    
	/**!
	 * @brief Configures the BSS (Base Station Subsystem) response.
	 *
	 * This function is responsible for handling the configuration response
	 * for the BSS. It ensures that the necessary parameters are set and
	 * validated for successful communication.
	 *
	 * @note This function does not take any parameters and does not return
	 * any values. It is used internally within the system to manage BSS
	 * configurations.
	 */
	void bss_config_res();
    
	/**!
	 * @brief Configures the BSS response.
	 *
	 * This function handles the configuration response for the BSS.
	 *
	 * @note Ensure that the BSS is properly initialized before calling this function.
	 */
	void bss_config_rsp();
    
	/**!
	 * @brief Configures the BSS (Base Station Subsystem) settings.
	 *
	 * This function is responsible for setting up the necessary parameters
	 * for the BSS configuration request.
	 *
	 * @note Ensure that all required parameters are initialized before
	 * calling this function.
	 */
	void bss_config_req();
    
	/**!
	 * @brief Initiates a channel scan report.
	 *
	 * This function triggers the process to generate a report of the channel scan.
	 *
	 * @note Ensure that the scanning process is complete before calling this function.
	 */
	void channel_scan_rprt();
    
	/**!
	 * @brief Handles the DPP (Device Provisioning Protocol) CCE (Configuration Change Event) indication.
	 *
	 * This function is responsible for handling the DPP CCE indication.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void dpp_cce_ind();
    
	/**!
	 * @brief Initiates a rekey request for the i1905 protocol.
	 *
	 * This function triggers the rekeying process, which is essential for maintaining secure communication channels.
	 *
	 * @note Ensure that the system is in a state that allows rekeying before calling this function.
	 */
	void i1905_rekey_req();
    
	/**!
	 * @brief Handles the decryption failure event in the i1905 protocol.
	 *
	 * This function is called when a decryption operation fails, allowing the system to
	 * perform necessary error handling or logging.
	 *
	 * @note Ensure that the decryption context and keys are correctly set up before
	 * calling this function to avoid unnecessary failures.
	 */
	void i1905_decrypt_fail();
    
	/**!
	 * @brief Terminates the CAC (Channel Access Control) process.
	 *
	 * This function is responsible for cleaning up and releasing any resources
	 * associated with the CAC process. It should be called when the CAC process
	 * is no longer needed.
	 *
	 * @note Ensure that all operations using CAC are completed before calling
	 * this function to avoid unexpected behavior.
	 */
	void cac_term();
    
	/**!
	 * @brief Handles the disassociation statistics for a client.
	 *
	 * This function handles the disassociation statistics for a client.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void client_disassoc_stats();
    
	/**!
	 * @brief Handles priority request service.
	 *
	 * This function is responsible for managing priority requests within the system.
	 *
	 * @note Ensure that the system is initialized before calling this function.
	 */
	void svc_prio_req();
    
	/**!
	 * @brief Handles error response.
	 *
	 * This function is responsible for processing error responses.
	 *
	 * @note Ensure that the error codes are properly defined.
	 */
	void err_rsp();
    
	/**!
	 * @brief Notifies the association status.
	 *
	 * This function is responsible for notifying the current status of the association.
	 * It does not take any parameters and does not return any value.
	 *
	 * @note Ensure that the association status is updated before calling this function.
	 */
	void assoc_status_notif();
    
	/**!
	 * @brief This function is responsible for handling tunneled operations.
	 *
	 * @note Ensure that the necessary preconditions are met before calling this function.
	 */
	void tunneled();
    
	/**!
	 * @brief Queries the station capabilities.
	 *
	 * This function is used to query the capabilities of a station.
	 * It does not take any parameters and does not return any value.
	 *
	 * @note This function is a placeholder and should be implemented.
	 */
	void bh_sta_cap_query();
    
	/**!
	 * @brief Reports the station capabilities.
	 *
	 * This function is responsible for reporting the capabilities of the station.
	 *
	 * @note Ensure that the station is initialized before calling this function.
	 */
	void bh_sta_cap_rprt();
    
	/**!
	 * @brief Encapsulates the DPP (Device Provisioning Protocol) process.
	 *
	 * This function is responsible for handling the encapsulation of the DPP process.
	 * It does not take any parameters and does not return any value.
	 *
	 * @note Ensure that the DPP context is properly initialized before calling this function.
	 */
	void proxied_encap_dpp();
    
	/**!
	 * @brief Directly encapsulates DPP (Data Processing Protocol).
	 *
	 * This function is responsible for handling the encapsulation of DPP.
	 *
	 * @note Ensure that the necessary preconditions are met before calling this function.
	 */
	void direct_encap_dpp();
    
	/**!
	* @brief Triggers a reconfiguration process.
	*
	* This function initiates a reconfiguration sequence within the system.
	*
	* @note Ensure that the system is in a stable state before triggering reconfiguration.
	*/
	void reconfig_trigger();
    
	/**!
	 * @brief Initiates a CAC request process.
	 *
	 * This function is responsible for starting the CAC (Channel Access Control) request.
	 *
	 * @note Ensure that the system is in the correct state before calling this function.
	 */
	void cac_req();
    
	/**!
	 * @brief Configures the MLD (Multicast Listener Discovery) settings.
	 *
	 * This function is responsible for setting up the necessary configurations
	 * for MLD operations. It should be called to initialize or update the MLD
	 * settings as required by the application.
	 *
	 * @note Ensure that the network interface is initialized before calling
	 * this function.
	 */
	void ap_mld_config_req();
    
	/**!
	 * @brief Handles the response for MLD configuration.
	 *
	 * This function processes the response received after sending a
	 * MLD (Multicast Listener Discovery) configuration request.
	 *
	 * @note Ensure that the MLD configuration request has been sent
	 * before calling this function.
	 */
	void ap_mld_config_rsp();
    
	/**!
	 * @brief Acknowledges the receipt of a message in the i1905 protocol.
	 *
	 * This function is used to send an acknowledgment for a received message
	 * in the i1905 protocol, ensuring that the sender is aware of the receipt.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void i1905_ack();
    
	/**!
	 * @brief Sets the M1 message with the given TLVs and length.
	 *
	 * This function initializes the M1 message using the provided TLVs and length.
	 *
	 * @param[in] tlvs Pointer to the TLVs data.
	 * @param[in] len Length of the TLVs data.
	 *
	 * @note Ensure that the TLVs pointer is valid and the length is correct to avoid buffer overflow.
	 */
	void set_m1(unsigned char *tlvs, unsigned int len);
    
	/**!
	 * @brief Retrieves the MAC address information of the client.
	 *
	 * This function fills the provided mac_address_t structure with the client's MAC address details.
	 *
	 * @param[out] mac Pointer to a mac_address_t structure where the MAC address information will be stored.
	 *
	 * @returns True if the MAC address information was successfully retrieved, false otherwise.
	 *
	 * @note Ensure that the mac parameter is a valid pointer before calling this function.
	 */
	bool get_client_mac_info(mac_address_t *mac);

    
	/**!
	 * @brief Constructor for em_msg_t class.
	 *
	 * Initializes an em_msg_t object with the specified type, profile, TLVs, and length.
	 *
	 * @param[in] type The type of the message.
	 * @param[in] profile The profile type associated with the message.
	 * @param[in] tlvs Pointer to the TLVs (Type-Length-Value) data.
	 * @param[in] len The length of the TLVs data.
	 *
	 * @note Ensure that the TLVs data is properly allocated and managed outside this constructor.
	 */
	em_msg_t(em_msg_type_t type, em_profile_type_t profile, unsigned char *tlvs, unsigned int len);
    
	/**!
	 * @brief Constructor for em_msg_t class.
	 *
	 * This constructor initializes the em_msg_t object with the provided TLVs and length.
	 *
	 * @param[in] tlvs Pointer to the TLVs (Type-Length-Value) data.
	 * @param[in] len Length of the TLVs data.
	 *
	 * @note Ensure that the TLVs data is valid and the length is correctly specified.
	 */
	em_msg_t(unsigned char *tlvs, unsigned int len);
    
	/**!
	 * @brief Default constructor for em_msg_t.
	 *
	 * This constructor initializes an instance of em_msg_t.
	 *
	 * @note This constructor does not take any parameters and does not return any value.
	 */
	em_msg_t() {}
    
	/**!
	 * @brief Destructor for the em_msg_t class.
	 *
	 * This function is responsible for cleaning up resources used by the em_msg_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	~em_msg_t();
};
#endif

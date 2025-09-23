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

#ifndef EM_CONFIGURATION_H
#define EM_CONFIGURATION_H

#include "em_base.h"
#include "em_crypto.h"
#include "dm_easy_mesh.h"
#include "ec_manager.h"

class em_cmd_t;
class em_mgr_t;
class em_configuration_t {

    
	/**!
	 * @brief Creates an auto-configuration response message.
	 *
	 * This function is responsible for generating a response message for auto-configuration
	 * based on the specified frequency band and destination.
	 *
	 * @param[out] buff Pointer to the buffer where the response message will be stored.
	 * @param[in] band The frequency band for which the response message is being created.
	 * @param[in] dst Pointer to the destination address for the response message.
	 * @param[in] chirp Optional pointer to a DPP chirp value to include in the message.
	 * @param[in] hash_len Length of the hash to be included in the chirp (can be 0 if no chirp is present).
	 *
	 * @return int The length of the created response message, or -1 on failure.
	 *
	 * @note Ensure that the buffer is adequately sized to hold the response message.
	 */
	int create_autoconfig_resp_msg(unsigned char *buff, em_freq_band_t band, unsigned char *dst, em_dpp_chirp_value_t *chirp = nullptr, size_t hash_len = 0);
    
	/**!
	 * @brief Creates an auto-configuration search message.
	 *
	 * This function is responsible for generating a search message used in the auto-configuration process.
	 *
	 * @param[out] buff Pointer to the buffer where the search message will be stored.
	 * @param[in] chirp Optional pointer to a DPP chirp value to include in the message.
	 * @param[in] hash_len Length of the hash to be included in the chirp (can be 0 if no chirp is present).
	 *
	 * @returns int Size of CMDU created on success, otherwise -1
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before calling this function.
	 */
	int create_autoconfig_search_msg(unsigned char *buff, em_dpp_chirp_value_t *chirp = nullptr, size_t hash_len = 0);
    
	/**!
	 * @brief Creates an auto-configuration WSC M1 message.
	 *
	 * This function generates a WSC M1 message and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the message will be stored.
	 * @param[in] dst Pointer to the destination address.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is allocated with sufficient size to hold the message.
	 */
	int create_autoconfig_wsc_m1_msg(unsigned char *buff, unsigned char *dst);
    
	/**!
	 * @brief Creates an auto-configuration WSC M2 message.
	 *
	 * This function generates a WSC (Wi-Fi Simple Configuration) M2 message for auto-configuration purposes.
	 *
	 * @param[out] buff Pointer to the buffer where the generated message will be stored.
	 * @param[in] haul_type Array of haul types used in the configuration.
	 * @param[in] num_hauls Number of haul types in the array.
	 *
	 * @returns int Status code indicating success or failure of the message creation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the buffer is adequately sized to hold the generated message.
	 */
	int create_autoconfig_wsc_m2_msg(unsigned char *buff, em_haul_type_t haul_type[], unsigned int num_hauls);
    
	/**!
	 * @brief Creates a BSS configuration request message.
	 *
	 * This function initializes a buffer with the necessary data to form a BSS configuration request message.
	 *
	 * @param[out] buff Pointer to the buffer where the request message will be stored.
	 * @param[in] dest_al_mac  The destination AL MAC address for the message.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval the size of the request message on success. 
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is allocated with sufficient size before calling this function.
	 */
	int create_bss_config_req_msg(uint8_t *buff, uint8_t dest_al_mac[ETH_ALEN]);
    
	/**!
	 * @brief Creates a BSS configuration response message.
	 *
	 * This function is responsible for creating a BSS configuration response message
	 * and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the response message will be stored.
	 * @param[in] dest_al_mac  The destination AL MAC address for the message.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval the size of the response message on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is allocated with sufficient size before calling this function.
	 */
	int create_bss_config_rsp_msg(uint8_t *buff, uint8_t dest_al_mac[ETH_ALEN], SSL_KEY* enrollee_nak);
    
	/**!
	 * @brief Creates a BSS configuration response message.
	 *
	 * This function initializes a buffer with the BSS configuration response message.
	 *
	 * @param[out] buff Pointer to the buffer where the response message will be stored.
	 * @param[in] dest_al_mac  The destination AL MAC address for the message.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval the size of the response message on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is allocated with sufficient size before calling this function.
	 */
	int create_bss_config_res_msg(uint8_t *buff, uint8_t dest_al_mac[ETH_ALEN]);


	/**!
	 * @brief Creates an agent list message.
	 *
	 * This function generates an Agent List message according to EasyMesh R6 17.1.48
	 *
	 * @param[out] buff Pointer to the buffer where the agent list message will be stored.
	 * @param[in] dest_al_mac The destination AL MAC address for the message.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval the size of the agent list message on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before calling this function.
	 */
	int create_agent_list_msg(uint8_t *buff, uint8_t dest_al_mac[ETH_ALEN]);

	/**!
	 * @brief Creates an operational BSS TLV.
	 *
	 * This function is responsible for creating an operational BSS TLV and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	int	create_operational_bss_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates an operational BSS TLV topology.
	 *
	 * This function is responsible for creating the topology of the operational BSS TLV.
	 *
	 * @param[out] buff A pointer to the buffer where the topology will be stored.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	int create_operational_bss_tlv_topology(unsigned char *buff);
    
	/**!
	 * @brief Creates a BSS configuration report TLV.
	 *
	 * This function generates a BSS (Basic Service Set) configuration report TLV (Type-Length-Value) and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the BSS configuration report TLV will be stored.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is large enough to hold the TLV data.
	 */
	int	create_bss_config_rprt_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a device information type TLV (Type-Length-Value) structure.
	 *
	 * This function initializes a TLV structure with device information type data.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV structure will be created.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before calling this function.
	 */
	int create_device_info_type_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a client association event TLV.
	 *
	 * This function constructs a TLV (Type-Length-Value) for a client association event.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 * @param[in] sta The MAC address of the station (client).
	 * @param[in] bssid The BSSID of the access point.
	 * @param[in] assoc Boolean flag indicating association status.
	 *
	 * @returns The length of the created TLV.
	 *
	 * @note Ensure that the buffer is large enough to hold the TLV.
	 */
	unsigned short create_client_assoc_event_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid, bool assoc);
    
	/**!
	 * @brief Creates an AP MLD configuration TLV.
	 *
	 * This function initializes and creates a TLV (Type-Length-Value) for AP MLD (Access Point Multi-Link Device) configuration.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is allocated with sufficient size before calling this function.
	 */
	int create_ap_mld_config_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a BSTA MLD configuration TLV.
	 *
	 * This function is responsible for creating a BSTA MLD (Basic Service Set Transition Management Link Discovery) configuration TLV (Type-Length-Value) structure and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is large enough to hold the TLV structure.
	 */
	int create_bsta_mld_config_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates an association station MLD configuration report TLV.
	 *
	 * This function generates a TLV (Type-Length-Value) report for the association
	 * station MLD (Multi-Link Device) configuration and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV report will be stored.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before calling this function.
	 */
	int create_assoc_sta_mld_config_report_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a TID to link map policy TLV.
	 *
	 * This function is responsible for creating a TID to link map policy TLV using the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be created.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	int create_tid_to_link_map_policy_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates an EHT operations TLV.
	 *
	 * This function generates an EHT (Extremely High Throughput) operations TLV (Type-Length-Value) and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns The length of the TLV created.
	 *
	 * @note Ensure that the buffer is large enough to hold the TLV data.
	 */
	virtual unsigned short create_eht_operations_tlv(unsigned char *buff) = 0;

	/**!
	 * @brief Creates an AP capability TLV.
	 *
	 * This function is responsible for creating an Access Point (AP) capability
	 * Type-Length-Value (TLV) structure and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns The length of the TLV on success, or -1 on failure
	 *
	 * @note Implemented by derived class
	 */
	virtual short create_ap_cap_tlv(unsigned char *buff) = 0;

	/**!
	 * @brief Creates a basic capability for the AP radio.
	 *
	 * This function initializes the basic capabilities of the AP radio and stores
	 * the result in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the basic capability data will be stored.
	 *
	 * @return The length of the TLV on success, or -1 on failure.
	 *
	 * @note Implemented by derived class
	 */
	virtual short create_ap_radio_basic_cap(unsigned char *buff) = 0;

	/**!
	 * @brief Creates a profile 2 TLV.
	 *
	 * This function is responsible for creating a profile 2 TLV (Type-Length-Value) structure
	 * and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @return The length of the TLV on success, or -1 on failure
	 *
	 * @note: Implemented by derived class
	 */
	virtual short create_prof_2_tlv(unsigned char *buff) = 0;

	/**!
	 * @brief Creates a HT TLV (Type-Length-Value) structure.
	 *
	 * This function initializes a HT TLV structure in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the HT TLV will be created.
	 *
	 * @return The size of the TLV created on success, or -1 on failure.
	 *
	 * @note Implemented by derived class
	 */
	virtual short create_ht_tlv(unsigned char *buff) = 0;

	/**!
	 * @brief Creates a VHT TLV (Very High Throughput Tag Length Value) structure.
	 *
	 * This function initializes a VHT TLV structure in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the VHT TLV will be created.
	 *
	 * @return The size of the TLV created on success, or -1 on failure.
	 *
	 * @note Implemented by derived class
	 */
	virtual short create_vht_tlv(unsigned char *buff) = 0;

	/**!
	 * @brief Creates a WiFi 6 TLV (Type-Length-Value) structure.
	 *
	 * This function is responsible for creating a WiFi 6 TLV structure and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 * @return Length of TLV created on success otherwise -1
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
	 * @return Length of TLV created on success otherwise -1
	 *
	 * @note Implemented by derived class
	 */
	virtual short create_wifi7_tlv(unsigned char *buff) = 0;

	/**
	 * @brief Create an AP Radio Advanced Capabilities TLV (EM 17.2.52)
	 * 
	 * @param buff The buffer to write the TLV to.
	 * @return short The length of the TLV on success, -1 on failure
	 * 
	 * @note Implemented by derived class
	 */
	virtual short create_ap_radio_advanced_cap_tlv(unsigned char *buff) = 0;

	/**!
	 * @brief Creates a list of enrollee BSTA.
	 *
	 * This function generates a cJSON object representing the list of enrollee BSTA
	 * based on the provided connection context.
	 *
	 * @param[in] pa_al_mac UNUSED
	 *
	 * @returns A pointer to a cJSON object representing the enrollee BSTA list.
	 *
	 * @note Ensure that the connection context is properly initialized before calling this function.
	 */
	virtual cJSON *create_enrollee_bsta_list(uint8_t pa_al_mac[ETH_ALEN]) = 0;


	virtual cJSON *create_bss_dpp_response_obj(const em_bss_info_t *bss_info, bool is_sta_response, bool tear_down_bss, dm_easy_mesh_t* data_model = NULL) = 0;
	
	/**!
	 * @brief Sends a topology response message.
	 *
	 * This function is responsible for sending a topology response message to the specified destination.
	 *
	 * @param[in] dst Pointer to the destination address where the message will be sent.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the destination address is valid before calling this function.
	 */
	int send_topology_response_msg(unsigned char *dst);
    
	/**!
	 * @brief Sends a topology notification by client.
	 *
	 * This function is responsible for sending a topology notification
	 * by the client using the provided MAC address, BSSID, and association status.
	 *
	 * @param[in] sta The MAC address of the station.
	 * @param[in] bssid The BSSID of the network.
	 * @param[in] assoc Boolean indicating association status.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the MAC address and BSSID are valid before calling this function.
	 */
	int send_topology_notification_by_client(mac_address_t sta, bssid_t bssid, bool assoc);
    
	/**!
	 * @brief Sends a BSTA MLD configuration request message.
	 *
	 * This function is responsible for sending a configuration request message
	 * to the BSTA MLD. The message is constructed and sent using the provided buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the message to be sent.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly initialized before calling this function.
	 */
	int send_bsta_mld_config_req_msg(unsigned char *buff);
    
	/**!
	 * @brief Sends a BSTA MLD configuration response message.
	 *
	 * This function is responsible for sending a configuration response message
	 * for the BSTA MLD (Multi-Link Device) using the provided buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the message to be sent.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly initialized before calling this function.
	 */
	int send_bsta_mld_config_resp_msg(unsigned char *buff);
    
	/**!
	 * @brief Sends a request message to configure AP MLD.
	 *
	 * This function is responsible for initiating the configuration request for AP MLD (Access Point Multi-Link Device).
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the system is properly initialized before calling this function.
	 */
	int send_ap_mld_config_req_msg();
    
	/**!
	 * @brief Sends the AP MLD configuration response message.
	 *
	 * This function is responsible for sending a configuration response message to the specified destination.
	 *
	 * @param[in] dst Pointer to the destination address where the message will be sent.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the destination address is valid and properly initialized before calling this function.
	 */
	int send_ap_mld_config_resp_msg(unsigned char *dst);
    
	/**!
	 * @brief Sends a 1905 acknowledgment message to a specified station.
	 *
	 * This function is responsible for sending an acknowledgment message
	 * to a station identified by its MAC address. It is part of the 1905
	 * protocol operations.
	 *
	 * @param[in] sta_mac The MAC address of the station to which the acknowledgment
	 * message is to be sent.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the MAC address is valid and the station is reachable
	 * before calling this function.
	 */
	int send_1905_ack_message(mac_addr_t sta_mac);
    
	

	/**!
	 * @brief Handles a BSS Configuration Request message and sends a Response to the source
	 * 
	 * EasyMesh 5.3.8 / EasyMesh 17.1.58
	 * 
	 * @param[in] buff Pointer to the buffer containing the BSS Configuration Request message.
	 * @param[in] len Length of the message in bytes.
	 * @param[in] src_al_mac Source AL MAC address of the sender.
	 * 
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 * @note Ensure that the buffer is properly allocated and contains a valid BSS Configuration Request message.
	 */
 	int handle_bss_config_req_msg(uint8_t *buff, unsigned int len, uint8_t src_al_mac[ETH_ALEN]);


	/**!
	 * @brief Handles a BSS Configuration Response message and sends a Result to the source
	 * 
	 * EasyMesh 5.3.8 / EasyMesh 17.1.58
	 * 
	 * @param[in] buff Pointer to the buffer containing the BSS Configuration Response message.
	 * @param[in] len Length of the message in bytes.
	 * @param[in] src_al_mac Source AL MAC address of the sender.
	 * 
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 * @note Ensure that the buffer is properly allocated and contains a valid BSS Configuration Response message.
	 */	
	int handle_bss_config_rsp_msg(uint8_t *buff, unsigned int len, uint8_t src_al_mac[ETH_ALEN]);


	/**!
	 * @brief Handles a BSS Configuration Result message and sends an Agent List to the source
	 * 
	 * EasyMesh 5.3.8 / EasyMesh 17.1.58
	 * 
	 * @param[in] buff Pointer to the buffer containing the BSS Configuration Result message.
	 * @param[in] len Length of the message in bytes.
	 * @param[in] src_al_mac Source AL MAC address of the sender.
	 * 
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 * @note Ensure that the buffer is properly allocated and contains a valid BSS Configuration Result message.
	 */
	int handle_bss_config_res_msg(uint8_t *buff, unsigned int len, uint8_t src_al_mac[ETH_ALEN]);

	/**!
	 * @brief Handles the Agent List message and processes it.
	 *
	 * EasyMesh 5.3.8 / EasyMesh 17.1.58
	 *
	 * @param[in] buff Pointer to the buffer containing the Agent List message.
	 * @param[in] len Length of the message in bytes.
	 * @param[in] src_al_mac Source AL MAC address of the sender.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated and contains a valid Agent List message.
	 */
	int handle_agent_list_msg(uint8_t *buff, unsigned int len, uint8_t src_al_mac[ETH_ALEN]);
	
	/**!
	 * @brief Handles the auto-configuration response.
	 *
	 * This function processes the response received for auto-configuration.
	 *
	 * @param[in] buff Pointer to the buffer containing the response data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_autoconfig_resp(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the autoconfiguration search process.
	 *
	 * This function processes the provided buffer to perform an autoconfiguration search.
	 *
	 * @param[in] buff Pointer to the buffer containing data for the search.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int Status code of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly initialized before calling this function.
	 */
	int handle_autoconfig_search(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the auto-configuration for WSC M1 message.
	 *
	 * This function processes the WSC M1 message contained in the buffer and performs
	 * necessary actions for auto-configuration.
	 *
	 * @param[in] buff Pointer to the buffer containing the WSC M1 message.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated and contains a valid WSC M1 message.
	 */
	int handle_autoconfig_wsc_m1(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the auto-configuration for WSC M2.
	 *
	 * This function processes the given buffer to handle the WSC M2 message.
	 *
	 * @param[in] buff Pointer to the buffer containing the WSC M2 message.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is properly allocated and the length is correct before calling this function.
	 */
	int handle_autoconfig_wsc_m2(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the WSC M1 message.
	 *
	 * This function processes the WSC (Wi-Fi Simple Configuration) M1 message.
	 *
	 * @param[in] buff Pointer to the buffer containing the WSC M1 message.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_wsc_m1(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the WSC M2 message.
	 *
	 * This function processes the WSC (Wi-Fi Simple Configuration) M2 message contained in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the WSC M2 message.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and contains a valid WSC M2 message before calling this function.
	 */
	int handle_wsc_m2(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the renewal of auto-configuration.
	 *
	 * This function processes the buffer to renew the auto-configuration settings.
	 *
	 * @param[in] buff Pointer to the buffer containing configuration data.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int Status code of the operation.
	 * @retval 0 Success.
	 * @retval -1 Failure.
	 *
	 * @note Ensure that the buffer is properly initialized before calling this function.
	 */
	int handle_autoconfig_renew(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the basic capabilities of the AP radio.
	 *
	 * This function processes the buffer containing the basic capabilities
	 * of the AP radio and performs necessary operations based on the data.
	 *
	 * @param[in] buff Pointer to the buffer containing the AP radio capabilities.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is properly initialized before calling this function.
	 */
	int handle_ap_radio_basic_cap(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the advanced capabilities of the AP radio.
	 *
	 * This function processes the advanced capabilities of the AP radio using the provided buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the data to be processed.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly initialized before calling this function.
	 */
	int handle_ap_radio_advanced_cap(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the topology response.
	 *
	 * This function processes the topology response received in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the topology response data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is properly allocated and the length is correct before calling this function.
	 */
	int handle_topology_response(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles topology notifications.
	 *
	 * This function processes the topology notification received in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the notification data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is properly allocated and the length is correct before calling this function.
	 */
	int handle_topology_notification(unsigned char *buff, unsigned int len);
	int handle_bsta_radio_cap(unsigned char *buff, unsigned int len);

	/**!
	 * @brief Handles the operational BSS for the access point.
	 *
	 * This function processes the buffer containing BSS information and performs
	 * necessary operations based on the data provided.
	 *
	 * @param[in] buff Pointer to the buffer containing BSS data.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly set
	 * before calling this function.
	 */
	int handle_ap_operational_bss(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the BSS configuration report.
	 *
	 * This function processes the BSS configuration report contained in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the BSS configuration report.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 Success.
	 * @retval -1 Failure due to invalid input.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_bss_configuration_report(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the MLD configuration request for BSTA.
	 *
	 * This function processes the MLD configuration request received in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the configuration request data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_bsta_mld_config_req(unsigned char *buff, unsigned int len);
    
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
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_ack_msg(unsigned char *buff, unsigned int len);
   

	/**!
	 * @brief Handles the BSS Configuration Request TLV.
	 *
	 * @param[in] tlv Pointer to the BSS Configuration Request TLV structure.
	 *
	 * @returns SSL_KEY* Pointer to the Enrollee Network Access Key (NAK) if successful, NULL on failure.
	 *
	 * @note Ensure the TLV is properly initialized before calling this function.
	 */
	SSL_KEY* handle_bss_config_req_tlv(em_tlv_t* tlv);
	
	/**!
	 * @brief Handles the BSS Configuration Response TLV.
	 *
	 * This function processes the BSS Configuration Response TLV including tearing down, and setting up 
	 * fronthaul and backhaul BSSs according to EasyMesh 5.3.8
	 *
	 * @param[in] tlv Pointer to the BSS Configuration Response TLV structure.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the TLV is properly initialized before calling this function.
	 */
	int handle_bss_config_rsp_tlv(em_tlv_t* tlv, m2ctrl_radioconfig& radioconfig, size_t bss_count);

	/**!
	 * @brief Handles the AP MLD configuration TLV.
	 *
	 * This function processes the AP MLD configuration TLV from the provided buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the TLV data.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is properly allocated and the length is correct before calling this function.
	 */
	int handle_ap_mld_config_tlv(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles EHT operations TLV.
	 *
	 * This function processes the EHT operations TLV from the provided buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the TLV data.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure the buffer is properly allocated and contains valid TLV data before calling this function.
	 */
	int handle_eht_operations_tlv(unsigned char *buff);
    
	/**!
	 * @brief Handles the Access Point MLD (Multi-Link Device) configuration request.
	 *
	 * This function processes the configuration request for the Access Point MLD.
	 *
	 * @param[in] buff Pointer to the buffer containing the configuration data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_ap_mld_config_req(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Handles the Access Point MLD (Multi-Link Device) configuration response.
	 *
	 * This function processes the response received for the AP MLD configuration.
	 *
	 * @param[in] buff Pointer to the buffer containing the response data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_ap_mld_config_resp(unsigned char *buff, unsigned int len);
	
	/**!
	 * @brief Handles the operational BSS for the AP vendor.
	 *
	 * This function processes the given value and length to manage the operational BSS.
	 *
	 * @param[in] value Pointer to the data representing the operational BSS.
	 * @param[in] len Length of the data pointed by value.
	 *
	 * @note Ensure that the value is not null and len is valid to avoid undefined behavior.
	 */
	void handle_ap_vendor_operational_bss(unsigned char *value, unsigned int len);

    
	/**!
	 * @brief Creates an M1 message.
	 *
	 * This function is responsible for creating an M1 message and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the M1 message will be stored.
	 *
	 * @returns The length of the created M1 message.
	 */
	unsigned short create_m1_msg(unsigned char *buff);
    
	/**!
	 * @brief Creates an M2 message based on the provided buffer and haul type.
	 *
	 * This function generates a message of type M2 using the given buffer and haul type.
	 *
	 * @param[in] buff Pointer to the buffer where the message will be created.
	 * @param[in] haul_type The type of haul for which the message is being created.
	 *
	 * @returns The length of the created message as an unsigned short.
	 *
	 * @note Ensure that the buffer is properly allocated and the haul type is valid before calling this function.
	 */
	unsigned short create_m2_msg(unsigned char *buff, em_haul_type_t haul_type);
    
	/**!
	 * @brief Creates a traffic separation policy.
	 *
	 * This function is responsible for creating a traffic separation policy using the provided buffer.
	 *
	 * @param[in] buff A pointer to an unsigned char buffer that contains the data required for creating the policy.
	 *
	 * @returns An unsigned short value indicating the result of the policy creation.
	 * @retval 0 on success.
	 * @retval non-zero error code on failure.
	 *
	 * @note Ensure that the buffer is properly initialized before calling this function.
	 */
	unsigned short create_traffic_separation_policy(unsigned char *buff);
    
	/**!
	 * @brief Creates an error code TLV.
	 *
	 * This function generates an error code TLV based on the provided buffer,
	 * value, and station MAC address.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 * @param[in] val Integer value representing the error code.
	 * @param[in] sta_mac MAC address of the station.
	 *
	 * @returns unsigned short The length of the created TLV.
	 *
	 * @note Ensure the buffer is sufficiently large to store the TLV.
	 */
	unsigned short create_error_code_tlv(unsigned char *buff, int val, mac_addr_t sta_mac);
  	
	/**!
	 * @brief Creates a vendor operational BSS TLV.
	 *
	 * This function is responsible for creating a vendor-specific operational
	 * BSS (Basic Service Set) TLV (Type-Length-Value) structure and storing
	 * it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before
	 * calling this function.
	 */
	int create_vendor_operational_bss_tlv(unsigned char *buff);

	/**
	 * @brief Creates a Backhaul STA Radio Capabilities TLV (17.2.65)
	 * 
	 * @param buff The buffer to write the TLV to.
	 * @return int The length of the TLV created, or -1 on failure.
	 */
	int create_bsta_radio_cap_tlv(uint8_t *buff);

	/**
	 * @brief Creates an AKM Suite Capabilities TLV (17.2.78)
	 * 
	 * @param buff The buffer to write the TLV to.
	 * @return int The length of the TLV created, or -1 on failure.
	 */
	int create_akm_suite_cap_tlv(uint8_t *buff);

	/**
	 * @brief Creates a BSS Configuration Response TLV (17.2.85)
	 * 
	 * @param buff The buffer to write the TLV to.
	 * @param bss_info Pointer to the `em_bss_info_t` struct containing the information about the BSS to create on the agent.
	 * @param dest_al_mac The destination AL MAC address (6 bytes).
	 * @return int The length of the TLV created, or -1 on failure.
	 */
	int create_bss_conf_resp_tlv(uint8_t *buff, em_bss_info_t *bss_info, uint8_t dest_al_mac[ETH_ALEN], dm_easy_mesh_t* dm, SSL_KEY* enrollee_nak);

	/**
	 * @brief Creates a BSS Configuration Request TLV (17.2.84)
	 * 
	 * @param buff The buffer to write the TLV to.
	 * @return int The length of the TLV created, or -1 on failure.
	 */
	int create_bss_conf_req_tlv(uint8_t *buff);

	/**
	 * @brief Creates an Agent List TLV (17.2.77) containing basic infomation about all agents in the network
	 * 
	 * @param buff The buffer to write the TLV to.
	 * @return int The length of the TLV created, or -1 on failure.
	 * 
	 * @note Make sure that the buffer is large enough to hold the TLV data.
	 */
	int create_agent_list_tlv(uint8_t *buff);

 
    // state handlers 
    
	/**!
	 * @brief Handles the state configuration when no specific configuration is set.
	 *
	 * This function is responsible for managing the default state configuration
	 * when no other configuration is applicable.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void handle_state_config_none();
    
	/**!
	 * @brief Handles the state when the auto-configuration response is pending.
	 *
	 * This function is responsible for managing the operations or transitions
	 * required when the system is in a state where it is awaiting a response
	 * for auto-configuration.
	 *
	 * @note Ensure that the system is prepared to handle the response once it arrives.
	 */
	void handle_state_autoconfig_rsp_pending();
    
	/**!
	 * @brief Handles the state when WSC M1 is pending.
	 *
	 * This function is responsible for managing the operations
	 * required when the WSC M1 state is pending.
	 *
	 * @note Ensure that the system is in the correct state before
	 * calling this function to avoid unexpected behavior.
	 */
	void handle_state_wsc_m1_pending();
    
	/**!
	 * @brief Handles the state when WSC M2 is pending.
	 *
	 * This function is responsible for managing the operations or transitions
	 * required when the WSC (Wi-Fi Simple Configuration) M2 message is in a
	 * pending state.
	 *
	 * @note Ensure that the system is in the correct state before invoking this
	 * function to avoid unexpected behavior.
	 */
	void handle_state_wsc_m2_pending();
    
	/**!
	 * @brief Handles the state topology notification.
	 *
	 * This function is responsible for processing notifications related to state topology changes.
	 *
	 * @note Ensure that the state topology is initialized before calling this function.
	 */
	void handle_state_topology_notify();
    
	/**!
	 * @brief Handles the state of auto-configuration renewal.
	 *
	 * This function is responsible for managing the transition and operations
	 * required during the auto-configuration renewal state.
	 *
	 * @note Ensure that the system is in the correct state before calling this function.
	 */
	void handle_state_autoconfig_renew();

    // helpers
    
	/**!
	 * @brief Fills the media data with the specified media specification.
	 *
	 * This function populates the provided media specification data structure
	 * with the necessary information.
	 *
	 * @param[out] spec Pointer to the media specification data structure to be filled.
	 *
	 * @note Ensure that the spec pointer is valid and points to a properly allocated
	 * em_media_spec_data_t structure before calling this function.
	 */
	void fill_media_data(em_media_spec_data_t *spec);

	
	/**!
	 * @brief Retrieves the manager instance.
	 *
	 * This function is a pure virtual function that must be implemented by the derived class.
	 *
	 * @returns A pointer to the em_mgr_t instance.
	 *
	 * @note This function does not take any parameters and returns a pointer to the manager.
	 */
	virtual em_mgr_t *get_mgr() = 0;
    
	/**!
	 * @brief Retrieves the EC Manager instance.
	 *
	 * This function is a pure virtual function that must be implemented by the derived class.
	 *
	 * @returns Reference to the EC Manager instance.
	 */
	virtual ec_manager_t& get_ec_mgr() = 0;
    
	/**!
	 * @brief Retrieves the data model instance.
	 *
	 * This function is a pure virtual function that must be implemented by the derived class.
	 *
	 * @returns A pointer to the data model instance of type dm_easy_mesh_t.
	 *
	 * @note The caller does not own the returned pointer and should not attempt to delete it.
	 */
	virtual dm_easy_mesh_t *get_data_model() = 0;
    
	/**!
	 * @brief Retrieves the current state.
	 *
	 * This function is a pure virtual function that must be implemented by the derived class.
	 *
	 * @returns The current state as an em_state_t.
	 */
	virtual em_state_t get_state() = 0;
    
	/**!
	 * @brief Sets the state of the entity.
	 *
	 * This function is responsible for updating the state of the entity to the specified value.
	 *
	 * @param[in] state The new state to be set. It must be a valid em_state_t value.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void set_state(em_state_t state) = 0;
    
	/**!
	 * @brief Retrieves the service type.
	 *
	 * This function is a pure virtual function that must be implemented by the derived class.
	 *
	 * @returns The service type as em_service_type_t.
	 */
	virtual em_service_type_t get_service_type() = 0;
    
	/**!
	 * @brief Retrieves the profile type.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns The profile type as an em_profile_type_t.
	 *
	 * @note This function does not take any parameters and returns the profile type directly.
	 */
	virtual em_profile_type_t get_profile_type() = 0;
    
	/**!
	 * @brief Sets the profile type.
	 *
	 * This function sets the profile type for the configuration.
	 *
	 * @param[in] profile The profile type to be set.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual void set_profile_type(em_profile_type_t profile) = 0;
    
	/**!
	 * @brief Retrieves the MAC address of the radio interface.
	 *
	 * This function returns the MAC address associated with the radio interface.
	 * This function is a pure virtual function that must be implemented by the derived class.
	 *
	 * @returns A pointer to an unsigned char array containing the MAC address.
	 *
	 * @note The caller is responsible for managing the memory of the returned MAC address.
	 */
	virtual unsigned char *get_radio_interface_mac() = 0;
    
	/**!
	 * @brief Retrieves the radio interface.
	 *
	 * This function is a pure virtual function that must be implemented by the derived class.
	 *
	 * @returns A pointer to the em_interface_t representing the radio interface.
	 *
	 * @note This function does not take any parameters and returns a non-null pointer.
	 */
	virtual em_interface_t *get_radio_interface() = 0;
    
	/**!
	 * @brief Retrieves the MAC address of the AL interface.
	 *
	 * This function returns the MAC address associated with the AL interface.
	 * This function is a pure virtual function that must be implemented by the derived class.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 *
	 * @note The returned MAC address is in a standard format and should be handled appropriately.
	 */
	virtual unsigned char *get_al_interface_mac() = 0;
    
	/**!
	 * @brief Retrieves the radio data for a specified interface.
	 *
	 * This function is responsible for obtaining the radio data associated with a given interface.
	 *
	 * @param[in] radio A pointer to the em_interface_t structure representing the radio interface.
	 *
	 * @returns A pointer to the rdk_wifi_radio_t structure containing the radio data.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual rdk_wifi_radio_t *get_radio_data(em_interface_t *radio) = 0;
    
	/**!
	 * @brief Retrieves the IEEE 1905 security capabilities.
	 *
	 * @returns A pointer to an em_ieee_1905_security_cap_t structure containing the security capabilities.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() = 0;
    
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
	 * @brief Retrieves the MAC address of the peer.
	 *
	 * This function returns the MAC address of the peer as an unsigned char pointer.
	 *
	 * @returns A pointer to an unsigned char array containing the MAC address.
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual unsigned char *get_peer_mac() = 0;
    
	/**!
	 * @brief Retrieves the cryptographic information.
	 *
	 * @returns A pointer to an em_crypto_info_t structure containing the cryptographic information.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual em_crypto_info_t *get_crypto_info() = 0;
    
	/**!
	 * @brief Retrieves the cryptographic object.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns A pointer to an em_crypto_t object.
	 * @note This function does not take any parameters and returns a pointer to a cryptographic object.
	 */
	virtual em_crypto_t *get_crypto() = 0;
    
	/**!
	 * @brief Sends a frame of data.
	 *
	 * This function is responsible for sending a frame of data with the option to multicast.
	 *
	 * @param[in] buff Pointer to the buffer containing the data to be sent.
	 * @param[in] len Length of the data in the buffer.
	 * @param[in] multicast Boolean flag indicating whether the data should be sent as multicast.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
	
	/**!
	 * @brief Pushes an event into the event manager.
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
	 * @brief Checks if the interface is an AL interface.
	 *
	 * This function determines whether the current interface is an AL (Application Layer) interface.
	 *
	 * @returns True if the interface is an AL interface, false otherwise.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual bool is_al_interface_em() = 0;
	
	/**!
	 * @brief Retrieves the radio instance from the device manager.
	 *
	 * This function returns a pointer to the radio instance associated with the device manager.
	 *
	 * @param[in] command_dm A boolean flag indicating whether to command the device manager.
	 *                       Defaults to false.
	 *
	 * @returns A pointer to the dm_radio_t instance.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_radio_t *get_radio_from_dm(bool command_dm = false) = 0;

    
	/**!
	 * @brief Retrieves the manufacturer information.
	 *
	 * @returns A pointer to a character array containing the manufacturer name.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual char *get_manufacturer() = 0;
    
	/**!
	 * @brief Retrieves the manufacturer model.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns A pointer to a character array containing the manufacturer model.
	 *
	 * @note The caller is responsible for managing the memory of the returned character array.
	 */
	virtual char *get_manufacturer_model() = 0;
    
	/**!
	 * @brief Retrieves the software version.
	 *
	 * This function returns the current version of the software as a string.
	 *
	 * @returns A pointer to a character array containing the software version.
	 *
	 * @note The returned string should not be modified or freed by the caller.
	 * @note This function is a pure virtual function and must be implemented by derived classes.
	 */
	virtual char *get_software_version() = 0;
    
	/**!
	 * @brief Retrieves the serial number.
	 *
	 * @returns A pointer to a character array containing the serial number.
	 *
	 * @note This function is pure virtual and must be implemented by derived classes.
	 */
	virtual char *get_serial_number() = 0;
    
	/**!
	 * @brief Retrieves the primary device type.
	 *
	 * This function returns a character pointer representing the primary device type.
	 *
	 * @returns A character pointer to the primary device type.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual char *get_primary_device_type() = 0;

    
	/**!
	 * @brief Sets the manufacturer name.
	 *
	 * This function assigns a manufacturer name to the configuration.
	 *
	 * @param[in] manufacturer A pointer to a character array containing the manufacturer name.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void set_manufacturer(char *) = 0;
    
	/**!
	 * @brief Sets the manufacturer model.
	 *
	 * This function assigns a manufacturer model to the device.
	 *
	 * @param[in] model A pointer to a character array representing the manufacturer model.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual void set_manufacturer_model(char *) = 0;
    
	/**!
	 * @brief Sets the software version.
	 *
	 * This function sets the software version using the provided character pointer.
	 *
	 * @param[in] version A character pointer to the software version string.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual void set_software_version(char *) = 0;
    
	/**!
	 * @brief Sets the serial number.
	 *
	 * This function assigns a serial number to the device.
	 *
	 * @param[in] serial_number A pointer to a character array containing the serial number.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual void set_serial_number(char *) = 0;
    
	/**!
	 * @brief Sets the primary device type.
	 *
	 * This function sets the primary device type using the provided character pointer.
	 *
	 * @param[in] device_type A character pointer representing the device type to be set.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void set_primary_device_type(char *) = 0;
    
	/**!
	 * @brief Retrieves the current frequency band.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns The current frequency band as an em_freq_band_t.
	 *
	 * @note This function does not take any parameters and returns the frequency band directly.
	 */
	virtual em_freq_band_t get_band() = 0;
    
	/**!
	 * @brief Sets the frequency band for the configuration.
	 *
	 * This function sets the specified frequency band for the configuration.
	 *
	 * @param[in] band The frequency band to be set. It is of type em_freq_band_t.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual void set_band(em_freq_band_t band) = 0;
    
	/**!
	 * @brief Retrieves the network SSID information based on the specified haul type.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @param[in] haul_type The type of haul for which the SSID information is requested.
	 *
	 * @returns A pointer to an em_network_ssid_info_t structure containing the SSID information.
	 *
	 * @note The caller is responsible for managing the memory of the returned pointer.
	 */
	virtual em_network_ssid_info_t *get_network_ssid_info_by_haul_type(em_haul_type_t haul_type) = 0;

private:
    em_profile_type_t   m_peer_profile;
    unsigned char m_m1_msg[MAX_EM_BUFF_SZ*EM_MAX_BANDS];
    unsigned char m_m2_msg[MAX_EM_BUFF_SZ*EM_MAX_BANDS];
    size_t m_m1_length;
    size_t m_m2_length;

    unsigned char m_m2_authenticator[SHA256_MAC_LEN];
    unsigned int m_m2_authenticator_len;
    unsigned char m_m2_encrypted_settings[MAX_EM_BUFF_SZ];
    unsigned int m_m2_encrypted_settings_len;

public:

	bool send_autoconf_search_ext_chirp(em_dpp_chirp_value_t *chirp, size_t hash_len);

	bool send_autoconf_search_resp_ext_chirp(em_dpp_chirp_value_t *chirp, size_t len, uint8_t dest_mac[ETH_ALEN]);

	bool send_bss_config_req_msg(uint8_t dest_al_mac[ETH_ALEN]);
    
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
	void process_msg(unsigned char *data, unsigned int len);	
    
	/**!
	 * @brief Processes the current state of the agent.
	 *
	 * This function is responsible for handling the logic associated with the agent's state.
	 *
	 * @note Ensure that the agent is initialized before calling this function.
	 */
	void process_agent_state();
    
	/**!
	 * @brief Processes the control state.
	 *
	 * This function is responsible for handling the current state of the control system.
	 *
	 * @note Ensure that the control system is initialized before calling this function.
	 */
	void process_ctrl_state();
    
	/**!
	 * @brief Retrieves the WSC message type from the provided buffer.
	 *
	 * This function analyzes the given buffer to determine the type of WSC message it contains.
	 *
	 * @param[in] buff Pointer to the buffer containing the WSC message.
	 * @param[in] len Length of the buffer.
	 *
	 * @returns The type of WSC message contained in the buffer.
	 * @retval em_wsc_msg_type_t Enum value representing the WSC message type.
	 *
	 * @note Ensure that the buffer is properly initialized and contains a valid WSC message.
	 */
	static em_wsc_msg_type_t get_wsc_msg_type(unsigned char *buff, unsigned int len);

    
	/**!
	* @brief Sends a topology query message.
	*
	* This function is responsible for initiating a query to gather topology information.
	*
	* @returns int
	* @retval 0 on success
	* @retval -1 on failure
	*
	* @note Ensure that the system is initialized before calling this function.
	*/
	int send_topology_query_msg();
    
	/**!
	 * @brief Sends an auto-configuration renewal message.
	 *
	 * This function is responsible for sending a renewal message for auto-configuration.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the network interface is up before calling this function.
	 */
	int send_autoconfig_renew_msg();
    
	/**!
	 * @brief Handles encrypted settings.
	 *
	 * This function is responsible for managing the encrypted settings
	 * within the application. It ensures that all settings are properly
	 * encrypted and decrypted as needed.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the encryption keys are properly initialized
	 * before calling this function.
	 */
	int handle_encrypted_settings();
    
	/**!
	 * @brief Creates encrypted settings based on the provided buffer and haul type.
	 *
	 * This function takes a buffer and a haul type as input and generates encrypted settings.
	 *
	 * @param[out] buff Pointer to the buffer where the encrypted settings will be stored.
	 * @param[in] haul_type The type of haul to be used for encryption.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	int create_encrypted_settings(unsigned char *buff, em_haul_type_t haul_type);
    
	/**!
	 * @brief Creates an authenticator using the provided buffer.
	 *
	 * This function initializes an authenticator with the data contained in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing data for the authenticator.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 Success.
	 * @retval -1 Failure due to invalid buffer.
	 *
	 * @note Ensure the buffer is properly initialized before calling this function.
	 */
	int create_authenticator(unsigned char *buff);

    
	/**!
	 * @brief Retrieves the UUID.
	 *
	 * This function fetches the UUID using the m_crypto object.
	 *
	 * @param[out] uuid Pointer to a buffer where the UUID will be stored.
	 *
	 * @returns The status of the operation as an unsigned integer.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the uuid buffer is properly allocated before calling this function.
	 */
	unsigned int get_e_uuid(unsigned char *uuid) { return m_crypto.get_e_uuid(uuid); }
    
	/**!
	 * @brief Retrieves the random UUID.
	 *
	 * This function calls the m_crypto.get_r_uuid function to obtain a random UUID.
	 *
	 * @param[out] uuid Pointer to a buffer where the UUID will be stored.
	 *
	 * @returns The status of the UUID retrieval operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the uuid buffer is large enough to hold the UUID.
	 */
	unsigned int get_r_uuid(unsigned char *uuid) { return m_crypto.get_r_uuid(uuid); }
    
	/**!
	 * @brief Retrieves the e_nonce value.
	 *
	 * This function fetches the e_nonce value using the provided nonce pointer.
	 *
	 * @param[out] nonce Pointer to the buffer where the e_nonce will be stored.
	 *
	 * @returns The e_nonce value as an unsigned integer.
	 *
	 * @note Ensure that the nonce buffer is properly allocated before calling this function.
	 */
	unsigned int get_e_nonce(unsigned char *nonce) { return m_crypto.get_e_nonce(nonce); }
    
	/**!
	 * @brief Retrieves the random nonce value.
	 *
	 * This function fetches the random nonce value and stores it in the provided buffer.
	 *
	 * @param[out] nonce Pointer to a buffer where the nonce will be stored.
	 *
	 * @returns The status of the operation as an unsigned integer.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the buffer pointed to by nonce is large enough to hold the nonce value.
	 */
	unsigned int get_r_nonce(unsigned char *nonce) { return m_crypto.get_r_nonce(nonce); }

    
	/**!
	 * @brief Retrieves the e_nonce value.
	 *
	 * @returns A pointer to the e_nonce value.
	 */
	unsigned char *get_e_nonce() { return m_crypto.get_e_nonce(); }
    
	/**!
	 * @brief Retrieves the R nonce value.
	 *
	 * This function returns a pointer to the R nonce value used in the cryptographic operations.
	 *
	 * @returns A pointer to the R nonce value.
	 *
	 * @note Ensure that the returned pointer is handled appropriately to avoid memory issues.
	 */
	unsigned char *get_r_nonce() { return m_crypto.get_r_nonce(); }
    
    
	/**!
	 * @brief Sets the E-UUID.
	 *
	 * This function assigns a unique identifier to the crypto module.
	 *
	 * @param[in] uuid Pointer to the UUID array.
	 * @param[in] len Length of the UUID array.
	 *
	 * @note Ensure that the UUID array is properly initialized before calling this function.
	 */
	void set_e_uuid(unsigned char *uuid, unsigned int len) { m_crypto.set_e_uuid(uuid, len); }
    
	/**!
	 * @brief Sets the UUID for the cryptographic module.
	 *
	 * This function assigns a UUID to the cryptographic module using the provided
	 * UUID and its length.
	 *
	 * @param[in] uuid Pointer to the UUID data.
	 * @param[in] len Length of the UUID data.
	 *
	 * @note Ensure that the UUID is valid and the length is correct before calling
	 * this function.
	 */
	void set_r_uuid(unsigned char *uuid, unsigned int len) { m_crypto.set_r_uuid(uuid, len); }
    
	/**!
	 * @brief Sets the encryption nonce.
	 *
	 * This function sets the encryption nonce using the provided nonce and length.
	 *
	 * @param[in] nonce Pointer to the nonce data.
	 * @param[in] len Length of the nonce data.
	 *
	 * @note This function directly interacts with the m_crypto object to set the nonce.
	 */
	void set_e_nonce(unsigned char *nonce, unsigned int len) { m_crypto.set_e_nonce(nonce, len); }
    
	/**!
	 * @brief Sets the R nonce value for cryptographic operations.
	 *
	 * This function assigns a nonce value to be used in cryptographic
	 * operations, ensuring that each operation is unique and secure.
	 *
	 * @param[in] nonce Pointer to the nonce value to be set.
	 * @param[in] len Length of the nonce value.
	 *
	 * @note Ensure that the nonce is unique for each operation to
	 * maintain security.
	 */
	void set_r_nonce(unsigned char *nonce, unsigned int len) { m_crypto.set_r_nonce(nonce, len); }	

    
	/**!
	 * @brief Retrieves the public encryption key.
	 *
	 * This function returns a pointer to the public encryption key used in the cryptographic operations.
	 *
	 * @returns A pointer to an unsigned char array representing the public encryption key.
	 *
	 * @note Ensure that the returned pointer is handled appropriately to avoid memory leaks or unauthorized access.
	 */
	unsigned char *get_e_public() { return m_crypto.get_e_public(); }
    
	/**!
	 * @brief Retrieves the length of the public exponent.
	 *
	 * @returns The length of the public exponent as an unsigned integer.
	 */
	unsigned int get_e_public_len() { return m_crypto.get_e_public_len(); }
    
	/**!
	 * @brief Retrieves the private encryption key.
	 *
	 * This function returns a pointer to the private encryption key used in the cryptographic operations.
	 *
	 * @returns A pointer to the private encryption key.
	 *
	 * @note Ensure that the returned pointer is handled securely to prevent unauthorized access to the private key.
	 */
	unsigned char *get_e_private() { return m_crypto.get_e_private(); }
    
	/**!
	 * @brief Retrieves the length of the private key.
	 *
	 * @returns The length of the private key as an unsigned integer.
	 */
	unsigned int get_e_private_len() { return m_crypto.get_e_private_len(); }
    
	/**!
	 * @brief Retrieves the public key.
	 *
	 * This function returns the public key from the cryptographic module.
	 *
	 * @returns A pointer to an unsigned char representing the public key.
	 *
	 * @note Ensure that the cryptographic module is properly initialized before calling this function.
	 */
	unsigned char *get_r_public() { return m_crypto.get_r_public(); }
    
	/**!
	 * @brief Retrieves the length of the public key.
	 *
	 * This function returns the length of the public key used in the cryptographic operations.
	 *
	 * @returns The length of the public key as an unsigned integer.
	 */
	unsigned int get_r_public_len() { return m_crypto.get_r_public_len(); }
    
	/**!
	 * @brief Retrieves the private key used in the cryptographic operations.
	 *
	 * This function returns a pointer to the private key used internally by the
	 * cryptographic module. The caller should ensure that the key is handled
	 * securely and not exposed to unauthorized entities.
	 *
	 * @returns A pointer to an unsigned char array representing the private key.
	 *
	 * @note The returned pointer is managed internally and should not be freed
	 * by the caller.
	 */
	unsigned char *get_r_private() { return m_crypto.get_r_private(); }
    
	/**!
	 * @brief Retrieves the length of the private key.
	 *
	 * This function calls the `get_r_private_len` method from the `m_crypto` object to obtain the length of the private key.
	 *
	 * @returns The length of the private key as an unsigned integer.
	 */
	unsigned int get_r_private_len() { return m_crypto.get_r_private_len(); }

    
	/**!
	 * @brief Sets the public key for encryption.
	 *
	 * This function assigns the provided public key to the encryption module.
	 *
	 * @param[in] pub Pointer to the public key data.
	 * @param[in] len Length of the public key data.
	 *
	 * @note Ensure that the public key data is valid and the length is correctly specified.
	 */
	void set_e_public(unsigned char *pub, unsigned int len) { m_crypto.set_e_public(pub, len); }
    
	/**!
	 * @brief Sets the public key.
	 *
	 * This function sets the public key using the provided byte array and its length.
	 *
	 * @param[in] pub Pointer to the byte array containing the public key.
	 * @param[in] len Length of the public key byte array.
	 *
	 * @note Ensure that the byte array is properly initialized and the length is correct.
	 */
	void set_r_public(unsigned char *pub, unsigned int len) { m_crypto.set_r_public(pub, len); }

    
	/**!
	 * @brief Retrieves the encrypted MAC address.
	 *
	 * This function returns the encrypted MAC address by calling the
	 * `get_e_mac` method from the `m_crypto` object.
	 *
	 * @returns A pointer to an unsigned char representing the encrypted MAC address.
	 */
	unsigned char *get_e_mac() { return m_crypto.get_e_mac(); }
    
	/**!
	 * @brief Retrieves the R-MAC value.
	 *
	 * This function returns the R-MAC value from the crypto module.
	 *
	 * @returns A pointer to an unsigned char representing the R-MAC value.
	 *
	 * @note Ensure that the returned pointer is handled appropriately to avoid memory issues.
	 */
	unsigned char *get_r_mac() { return m_crypto.get_r_mac(); }

    
	/**!
	 * @brief Sets the E-MAC address.
	 *
	 * This function sets the E-MAC address using the provided MAC address.
	 *
	 * @param[in] mac Pointer to the MAC address to be set.
	 *
	 * @note Ensure that the MAC address is valid and properly formatted.
	 */
	void set_e_mac(unsigned char *mac) { m_crypto.set_e_mac(mac); }
    
	/**!
	 * @brief Sets the R MAC address.
	 *
	 * This function sets the R MAC address using the provided MAC address.
	 *
	 * @param[in] mac Pointer to the MAC address to be set.
	 *
	 * @note Ensure that the MAC address is valid and properly formatted before calling this function.
	 */
	void set_r_mac(unsigned char *mac) { m_crypto.set_r_mac(mac); }

    
	/**!
	 * @brief Computes a shared secret using the provided public and private keys.
	 *
	 * This function utilizes the platform-specific method to compute a shared secret.
	 *
	 * @param[out] secret Pointer to the buffer where the computed secret will be stored.
	 * @param[out] secret_len Pointer to the length of the computed secret.
	 * @param[in] remote_pub Pointer to the remote public key.
	 * @param[in] pub_len Length of the remote public key.
	 * @param[in] local_priv Pointer to the local private key.
	 * @param[in] priv_len Length of the local private key.
	 *
	 * @returns int Status code of the computation.
	 *
	 * @note Ensure that the buffers provided are adequately sized to hold the computed secret.
	 */
	int compute_secret(unsigned char **secret, unsigned short *secret_len, 
        unsigned char *remote_pub, unsigned short pub_len, 
        unsigned char *local_priv, unsigned short priv_len) { 
            return em_crypto_t::platform_compute_shared_secret(secret, secret_len, remote_pub, pub_len, local_priv, static_cast<uint8_t>(priv_len));
    }

    
	/**!
	 * @brief Computes the SHA256 digest for the given input.
	 *
	 * This function takes a number, an address, and a length to compute the SHA256 digest.
	 *
	 * @param[in] num The number of elements to process.
	 * @param[in] addr Pointer to the address of the data.
	 * @param[in,out] len Pointer to the size of the data.
	 * @param[out] digest Pointer to the buffer where the computed digest will be stored.
	 *
	 * @returns int Status code of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the digest buffer is properly allocated before calling this function.
	 */
	int compute_digest(unsigned char num, unsigned char **addr, size_t *len, unsigned char *digest) {
        return em_crypto_t::platform_SHA256(num, addr, len, digest); 
    }

    int compute_kdk(unsigned char *key, size_t keylen, 
        unsigned char num_elem, unsigned char **addr, 
        size_t *len, unsigned char *hmac) {
            return em_crypto_t::platform_hmac_SHA256(key, keylen, num_elem, addr, len, hmac);
    }

    
	/**!
	 * @brief Derives a key using the specified label and prefix.
	 *
	 * This function performs a key derivation operation using the provided key, label prefix, and label.
	 *
	 * @param[in] key The base key used for derivation.
	 * @param[in] label_prefix The prefix to be used with the label.
	 * @param[in] label_prefix_len The length of the label prefix.
	 * @param[in] label The label used in the derivation process.
	 * @param[out] res The buffer where the derived key will be stored.
	 * @param[in] res_len The length of the result buffer.
	 *
	 * @returns int Status of the key derivation operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the result buffer is large enough to hold the derived key.
	 */
	int derive_key(unsigned char *key, unsigned char *label_prefix, size_t label_prefix_len, 
        char *label, unsigned char *res, unsigned int res_len) {
            return em_crypto_t::wps_key_derivation_function(key, label_prefix, label_prefix_len, label, res, res_len);
    }

    
	/**!
	 * @brief Computes cryptographic keys based on provided public and private keys.
	 *
	 * This function takes a remote public key and a local private key to compute
	 * the necessary cryptographic keys for secure communication.
	 *
	 * @param[in] remote_pub Pointer to the remote public key.
	 * @param[in] pub_len Length of the remote public key.
	 * @param[in] local_priv Pointer to the local private key.
	 * @param[in] priv_len Length of the local private key.
	 *
	 * @returns int Status code indicating success or failure of the key computation.
	 * @retval 0 Success
	 * @retval -1 Failure due to invalid input parameters
	 *
	 * @note Ensure that the provided keys are valid and properly formatted before
	 * calling this function.
	 */
	int compute_keys(unsigned char *remote_pub, unsigned short pub_len, unsigned char *local_priv, unsigned short priv_len);

    //void test_topology_response_msg() { send_topology_response_msg(); }
    
	/**!
	 * @brief Prints the operational BSS TLV.
	 *
	 * This function processes and prints the operational BSS TLV from the given value.
	 *
	 * @param[in] value Pointer to the unsigned char array containing the TLV data.
	 * @param[in] len Length of the TLV data.
	 *
	 * @note Ensure that the value pointer is valid and the length is correct to avoid undefined behavior.
	 */
	void print_ap_operational_bss_tlv(unsigned char *value, unsigned int len);
	
	/**!
	 * @brief Prints the BSS configuration report TLV.
	 *
	 * This function processes the given value and length to output the BSS configuration report.
	 *
	 * @param[in] value Pointer to the unsigned char array containing the TLV data.
	 * @param[in] len The length of the TLV data.
	 *
	 * @note Ensure that the value pointer is valid and the length is correct to avoid undefined behavior.
	 */
	void print_bss_configuration_report_tlv(unsigned char *value, unsigned int len);
	
	/**!
	 * @brief Print the AP vendor operational BSS TLV.
	 *
	 * This function processes and prints the Access Point (AP) vendor-specific
	 * operational Basic Service Set (BSS) TLV (Type-Length-Value) data.
	 *
	 * @param[in] value Pointer to the unsigned char array containing the TLV data.
	 * @param[in] len The length of the TLV data array.
	 *
	 * @note Ensure that the `value` pointer is valid and that `len` accurately
	 * represents the size of the data to avoid undefined behavior.
	 */
	void print_ap_vendor_operational_bss_tlv(unsigned char *value, unsigned int len);
    
	/**!
	 * @brief Retrieves the count of renew transactions.
	 *
	 * This function returns the current count of renew transactions by casting
	 * the member variable `m_renew_tx_cnt` to an integer.
	 *
	 * @returns The count of renew transactions as an integer.
	 */
	int get_renew_tx_count() { return static_cast<int>(m_renew_tx_cnt); }
    
	/**!
	 * @brief Sets the renew transaction count.
	 *
	 * This function assigns the provided count to the member variable
	 * responsible for tracking the number of renew transactions.
	 *
	 * @param[in] cnt The count to set for renew transactions.
	 */
	void set_renew_tx_count(unsigned int cnt) { m_renew_tx_cnt = cnt; }
    
	/**!
	 * @brief Retrieves the topology query transaction count.
	 *
	 * This function returns the number of topology query transactions.
	 *
	 * @returns The number of topology query transactions as an integer.
	 */
	int get_topo_query_tx_count() { return static_cast<int>(m_topo_query_tx_cnt); }
    
	/**!
	 * @brief Sets the topology query transmission count.
	 *
	 * This function assigns the provided count to the member variable
	 * responsible for tracking the number of topology query transmissions.
	 *
	 * @param[in] cnt The count to set for topology query transmissions.
	 *
	 * @note Ensure that the count is a valid unsigned integer.
	 */
	void set_topo_query_tx_count(unsigned int cnt) { m_topo_query_tx_cnt = cnt; }

	virtual bool get_is_dpp_onboarding() = 0;

	virtual void set_is_dpp_onboarding(bool is_onboarding) = 0;

    static unsigned short msg_id;

    em_crypto_t m_crypto;
    unsigned char m_auth_key[WPS_AUTHKEY_LEN];
    unsigned char m_key_wrap_key[WPS_KEYWRAPKEY_LEN];
    unsigned char m_emsk[WPS_EMSK_LEN];
    unsigned int m_renew_tx_cnt;
    unsigned int m_topo_query_tx_cnt;

    
	/**!
	 * @brief Constructor for em_configuration_t.
	 *
	 * Initializes the em_configuration_t object.
	 *
	 * @note This constructor does not take any parameters.
	 */
	em_configuration_t();
    
	/**!
	 * @brief Destructor for the em_configuration_t class.
	 *
	 * This function cleans up any resources used by the em_configuration_t instance.
	 *
	 * @note This is a virtual destructor, allowing for proper cleanup of derived class objects.
	 */
	virtual ~em_configuration_t();

};

#endif

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

#ifndef DM_EM_H
#define DM_EM_H
#include <vector>
#include "em_base.h"
#include "wifi_webconfig.h"
#include "dm_device.h"
#include "dm_network.h"
#include "dm_ieee_1905_security.h"
#include "dm_network_ssid.h"
#include "dm_radio.h"
#include "dm_bss.h"
#include "dm_sta.h"
#include "dm_dpp.h"
#include "dm_op_class.h"
#include "dm_policy.h"
#include "dm_scan_result.h"
#include "dm_csi_container.h"
#include "dm_radio_cap.h"
#include "dm_cac_comp.h"
#include "dm_ap_mld.h"
#include "dm_bsta_mld.h"
#include "dm_assoc_sta_mld.h"
#include "dm_tid_to_link.h"
#include "webconfig_external_proto.h"

#define GLOBAL_NET_ID "OneWifiMesh"

class em_t;

class dm_easy_mesh_t {
public:
    webconfig_subdoc_data_t *m_wifi_data;
	unsigned int m_num_preferences;
	em_interface_preference_t	m_preference[EM_MAX_PLATFORMS];
	unsigned int	m_num_interfaces;
	em_interface_t	m_interfaces[EM_MAX_INTERFACES];
    dm_network_t    m_network;
    dm_device_t     m_device;
    dm_ieee_1905_security_t m_ieee_1905_security;
    unsigned int	m_num_net_ssids;
    dm_network_ssid_t   m_network_ssid[EM_MAX_NET_SSIDS];
    unsigned int    m_num_radios;
    dm_radio_t  m_radio[EM_MAX_BANDS];
    dm_radio_cap_t     m_radio_cap[EM_MAX_BANDS];
    unsigned int    m_num_bss;    
    dm_bss_t    m_bss[EM_MAX_BSSS];
    dm_dpp_t        m_dpp;
    em_cmd_ctx_t    m_cmd_ctx;
    unsigned int 	m_num_opclass;    
    dm_op_class_t m_op_class[EM_MAX_OPCLASS];
	unsigned int	m_num_policy;
	dm_policy_t	m_policy[EM_MAX_POLICIES];
    uint32_t           m_num_csi_containers;
    dm_csi_container_t m_csi_containers[EM_MAX_CSI_CONTAINERS];
	hash_map_t		*m_scan_result_map = NULL;
    hash_map_t  	*m_sta_map = NULL;
    hash_map_t      *m_sta_assoc_map = NULL;
    hash_map_t      *m_sta_dassoc_map = NULL;
    dm_cac_comp_t	m_cac_comp;
    unsigned short           msg_id;
    em_db_cfg_param_t	m_db_cfg_param;
    em_t *m_em;
    bool    m_colocated;
    unsigned int    m_num_ap_mld;
    dm_ap_mld_t     m_ap_mld[EM_MAX_AP_MLD];
    unsigned int    m_num_bsta_mld;
    dm_bsta_mld_t   m_bsta_mld[EM_MAX_BSTA_MLD];
    unsigned int    m_num_assoc_sta_mld;
    dm_assoc_sta_mld_t m_assoc_sta_mld[EM_MAX_ASSOC_STA_MLD];
    dm_tid_to_link_t m_tid_to_link;

public:
	static em_e4_table_t m_e4_table[];
	
	/**!
	 * @brief Retrieves the frequency band associated with a given operating class.
	 *
	 * This function takes an operating class as input and returns the corresponding
	 * frequency band. It is used to map operating classes to their respective
	 * frequency bands in the EasyMesh framework.
	 *
	 * @param[in] op_class The operating class for which the frequency band is required.
	 *
	 * @returns The frequency band corresponding to the provided operating class.
	 *
	 * @note Ensure that the provided operating class is valid and supported by the
	 * EasyMesh framework to avoid unexpected results.
	 */
	static em_freq_band_t get_freq_band_by_op_class(int op_class);

	/**!
	 * @brief Retrieves the list of channel associated with a given operating class.
	 *
	 * This function takes an operating class as input and returns the corresponding
	 * channel list. It is used to map operating classes to their respective
	 * channels in the EasyMesh framework.
	 *
	 * @param[in] op_class The operating class for which the frequency band is required.
	 *
	 * @returns The list of channels corresponding to the provided operating class.
	 *
	 * @note Ensure that the provided operating class is valid and supported by the
	 * EasyMesh framework to avoid unexpected results.
	 */
	static std::vector<int> get_channel_list_by_op_class(int op_class);

	/**!
	 * @brief Retrieves the operating class information for a given BSS with an optional check for integer operating class.
	 *
	 * This function searches for the operating class information associated with the
	 * specified BSS (Basic Service Set) identified by its MAC address.
	 *
	 * @param[in] bssid The MAC address of the BSS for which the operating class information is requested.
	 * @param[in] op_class Optional check for integer operating class (used to filter results). Can be NULL.
	 *
	 * @returns The pointer to the `em_op_class_info_t` structure containing the operating class information.
	 * NULL if no matching BSS is found or if the operating class does not match.
	 */
	em_op_class_info_t* get_opclass_info_for_bss(mac_address_t bssid, unsigned int* op_class = NULL);
	
	/**!
	 * @brief Retrieves the BSS information associated with a given MAC address.
	 *
	 * This function searches for and returns the BSS (Basic Service Set) information
	 * corresponding to the specified MAC address.
	 *
	 * @param[in] mac The MAC address for which the BSS information is requested.
	 *
	 * @returns A pointer to the em_bss_info_t structure containing the BSS information.
	 * @retval NULL if the BSS information is not found for the given MAC address.
	 *
	 * @note Ensure that the MAC address provided is valid and corresponds to a known BSS.
	 */
	em_bss_info_t *get_bss_info_with_mac(mac_address_t mac);
	
	/**!
	 * @brief Retrieves the BSS information associated with a given MAC address.
	 *
	 * This function searches for and returns the BSS (Basic Service Set) information
	 * corresponding to the specified MAC address within the EasyMesh domain.
	 *
	 * @param[in] dm Pointer to the EasyMesh domain object.
	 * @param[in] mac The MAC address for which the BSS information is requested.
	 *
	 * @returns Pointer to the BSS information structure associated with the given MAC address.
	 * @retval nullptr If no BSS information is found for the specified MAC address.
	 *
	 * @note Ensure that the `dm` pointer is valid and properly initialized before calling this function.
	 */
	static em_bss_info_t *get_bss_info_with_mac(void *dm, mac_address_t mac) { return (static_cast<dm_easy_mesh_t *>(dm))->get_bss_info_with_mac(mac); }
    
	/**!
	 * @brief Analyzes device initialization.
	 *
	 * This function processes the initialization event and command for a device.
	 *
	 * @param[in] evt Pointer to the bus event structure.
	 * @param[in] pcmd Array of pointers to command structures.
	 *
	 * @returns int Status code indicating the result of the analysis.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	virtual int analyze_dev_init(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    
	/**!
	 * @brief Analyzes the radio configuration based on the provided event and command.
	 *
	 * This function processes the radio configuration using the event data and command array.
	 *
	 * @param[in] evt Pointer to the event structure containing radio configuration data.
	 * @param[in] pcmd Array of pointers to command structures for processing.
	 *
	 * @returns int Status code indicating the success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_radio_config(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    
	/**!
	 * @brief Analyzes the VAP configuration based on the provided event and command.
	 *
	 * This function processes the VAP configuration using the event and command data
	 * provided in the parameters.
	 *
	 * @param[in] evt Pointer to the event structure containing event data.
	 * @param[in] pcmd Array of pointers to command structures for processing.
	 *
	 * @returns int Status code indicating the result of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized
	 * before calling this function.
	 */
	int analyze_vap_config(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    
	/**!
	 * @brief Analyzes the station list from the given event and command.
	 *
	 * This function processes the station list contained within the event and command
	 * structures, performing necessary analysis and operations.
	 *
	 * @param[in] evt Pointer to the event structure containing station list data.
	 * @param[in] pcmd Array of pointers to command structures for processing.
	 *
	 * @returns int Status code indicating success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized
	 * before calling this function.
	 */
	int analyze_sta_list(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    
	/**!
	 * @brief Analyzes the access point capability query.
	 *
	 * This function processes the event and command data to analyze the capabilities of the access point.
	 *
	 * @param[in] evt Pointer to the event structure containing the access point capability query.
	 * @param[out] pcmd Array of pointers to command structures where the results of the analysis will be stored.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_ap_cap_query(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    
	/**!
	 * @brief Analyzes the client capability query.
	 *
	 * This function processes the client capability query event and command.
	 *
	 * @param[in] evt Pointer to the event structure containing client capability query details.
	 * @param[out] pcmd Array of pointers to command structures to be populated based on the query analysis.
	 *
	 * @returns int Status code indicating the success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_client_cap_query(em_bus_event_t *evt, em_cmd_t *pcmd[]);

    
	/**!
	 * @brief Decodes the configuration for the specified sub-document.
	 *
	 * This function processes the configuration data for a given sub-document
	 * identified by the key and index, and optionally returns the number of
	 * processed items.
	 *
	 * @param[in] subdoc Pointer to the sub-document information structure.
	 * @param[in] key The key identifying the configuration to decode.
	 * @param[in] index The index of the configuration item to decode (default is 0).
	 * @param[out] num Optional pointer to store the number of processed items.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 *
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the subdoc pointer is valid and points to a properly
	 * initialized em_subdoc_info_t structure before calling this function.
	 */
	int decode_config(em_subdoc_info_t *subdoc, const char *key, unsigned int index = 0, unsigned int *num = NULL);
    
	/**!
	 * @brief Decodes the configuration reset for the given subdocument and key.
	 *
	 * This function processes the configuration reset operation by decoding the
	 * provided subdocument information and key.
	 *
	 * @param[in] subdoc Pointer to the subdocument information structure.
	 * @param[in] key The key associated with the configuration reset.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the subdoc and key are valid before calling this function.
	 */
	int decode_config_reset(em_subdoc_info_t *subdoc, const char *key);
    
	/**!
	 * @brief Decodes the configuration test for the given subdocument and key.
	 *
	 * This function processes the provided subdocument information and key to decode
	 * the configuration test. It is used to extract and interpret the configuration
	 * settings from the subdocument.
	 *
	 * @param[in] subdoc Pointer to the subdocument information structure.
	 * @param[in] key The key associated with the configuration to be decoded.
	 *
	 * @returns int Status code indicating success or failure of the decoding process.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the subdoc and key are valid and properly initialized before
	 * calling this function.
	 */
	int decode_config_test(em_subdoc_info_t *subdoc, const char *key);
    
	/**!
	 * @brief Decodes the configuration to set the SSID.
	 *
	 * This function processes the given sub-document information and key to
	 * decode and set the SSID configuration.
	 *
	 * @param[in] subdoc Pointer to the sub-document information structure.
	 * @param[in] key The key associated with the SSID configuration.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the subdoc and key are valid before calling this function.
	 */
	int decode_config_set_ssid(em_subdoc_info_t *subdoc, const char *key);
    
	/**!
	 * @brief Decodes the configuration to set the channel.
	 *
	 * This function processes the given subdocument information and key to set the channel
	 * configuration at the specified index. It updates the number of channels processed.
	 *
	 * @param[in] subdoc Pointer to the subdocument information structure.
	 * @param[in] key The key associated with the configuration setting.
	 * @param[in] index The index at which the channel configuration is to be set.
	 * @param[out] num Pointer to an unsigned integer where the number of channels processed will be stored.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the subdoc and num pointers are valid before calling this function.
	 */
	int decode_config_set_channel(em_subdoc_info_t *subdoc, const char *key, unsigned int index, unsigned int *num);
    
	/**!
	 * @brief Decodes the configuration and sets the policy based on the provided subdocument information.
	 *
	 * This function processes the subdocument information and applies the policy settings
	 * according to the specified key and index.
	 *
	 * @param[in] subdoc Pointer to the subdocument information structure.
	 * @param[in] key The key associated with the policy to be set.
	 * @param[in] index The index at which the policy is to be applied.
	 * @param[out] num Pointer to an unsigned integer where the number of policies set will be stored.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the subdoc pointer is valid and that the key is correctly specified.
	 */
	int decode_config_set_policy(em_subdoc_info_t *subdoc, const char *key, unsigned int index, unsigned int *num);
    
	/**!
	 * @brief Decodes the configuration and sets the radio parameters.
	 *
	 * This function processes the given subdocument information and updates the radio
	 * configuration based on the specified key and index.
	 *
	 * @param[in] subdoc Pointer to the subdocument information structure.
	 * @param[in] key The key associated with the configuration to be decoded.
	 * @param[in] index The index of the radio configuration to be set.
	 * @param[out] num Pointer to an unsigned integer where the number of configurations
	 *                 processed will be stored.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the subdoc and num pointers are valid before calling this function.
	 */
	int decode_config_set_radio(em_subdoc_info_t *subdoc, const char *key, unsigned int index, unsigned int *num);
    
	/**!
	 * @brief Decodes the configuration operation class array.
	 *
	 * This function processes the given JSON object to extract operation class
	 * information based on the specified type and MAC address.
	 *
	 * @param[in] arr_obj Pointer to the cJSON object representing the array.
	 * @param[in] type The operation class type to decode.
	 * @param[out] mac Pointer to the buffer where the MAC address will be stored.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the arr_obj is properly formatted and contains valid data
	 * for decoding.
	 */
	int decode_config_op_class_array(cJSON *arr_obj, em_op_class_type_t type, unsigned char *mac);
    
    
	/**!
	 * @brief Encodes the configuration for the given subdocument and key.
	 *
	 * This function takes a subdocument information structure and a key, then encodes the configuration accordingly.
	 *
	 * @param[in] subdoc Pointer to the subdocument information structure to be encoded.
	 * @param[in] key The key associated with the configuration to be encoded.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note Ensure that the subdoc and key are valid before calling this function.
	 */
	int encode_config(em_subdoc_info_t *subdoc, const char *key);
    
	/**!
	 * @brief Encodes the configuration reset for the given sub-document.
	 *
	 * This function takes a sub-document information structure and a key,
	 * and encodes the configuration reset process.
	 *
	 * @param[in] subdoc Pointer to the sub-document information structure.
	 * @param[in] key The key associated with the configuration reset.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the subdoc and key are valid before calling this function.
	 */
	int encode_config_reset(em_subdoc_info_t *subdoc, const char *key);
    
	/**!
	 * @brief Encodes the configuration test for the given sub-document.
	 *
	 * This function takes a sub-document information structure and a key,
	 * and encodes the configuration test based on these inputs.
	 *
	 * @param[in] subdoc Pointer to the sub-document information structure.
	 * @param[in] key The key used for encoding the configuration test.
	 *
	 * @returns int Status code indicating success or failure of the encoding process.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the subdoc and key are valid before calling this function.
	 */
	int encode_config_test(em_subdoc_info_t *subdoc, const char *key);
    
	/**!
	 * @brief Encodes the configuration operation class array.
	 *
	 * This function encodes the operation class array based on the provided JSON object and operation class type.
	 *
	 * @param[in] arr_obj Pointer to the cJSON object representing the array to be encoded.
	 * @param[in] type The operation class type to be used for encoding.
	 * @param[in] mac Pointer to the MAC address used in the encoding process.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the cJSON object and MAC address are valid before calling this function.
	 */
	int encode_config_op_class_array(cJSON *arr_obj, em_op_class_type_t type, unsigned char *mac);

    
	/**!
	 * @brief Decodes the station configuration from the given subdocument.
	 *
	 * This function processes the provided subdocument to extract and configure
	 * the station settings for the specified device index.
	 *
	 * @param[in] subdoc Pointer to the subdocument containing station configuration.
	 * @param[in] dev_index The index of the device for which the configuration is to be decoded.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the subdocument is properly initialized before calling this function.
	 */
	int decode_sta_config(em_subdoc_info_t *subdoc, unsigned int dev_index);
    
	/**!
	 * @brief Decodes the number of devices from the given sub-document.
	 *
	 * This function takes a sub-document information structure and extracts
	 * the number of devices encoded within it.
	 *
	 * @param[in] subdoc Pointer to the sub-document information structure.
	 *
	 * @returns int The number of devices decoded from the sub-document.
	 *
	 * @note Ensure that the subdoc pointer is valid and properly initialized
	 * before calling this function.
	 */
	int decode_num_devices(em_subdoc_info_t *subdoc);
    
	/**!
	 * @brief Decodes the client capability configuration.
	 *
	 * This function processes the given sub-document information and extracts
	 * the client MAC and radio MAC addresses based on the provided key.
	 *
	 * @param[in] subdoc Pointer to the sub-document information structure.
	 * @param[in] key The key used to identify the specific configuration.
	 * @param[out] clientmac Buffer to store the decoded client MAC address.
	 * @param[out] radio_mac Buffer to store the decoded radio MAC address.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffers for clientmac and radio_mac are adequately
	 * sized to hold the MAC addresses.
	 */
	int decode_client_cap_config(em_subdoc_info_t *subdoc, const char *key, char *clientmac, char *radio_mac);
    
	/**!
	 * @brief Decodes the AP capability configuration from the given subdocument.
	 *
	 * This function processes the subdocument information and extracts the AP capability
	 * configuration based on the provided key.
	 *
	 * @param[in] subdoc Pointer to the subdocument information structure.
	 * @param[in] key The key used to identify the AP capability configuration within the subdocument.
	 *
	 * @returns int Status code indicating the success or failure of the decoding operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the subdoc and key are valid and properly initialized before calling this function.
	 */
	int decode_ap_cap_config(em_subdoc_info_t *subdoc, const char *key);

    
	/**!
	 * @brief Commits the configuration to the specified target.
	 *
	 * This function applies the current configuration settings to the given target
	 * within the EasyMesh framework.
	 *
	 * @param[in] dm Reference to the EasyMesh instance.
	 * @param[in] target The target to which the configuration will be committed.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the EasyMesh instance is properly initialized before calling
	 * this function.
	 */
	int commit_config(dm_easy_mesh_t& dm, em_commit_target_t target);
    
	/**!
	 * @brief Commits the configuration for the specified target.
	 *
	 * This function applies the configuration changes specified by the TLV type and data to the target.
	 *
	 * @param[in] tlv The type-length-value (TLV) type that specifies the configuration.
	 * @param[in] data Pointer to the data buffer containing the configuration.
	 * @param[in] len The length of the data buffer.
	 * @param[in] id The BSSID identifier for the configuration.
	 * @param[in] target The target for which the configuration is to be committed.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Success
	 * @retval -1 Failure
	 *
	 * @note Ensure that the data buffer is properly allocated and the length is correctly specified to avoid buffer overflow.
	 */
	int commit_config(em_tlv_type_t tlv, unsigned char *data, unsigned int len, bssid_t id, em_commit_target_t target);
    
	/**!
	 * @brief Commits a configuration to the specified target.
	 *
	 * This function applies the given configuration attribute to the target specified by the BSSID.
	 *
	 * @param[in] attrib The attribute ID to be committed.
	 * @param[in] data Pointer to the data associated with the attribute.
	 * @param[in] len Length of the data in bytes.
	 * @param[in] id The BSSID of the target device.
	 * @param[in] target The target where the configuration should be committed.
	 *
	 * @returns int Status of the commit operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the data buffer is valid and the length is correctly specified.
	 */
	int commit_config(em_attrib_id_t attrib, unsigned char *data, unsigned int len, bssid_t id, em_commit_target_t target);
    
	/**!
	 * @brief Commits the configuration for the specified radio and VAP indices.
	 *
	 * This function applies the configuration settings to the specified radio and VAP indices within the EasyMesh framework.
	 *
	 * @param[in] dm The EasyMesh data structure containing the configuration settings.
	 * @param[in] radio_index The index of the radio to which the configuration is to be applied.
	 * @param[in] vap_index The index of the VAP (Virtual Access Point) to which the configuration is to be applied.
	 * @param[in] num_radios The total number of radios available in the system.
	 * @param[in] num_bss The total number of BSS (Basic Service Set) available in the system.
	 *
	 * @returns int Status code indicating success or failure of the commit operation.
	 * @retval 0 Success
	 * @retval -1 Failure due to invalid parameters or internal errors.
	 *
	 * @note Ensure that the indices provided are within the valid range of available radios and VAPs.
	 */
	int commit_config(dm_easy_mesh_t& dm, unsigned int radio_index, unsigned int vap_index, unsigned int num_radios, unsigned int num_bss);
    
	/**!
	* @brief Commits the configuration using the provided command.
	*
	* This function takes a command structure and applies the configuration
	* settings contained within it.
	*
	* @param[in] cmd Pointer to the command structure containing configuration settings.
	*
	* @returns int Status code indicating success or failure of the operation.
	* @retval 0 on success.
	* @retval -1 on failure.
	*
	* @note Ensure that the command structure is properly initialized before calling this function.
	*/
	int commit_config(em_cmd_t  *cmd);
    
	/**!
	 * @brief Commits the BSS configuration for a specified VAP index.
	 *
	 * This function applies the BSS configuration changes to the specified VAP index within the EasyMesh domain.
	 *
	 * @param[in] dm The EasyMesh domain object containing the configuration.
	 * @param[in] vap_index The index of the VAP to which the configuration should be applied.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the VAP index is valid and the EasyMesh domain is properly initialized before calling this function.
	 */
	int commit_bss_config(dm_easy_mesh_t& dm, unsigned int vap_index);

    
	/**!
	 * @brief Sets the network configuration.
	 *
	 * This function assigns the provided network configuration to the member variable.
	 *
	 * @param[in] network Reference to the network configuration to be set.
	 *
	 * @note Ensure that the network configuration is valid before calling this function.
	 */
	void set_network(dm_network_t &network) { m_network = network; }

    
	/**!
	 * @brief Retrieves the control AL interface.
	 *
	 * This function returns the control AL interface from the network's colocated agent interface.
	 *
	 * @returns A pointer to the control AL interface.
	 *
	 * @note Ensure that the network is properly initialized before calling this function.
	 */
	em_interface_t *get_ctrl_al_interface() { return m_network.get_colocated_agent_interface(); }
    
	/**!
	 * @brief Retrieves the MAC address of the control interface.
	 *
	 * This function returns the MAC address associated with the control interface
	 * of the network's colocated agent.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 * @note Ensure that the returned MAC address is valid and properly formatted.
	 */
	unsigned char *get_ctrl_al_interface_mac() { return m_network.get_colocated_agent_interface_mac(); }
    
	/**!
	 * @brief Retrieves the control AL interface name.
	 *
	 * This function returns the name of the control AL interface used in the network.
	 *
	 * @returns A pointer to a character string containing the interface name.
	 *
	 * @note The returned string is managed internally and should not be freed by the caller.
	 */
	char *get_ctrl_al_interface_name() { return m_network.get_colocated_agent_interface_name(); }
    
	/**!
	 * @brief Sets the control AL interface MAC address.
	 *
	 * This function assigns the provided MAC address to the control AL interface.
	 *
	 * @param[in] mac Pointer to the MAC address to be set.
	 *
	 * @note Ensure that the MAC address is valid and properly formatted before calling this function.
	 */
	void set_ctrl_al_interface_mac(unsigned char *mac) { m_network.set_colocated_agent_interface_mac(mac); }
    
	/**!
	 * @brief Sets the control AL interface name.
	 *
	 * This function assigns the provided interface name to the control AL interface.
	 *
	 * @param[in] name The name of the interface to be set.
	 *
	 * @note This function modifies the interface name used by the network control agent.
	 */
	void set_ctrl_al_interface_name(char *name) { m_network.set_colocated_agent_interface_name(name); }
	
	/**!
	 * @brief Sets the controller ID for the network.
	 *
	 * This function assigns a new controller ID to the network using the provided MAC address.
	 *
	 * @param[in] mac Pointer to an unsigned char array representing the MAC address.
	 *
	 * @note Ensure that the MAC address is valid and correctly formatted before calling this function.
	 */
	void set_controller_id(unsigned char *mac) { m_network.set_controller_id(mac); }
	
	/**!
	 * @brief Sets the controller interface media type.
	 *
	 * This function configures the media type for the controller interface.
	 *
	 * @param[in] media The media type to be set for the controller interface.
	 *
	 * @note This function directly modifies the network's controller interface media type.
	 */
	void set_controller_intf_media(em_media_type_t media) { m_network.set_controller_intf_media(media); }

    
	/**!
	 * @brief Retrieves the agent's AL interface.
	 *
	 * This function returns a pointer to the agent's AL (Abstraction Layer) interface.
	 *
	 * @returns A pointer to the `em_interface_t` representing the agent's AL interface.
	 * @note Ensure that the returned interface is valid before using it.
	 */
	em_interface_t *get_agent_al_interface() { return m_device.get_dev_interface(); }
    
	/**!
	 * @brief Retrieves the MAC address of the agent's AL interface.
	 *
	 * This function returns the MAC address associated with the agent's AL interface.
	 *
	 * @returns A pointer to an unsigned char array containing the MAC address.
	 *
	 * @note The returned MAC address is managed by the device and should not be modified.
	 */
	unsigned char *get_agent_al_interface_mac() { return m_device.get_dev_interface_mac(); }
    
	/**!
	 * @brief Retrieves the interface name of the agent.
	 *
	 * This function returns the interface name associated with the agent.
	 *
	 * @returns A pointer to a character string containing the interface name.
	 *
	 * @note The returned string is managed by the device and should not be freed by the caller.
	 */
	char *get_agent_al_interface_name() { return m_device.get_dev_interface_name(); }
    
	/**!
	 * @brief Sets the MAC address for the agent's AL interface.
	 *
	 * This function assigns the provided MAC address to the agent's AL interface.
	 *
	 * @param[in] mac Pointer to the MAC address to be set.
	 *
	 * @note Ensure that the MAC address is valid and properly formatted before calling this function.
	 */
	void set_agent_al_interface_mac(unsigned char *mac) { m_device.set_dev_interface_mac(mac); }
    
	/**!
	 * @brief Sets the interface name for the agent.
	 *
	 * This function assigns a new interface name to the agent's device.
	 *
	 * @param[in] name The new interface name to be set.
	 *
	 * @note The name should be a valid network interface identifier.
	 */
	void set_agent_al_interface_name(char *name) { return m_device.set_dev_interface_name(name); }

    
	/**!
	 * @brief Updates the CAC status for a given MAC address.
	 *
	 * This function updates the CAC (Channel Access Control) status for the specified
	 * MAC address. It is used to manage the channel access control settings in the
	 * EasyMesh network.
	 *
	 * @param[in] al_mac The MAC address for which the CAC status needs to be updated.
	 *
	 * @note Ensure that the MAC address provided is valid and corresponds to a device
	 * in the EasyMesh network.
	 */
	void update_cac_status_id(mac_address_t al_mac);

    
	/**!
	 * @brief Retrieves the controller interface.
	 *
	 * This function returns a pointer to the controller interface used in the network.
	 *
	 * @returns A pointer to the `em_interface_t` representing the controller interface.
	 *
	 * @note Ensure that the network is properly initialized before calling this function.
	 */
	em_interface_t *get_controller_interface() { return m_network.get_controller_interface(); }
    
	/**!
	 * @brief Retrieves the MAC address of the controller interface.
	 *
	 * @returns A pointer to an unsigned char array containing the MAC address.
	 *
	 * @note The returned MAC address is associated with the controller interface.
	 */
	unsigned char *get_controller_interface_mac() { return m_network.get_controller_interface_mac(); }
    
	/**!
	 * @brief Retrieves the IEEE 1905 security information.
	 *
	 * This function returns a pointer to the IEEE 1905 security information
	 * associated with the given data model.
	 *
	 * @param[in] dm Pointer to the data model (dm_easy_mesh_t) from which
	 * the IEEE 1905 security information is to be retrieved.
	 *
	 * @returns Pointer to the em_ieee_1905_security_info_t structure containing
	 * the security information.
	 *
	 * @note Ensure that the provided data model pointer is valid and properly
	 * initialized before calling this function.
	 */
	static em_ieee_1905_security_info_t *get_ieee_1905_security_info(void *dm) { return (static_cast<dm_easy_mesh_t *>(dm))->get_ieee_1905_security_info(); }
    
	/**!
	 * @brief Retrieves the IEEE 1905 security information.
	 *
	 * This function returns a pointer to the IEEE 1905 security information structure.
	 *
	 * @returns A pointer to the `em_ieee_1905_security_info_t` structure containing the security information.
	 *
	 * @note Ensure that the returned pointer is not null before accessing the structure.
	 */
	em_ieee_1905_security_info_t *get_ieee_1905_security_info() { return m_ieee_1905_security.get_ieee_1905_security_info(); }
    
	/**!
	 * @brief Retrieves the IEEE 1905 security capabilities.
	 *
	 * This function returns a pointer to the IEEE 1905 security capabilities structure.
	 *
	 * @returns A pointer to the `em_ieee_1905_security_cap_t` structure containing the security capabilities.
	 *
	 * @note Ensure that the returned pointer is not null before accessing the structure.
	 */
	em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() { return m_ieee_1905_security.get_ieee_1905_security_cap(); }
    
	/**!
	 * @brief Retrieves the device information.
	 *
	 * This function returns a pointer to the device information structure.
	 *
	 * @returns A pointer to an em_device_info_t structure containing the device information.
	 *
	 * @note Ensure that the returned pointer is not null before accessing its members.
	 */
	em_device_info_t *get_device_info() { return m_device.get_device_info(); }
    
	/**!
	 * @brief Retrieves the device information from the given mesh device manager.
	 *
	 * This function casts the provided device manager to the appropriate type and
	 * calls the `get_device_info` method to obtain the device information.
	 *
	 * @param[in] dm A pointer to the device manager from which to retrieve the device information.
	 *
	 * @returns A pointer to the `em_device_info_t` structure containing the device information.
	 *
	 * @note Ensure that the `dm` pointer is valid and correctly castable to `dm_easy_mesh_t`.
	 */
	static em_device_info_t *get_device_info(void *dm) { return (static_cast<dm_easy_mesh_t *>(dm))->get_device_info(); }
    
    
	/**!
	 * @brief Retrieves the current network configuration.
	 *
	 * This function returns a pointer to the current network configuration
	 * stored in the `m_network` variable.
	 *
	 * @returns A pointer to the `dm_network_t` structure representing the
	 * current network configuration.
	 *
	 * @note Ensure that the returned pointer is not modified directly.
	 */
	dm_network_t *get_network() { return &m_network; }
    
	/**!
	 * @brief Retrieves the network reference.
	 *
	 * This function returns a reference to the current network object.
	 *
	 * @returns A reference to the current network object.
	 *
	 * @note Ensure that the network object is properly initialized before calling this function.
	 */
	dm_network_t& get_network_by_ref() { return m_network; }
    
	/**!
	 * @brief Retrieves the network information.
	 *
	 * This function returns a pointer to the network information structure.
	 *
	 * @returns A pointer to the em_network_info_t structure containing the network information.
	 *
	 * @note Ensure that the returned pointer is not null before accessing the network information.
	 */
	em_network_info_t *get_network_info() { return m_network.get_network_info(); }
    
	/**!
	 * @brief Retrieves the network information from the given Easy Mesh instance.
	 *
	 * This function casts the provided Easy Mesh instance to the appropriate type and
	 * returns the network information associated with it.
	 *
	 * @param[in] dm Pointer to the Easy Mesh instance.
	 *
	 * @returns Pointer to the network information structure.
	 *
	 * @note Ensure that the provided pointer is valid and correctly initialized.
	 */
	static em_network_info_t *get_network_info(void *dm) { return (static_cast<dm_easy_mesh_t *>(dm))->get_network_info(); }
    
	/**!
	 * @brief Retrieves the MAC address of the controller interface.
	 *
	 * This function returns the MAC address associated with the controller interface
	 * of the network.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 *
	 * @note Ensure that the returned MAC address is valid and properly formatted.
	 */
	unsigned char *get_ctl_mac() { return m_network.get_controller_interface_mac();}

	
	/**!
	 * @brief Retrieves the interface by its index.
	 *
	 * This function returns a pointer to the interface structure corresponding to the given index.
	 *
	 * @param[in] index The index of the interface to retrieve.
	 *
	 * @returns A pointer to the interface structure.
	 * @retval NULL if the index is out of bounds.
	 *
	 * @note Ensure that the index is within the valid range of interfaces.
	 */
	em_interface_t *get_interface_by_index(unsigned int index) { return &m_interfaces[index]; }
	
	/**!
	 * @brief Retrieves the prioritized interface for a given platform.
	 *
	 * This function searches for and returns the interface that has the highest priority
	 * for the specified platform.
	 *
	 * @param[in] platform A string representing the platform for which the prioritized
	 * interface is to be retrieved.
	 *
	 * @returns A pointer to the `em_interface_t` structure representing the prioritized
	 * interface for the given platform.
	 * @retval NULL if no prioritized interface is found for the specified platform.
	 *
	 * @note Ensure that the platform string is valid and corresponds to a known platform
	 * before calling this function.
	 */
	em_interface_t *get_prioritized_interface(const char *platform);

	/**!
	 * @brief Retrieves the platform details.
	 *
	 * This function retrive the device platform and return the pointer to the name.
	 *
	 * @returns A pointer to the name of platform.
	 */
	const char* get_platform();
    
	/**!
	 * @brief Retrieves the device object.
	 *
	 * This function returns a pointer to the device object managed by the system.
	 *
	 * @returns A pointer to the device object.
	 */
	dm_device_t *get_device() { return &m_device; }
    
	/**!
	 * @brief Retrieves a reference to the device.
	 *
	 * @returns A reference to the device object.
	 */
	dm_device_t& get_device_by_ref() { return m_device; }
    
	/**!
	 * @brief Finds a matching device from a list of devices.
	 *
	 * This function searches through a list of devices to find one that matches the specified device.
	 *
	 * @param[in] dev Pointer to the device to match against the list.
	 *
	 * @returns Pointer to the matching device if found, otherwise NULL.
	 *
	 * @note Ensure that the device list is properly initialized before calling this function.
	 */
	dm_device_t *find_matching_device(dm_device_t *dev);
    
	/**!
	 * @brief Retrieves the current operational class for the given index.
	 *
	 * @param[in] index The index for which the operational class is to be retrieved.
	 *
	 * @returns A pointer to the current operational class.
	 * @retval NULL if the index is out of range or an error occurs.
	 *
	 * @note Ensure that the index is within the valid range before calling this function.
	 */
	dm_op_class_t *get_curr_op_class(unsigned int index);

    
	/**!
	 * @brief Retrieves the number of network SSIDs.
	 *
	 * This function returns the total count of network SSIDs available.
	 *
	 * @returns The number of network SSIDs.
	 */
	unsigned int get_num_network_ssid() { return m_num_net_ssids; }
    
	/**!
	 * @brief Sets the number of network SSIDs.
	 *
	 * This function assigns the provided number to the member variable
	 * responsible for storing the count of network SSIDs.
	 *
	 * @param[in] num The number of network SSIDs to set.
	 *
	 * @note Ensure that the number provided is within the valid range
	 * for network SSIDs.
	 */
	void set_num_network_ssid(unsigned int num) { m_num_net_ssids = num; }
    
	/**!
	 * @brief Retrieves the network SSID at the specified index.
	 *
	 * This function returns a pointer to the network SSID structure
	 * located at the given index within the internal array.
	 *
	 * @param[in] index The index of the network SSID to retrieve.
	 *
	 * @returns A pointer to the `dm_network_ssid_t` structure at the specified index.
	 *
	 * @note Ensure that the index is within the valid range of the array.
	 */
	dm_network_ssid_t *get_network_ssid(unsigned int index) { return &m_network_ssid[index]; }
    
	/**!
	 * @brief Retrieves the network SSID by reference for a given index.
	 *
	 * This function returns a reference to the network SSID at the specified index.
	 *
	 * @param[in] index The index of the network SSID to retrieve.
	 *
	 * @returns A reference to the network SSID at the specified index.
	 *
	 * @note Ensure that the index is within the valid range of network SSIDs.
	 */
	dm_network_ssid_t& get_network_ssid_by_ref(unsigned int index) { return m_network_ssid[index]; }
    
	/**!
	 * @brief Retrieves the network SSID information based on the specified haul type.
	 *
	 * This function searches for and returns the SSID information associated with the given haul type.
	 *
	 * @param[in] haul_type The type of haul for which the SSID information is requested.
	 *
	 * @returns A pointer to the em_network_ssid_info_t structure containing the SSID information.
	 * @retval NULL if no SSID information is found for the specified haul type.
	 *
	 * @note Ensure that the haul_type provided is valid and supported by the system.
	 */
	em_network_ssid_info_t *get_network_ssid_info_by_haul_type(em_haul_type_t haul_type);

	
	/**!
	 * @brief Retrieves the operational class information for a given index.
	 *
	 * This function returns a pointer to the operational class information
	 * associated with the specified index.
	 *
	 * @param[in] index The index of the operational class to retrieve.
	 *
	 * @returns A pointer to the `em_op_class_info_t` structure containing
	 * the operational class information.
	 *
	 * @note Ensure that the index is within the valid range of operational
	 * classes to avoid undefined behavior.
	 */
	em_op_class_info_t *get_op_class_info(unsigned int index) { return m_op_class[index].get_op_class_info(); }
    
	/**!
	 * @brief Retrieves the operational class information for a given index.
	 *
	 * This function accesses the operational class information from the provided
	 * data model (dm) and returns the corresponding information for the specified index.
	 *
	 * @param[in] dm Pointer to the data model from which to retrieve the information.
	 * @param[in] index The index for which the operational class information is requested.
	 *
	 * @returns A pointer to the operational class information structure.
	 * @retval NULL if the information cannot be retrieved or if the index is invalid.
	 *
	 * @note Ensure that the data model (dm) is properly initialized before calling this function.
	 */
	static em_op_class_info_t *get_op_class_info(void *dm, unsigned int index) { return (static_cast<dm_easy_mesh_t *>(dm))->get_op_class_info(index); }
    
	/**!
	 * @brief Retrieves the number of operational classes.
	 *
	 * @returns The number of operational classes.
	 */
	unsigned int get_num_op_class() { return m_num_opclass; }
    
	/**!
	 * @brief Retrieves the number of operational classes.
	 *
	 * This function returns the number of operational classes available in the
	 * dm_easy_mesh_t structure.
	 *
	 * @param[in] dm Pointer to the dm_easy_mesh_t structure.
	 *
	 * @returns The number of operational classes as an unsigned integer.
	 */
	static unsigned int get_num_op_class(void *dm) { return (static_cast<dm_easy_mesh_t *>(dm))->get_num_op_class(); }
    
	/**!
	 * @brief Sets the number of operating classes.
	 *
	 * This function assigns the provided number to the member variable
	 * responsible for storing the number of operating classes.
	 *
	 * @param[in] num The number of operating classes to set.
	 */
	void set_num_op_class(unsigned int num) { m_num_opclass = num; }
    
	/**!
	 * @brief Sets the number of operational classes.
	 *
	 * This function sets the number of operational classes for the given
	 * dm_easy_mesh_t instance.
	 *
	 * @param[in] dm Pointer to the dm_easy_mesh_t instance.
	 * @param[in] num The number of operational classes to set.
	 *
	 * @note Ensure that the dm pointer is valid before calling this function.
	 */
	static void set_num_op_class(void *dm, unsigned int num) { (static_cast<dm_easy_mesh_t *>(dm))->set_num_op_class(num); }
    
	/**!
	 * @brief Retrieves the operational class at the specified index.
	 *
	 * @param[in] index The index of the operational class to retrieve.
	 *
	 * @returns A pointer to the operational class at the specified index.
	 *
	 * @note Ensure that the index is within the valid range to avoid undefined behavior.
	 */
	dm_op_class_t *get_op_class(unsigned int index) { return &m_op_class[index]; }
    
	/**!
	 * @brief Retrieves the operational class by reference.
	 *
	 * This function returns a reference to the operational class at the specified index.
	 *
	 * @param[in] index The index of the operational class to retrieve.
	 *
	 * @returns A reference to the operational class at the given index.
	 *
	 * @note Ensure that the index is within the valid range to avoid undefined behavior.
	 */
	dm_op_class_t& get_op_class_by_ref(unsigned int index) { return m_op_class[index]; }
	
	/**!
	 * @brief Prints the operational class list.
	 *
	 * This function outputs the list of operational classes associated with the given EasyMesh instance.
	 *
	 * @param[in] dm Pointer to the EasyMesh instance.
	 *
	 * @note Ensure that the EasyMesh instance is properly initialized before calling this function.
	 */
	static void print_op_class_list(dm_easy_mesh_t *dm);

    
	/**!
	 * @brief Retrieves the BSS (Basic Service Set) information for a given index.
	 *
	 * This function returns a pointer to the BSS information structure for the specified index.
	 *
	 * @param[in] index The index of the BSS information to retrieve.
	 *
	 * @returns A pointer to the em_bss_info_t structure containing the BSS information.
	 * @retval nullptr If the index is out of range or the BSS information is not available.
	 *
	 * @note Ensure that the index is within the valid range of available BSS information.
	 */
	em_bss_info_t *get_bss_info(unsigned int index) { return m_bss[index].get_bss_info(); }
    
	/**!
	 * @brief Retrieves the BSS information for a given index.
	 *
	 * This function accesses the BSS information from the EasyMesh data structure.
	 *
	 * @param[in] dm Pointer to the EasyMesh data structure.
	 * @param[in] index The index of the BSS information to retrieve.
	 *
	 * @returns A pointer to the BSS information structure.
	 *
	 * @note Ensure that the index is within the valid range of BSS entries.
	 */
	static em_bss_info_t *get_bss_info(void *dm, unsigned int index) { return (static_cast<dm_easy_mesh_t *>(dm))->get_bss_info(index); }

	/**!
	 * @brief Retrieves the `em_bss_info_t` for the bSTA.
	 *
	 * @returns A pointer to the em_bss_info_t structure containing BSTA BSS information. NULL if not found.
	 *
	 */
	em_bss_info_t* get_bsta_bss_info();


	/**!
	 * @brief Retrieves the `em_bss_info_t` for the backhaul BSS.
	 *
	 * @returns A pointer to the em_bss_info_t structure containing the backhaul BSS information.
	 * NULL if the backhaul BSS is not found
	 */
	em_bss_info_t* get_backhaul_bss_info();
    
	/**!
	 * @brief Retrieves the number of BSS (Basic Service Set).
	 *
	 * This function returns the current number of BSS managed by the system.
	 *
	 * @returns The number of BSS.
	 */
	unsigned int get_num_bss() { return m_num_bss; }
    
	/**!
	 * @brief Retrieves the number of BSS (Basic Service Set) from the given Easy Mesh instance.
	 *
	 * @param[in] dm Pointer to the Easy Mesh instance.
	 *
	 * @returns The number of BSS.
	 */
	static unsigned int get_num_bss(void *dm) { return (static_cast<dm_easy_mesh_t *>(dm))->get_num_bss(); }
    
	/**!
	 * @brief Sets the number of BSS (Basic Service Set).
	 *
	 * This function assigns the provided number to the member variable `m_num_bss`.
	 *
	 * @param[in] num The number of BSS to set.
	 */
	void set_num_bss(unsigned int num) { m_num_bss = num; }
    
	/**!
	 * @brief Sets the number of BSS (Basic Service Set) for the given mesh instance.
	 *
	 * This function updates the number of BSS in the specified mesh instance.
	 *
	 * @param[in] dm Pointer to the mesh instance (dm_easy_mesh_t).
	 * @param[in] num The number of BSS to set.
	 *
	 * @note Ensure that the mesh instance is properly initialized before calling this function.
	 */
	static void set_num_bss(void *dm, unsigned int num) { (static_cast<dm_easy_mesh_t *>(dm))->set_num_bss(num); }
    
	/**!
	 * @brief Retrieves a BSS (Basic Service Set) from the list based on the provided index.
	 *
	 * This function returns a pointer to the BSS structure at the specified index.
	 *
	 * @param[in] index The index of the BSS to retrieve.
	 *
	 * @returns A pointer to the BSS structure at the specified index.
	 * @retval NULL if the index is out of bounds.
	 *
	 * @note Ensure that the index is within the valid range to avoid undefined behavior.
	 */
	dm_bss_t *get_bss(unsigned int index) { return &m_bss[index]; }
    
	/**!
	 * @brief Retrieves the BSS (Basic Service Set) information for a given radio and BSS MAC address.
	 *
	 * This function searches for the BSS associated with the specified radio and BSS MAC addresses and returns a pointer to the BSS structure.
	 *
	 * @param[in] radio The MAC address of the radio interface.
	 * @param[in] bss The MAC address of the BSS to be retrieved.
	 *
	 * @returns A pointer to the `dm_bss_t` structure representing the BSS information.
	 * @retval NULL if the BSS is not found or an error occurs.
	 *
	 * @note Ensure that the radio and BSS MAC addresses are valid and correspond to existing entries.
	 */
	dm_bss_t *get_bss(mac_address_t radio, mac_address_t bss);
    
	/**!
	 * @brief Retrieves a reference to the BSS object at the specified index.
	 *
	 * This function returns a reference to the BSS object stored in the internal array
	 * at the given index. It is assumed that the index is valid and within bounds.
	 *
	 * @param[in] index The index of the BSS object to retrieve.
	 *
	 * @returns A reference to the BSS object at the specified index.
	 */
	dm_bss_t& get_bss_by_ref(unsigned int index) { return m_bss[index]; }
	
	/**!
	 * @brief Removes a BSS entry by its index.
	 *
	 * This function deletes a BSS (Basic Service Set) entry from the list using the specified index.
	 *
	 * @param[in] index The index of the BSS entry to be removed.
	 *
	 * @note Ensure the index is valid and within the range of existing entries.
	 */
	void remove_bss_by_index(unsigned int index);
	
	/**!
	 * @brief Finds a matching BSS (Basic Service Set) based on the provided BSS ID.
	 *
	 * This function searches for a BSS that matches the given BSS ID and returns a pointer to it.
	 *
	 * @param[in] id Pointer to the BSS ID structure to match against existing BSS entries.
	 *
	 * @returns Pointer to the matching BSS structure if found, otherwise NULL.
	 *
	 * @note Ensure that the BSS ID provided is valid and initialized before calling this function.
	 */
	dm_bss_t *find_matching_bss(em_bss_id_t *id);

	
	/**!
	 * @brief Retrieves the number of policies.
	 *
	 * @returns The number of policies as an unsigned integer.
	 */
	unsigned int get_num_policy() { return m_num_policy; }
	
	/**!
	 * @brief Sets the number policy.
	 *
	 * This function assigns the provided number to the member variable `m_num_policy`.
	 *
	 * @param[in] num The number to set as the policy.
	 */
	void set_num_policy(unsigned int num) { m_num_policy = num; }
	
	/**!
	 * @brief Retrieves the policy at the specified index.
	 *
	 * This function returns a pointer to the policy object located at the given index
	 * within the policy array.
	 *
	 * @param[in] index The index of the policy to retrieve.
	 *
	 * @returns A pointer to the policy object at the specified index.
	 * @retval nullptr If the index is out of bounds.
	 *
	 * @note Ensure that the index is within the valid range of the policy array.
	 */
	dm_policy_t *get_policy(unsigned int index) { return &m_policy[index]; }
    
	/**!
	 * @brief Retrieves a reference to the policy at the specified index.
	 *
	 * This function returns a reference to the policy object stored at the given index
	 * within the policy array. It is used to access and modify the policy directly.
	 *
	 * @param[in] index The index of the policy to retrieve.
	 *
	 * @returns A reference to the policy object at the specified index.
	 *
	 * @note Ensure that the index is within the bounds of the policy array to avoid
	 * undefined behavior.
	 */
	dm_policy_t& get_policy_by_ref(unsigned int index) { return m_policy[index]; }

	
	/**!
	 * @brief Finds a matching scan result based on the provided scan result ID.
	 *
	 * This function searches through the available scan results and returns a pointer to the result that matches the given ID.
	 *
	 * @param[in] id A pointer to the scan result ID used for matching.
	 *
	 * @returns A pointer to the matching scan result if found, otherwise NULL.
	 *
	 * @note Ensure that the scan results are initialized before calling this function.
	 */
	dm_scan_result_t *find_matching_scan_result(em_scan_result_id_t *id);
	
	/**!
	 * @brief Creates a new scan result.
	 *
	 * This function initializes a new scan result structure using the provided scan result ID.
	 *
	 * @param[in] id Pointer to the scan result ID used to initialize the new scan result.
	 *
	 * @returns Pointer to the newly created scan result structure.
	 * @retval NULL if the creation fails due to memory allocation issues or invalid input.
	 *
	 * @note Ensure that the `id` is valid and properly initialized before calling this function.
	 */
	dm_scan_result_t *create_new_scan_result(em_scan_result_id_t *id);
	
	/**!
	 * @brief Retrieves the number of scan results available.
	 *
	 * This function returns the count of scan results stored in the scan result map.
	 *
	 * @returns The number of scan results.
	 */
	unsigned int	get_num_scan_results() { return hash_map_count(m_scan_result_map); }
	
	/**!
	 * @brief Retrieves the scan result at the specified index.
	 *
	 * This function returns a pointer to the scan result corresponding to the given index.
	 *
	 * @param[in] index The index of the scan result to retrieve.
	 *
	 * @returns A pointer to the scan result at the specified index.
	 * @retval NULL if the index is out of bounds or if there is no scan result available.
	 *
	 * @note Ensure that the index is within the valid range of available scan results.
	 */
	dm_scan_result_t *get_scan_result(unsigned int index);
    
	/**!
	 * @brief Updates the scan results with the provided scan result data.
	 *
	 * This function takes a pointer to a scan result structure and updates the
	 * internal scan results accordingly.
	 *
	 * @param[in] scan_result Pointer to the scan result data to be updated.
	 *
	 * @note Ensure that the scan_result pointer is valid and points to a properly
	 * initialized em_scan_result_t structure before calling this function.
	 */
	void update_scan_results(em_scan_result_t *scan_result);
    
	/**!
	 * @brief Updates the scan results for the EasyMesh device.
	 *
	 * This function processes the scan results and updates the internal state of the EasyMesh device.
	 *
	 * @param[in] dm Pointer to the EasyMesh device context.
	 * @param[in] scan_result Pointer to the scan result structure containing the latest scan data.
	 *
	 * @note This function is static and should be used internally within the EasyMesh module.
	 */
	static void update_scan_results(void *dm, em_scan_result_t *scan_result) { (static_cast<dm_easy_mesh_t *> (dm))->update_scan_results(scan_result); }

    
	/**!
	 * @brief Retrieves the number of AP MLDs.
	 *
	 * @returns The number of AP MLDs.
	 */
	unsigned int get_num_ap_mld() { return m_num_ap_mld; }
    
	/**!
	 * @brief Retrieves the number of AP MLDs.
	 *
	 * This function returns the number of Access Point Multi-Link Devices (AP MLDs)
	 * associated with the given EasyMesh data structure.
	 *
	 * @param[in] dm Pointer to the EasyMesh data structure.
	 *
	 * @returns The number of AP MLDs.
	 */
	static unsigned int get_num_ap_mld(void *dm) { return (static_cast<dm_easy_mesh_t *>(dm))->get_num_ap_mld(); }
    
	/**!
	 * @brief Sets the number of AP MLD.
	 *
	 * This function assigns the provided number to the member variable m_num_ap_mld.
	 *
	 * @param[in] num The number of AP MLD to set.
	 */
	void set_num_ap_mld(unsigned int num) { m_num_ap_mld = num; }
    
	/**!
	 * @brief Sets the number of AP MLDs in the EasyMesh configuration.
	 *
	 * This function updates the number of Access Point Multi-Link Devices (AP MLDs) in the EasyMesh configuration.
	 *
	 * @param[in] dm Pointer to the EasyMesh configuration object.
	 * @param[in] num The number of AP MLDs to set.
	 *
	 * @note Ensure that the `dm` pointer is valid and points to a properly initialized EasyMesh configuration object.
	 */
	static void set_num_ap_mld(void *dm, unsigned int num) { (static_cast<dm_easy_mesh_t *>(dm))->set_num_ap_mld(num); }
    
	/**!
	 * @brief Retrieves the access point MLD (Multi-Link Device) at the specified index.
	 *
	 * This function returns a pointer to the access point MLD structure located at the given index.
	 *
	 * @param[in] index The index of the access point MLD to retrieve.
	 *
	 * @returns A pointer to the `dm_ap_mld_t` structure at the specified index.
	 *
	 * @note Ensure that the index is within the valid range to avoid undefined behavior.
	 */
	dm_ap_mld_t *get_ap_mld(unsigned int index) { return &m_ap_mld[index]; }
    
	/**!
	 * @brief Retrieves a reference to the AP MLD at the specified index.
	 *
	 * This function returns a reference to the AP MLD (Access Point Multi-Link Device) object
	 * located at the given index within the internal storage.
	 *
	 * @param[in] index The index of the AP MLD to retrieve.
	 *
	 * @returns A reference to the AP MLD object at the specified index.
	 *
	 * @note Ensure that the index is within the valid range of stored AP MLDs to avoid undefined behavior.
	 */
	dm_ap_mld_t& get_ap_mld_by_ref(unsigned int index) { return m_ap_mld[index]; }

    
	/**!
	 * @brief Retrieves the number of BSTA MLD.
	 *
	 * This function returns the current number of BSTA MLD.
	 *
	 * @returns The number of BSTA MLD.
	 */
	unsigned int get_num_bsta_mld() { return m_num_bsta_mld; }
    
	/**!
	 * @brief Retrieves the number of BSTA MLD.
	 *
	 * This function returns the number of BSTA MLD from the given dm_easy_mesh_t object.
	 *
	 * @param[in] dm Pointer to the dm_easy_mesh_t object.
	 *
	 * @returns The number of BSTA MLD.
	 */
	static unsigned int get_num_bsta_mld(void *dm) { return (static_cast<dm_easy_mesh_t *>(dm))->get_num_bsta_mld(); }

    
	/**!
	 * @brief Retrieves the number of associated station MLDs.
	 *
	 * This function returns the current count of associated station MLDs.
	 *
	 * @returns The number of associated station MLDs.
	 */
	unsigned int get_num_assoc_sta_mld() { return m_num_assoc_sta_mld; }
    
	/**!
	 * @brief Retrieves the number of associated stations in the mesh network.
	 *
	 * This function returns the number of associated stations in the mesh network
	 * by accessing the relevant data from the dm_easy_mesh_t structure.
	 *
	 * @param[in] dm Pointer to the dm_easy_mesh_t structure.
	 *
	 * @returns The number of associated stations in the mesh network.
	 */
	static unsigned int get_num_assoc_sta_mld(void *dm) { return (static_cast<dm_easy_mesh_t *>(dm))->get_num_assoc_sta_mld(); }

    
	/**!
	 * @brief Retrieves the Data Model DPP object.
	 *
	 * @returns A pointer to the dm_dpp_t object.
	 */
	dm_dpp_t *get_dpp() { return &m_dpp; }

    
	/**!
	 * @brief Retrieves a radio object based on the provided index.
	 *
	 * This function returns a pointer to a dm_radio_t object corresponding to the specified index.
	 *
	 * @param[in] index The index of the radio to retrieve.
	 *
	 * @returns A pointer to the dm_radio_t object if the index is valid.
	 * @retval NULL if the index is out of range.
	 *
	 * @note Ensure the index is within the valid range before calling this function.
	 */
	dm_radio_t *get_radio(unsigned int index);
    
	/**!
	 * @brief Retrieves a reference to the radio object at the specified index.
	 *
	 * @param[in] index The index of the radio object to retrieve.
	 *
	 * @returns A reference to the radio object at the specified index.
	 *
	 * @note Ensure the index is within the valid range to avoid undefined behavior.
	 */
	dm_radio_t& get_radio_by_ref(unsigned int index) { return m_radio[index]; }
    
	/**!
	 * @brief Retrieves the radio configuration for a given MAC address.
	 *
	 * This function searches for the radio configuration associated with the specified MAC address and returns a pointer to the radio configuration structure.
	 *
	 * @param[in] mac The MAC address for which the radio configuration is requested.
	 *
	 * @returns A pointer to the dm_radio_t structure containing the radio configuration.
	 * @retval NULL if the MAC address is not found or an error occurs.
	 *
	 * @note Ensure that the MAC address provided is valid and corresponds to a configured radio.
	 */
	dm_radio_t *get_radio(mac_address_t mac);
    
	/**!
	 * @brief Retrieves the radio interface for a given index.
	 *
	 * This function returns the radio interface associated with the specified index.
	 *
	 * @param[in] index The index of the radio interface to retrieve.
	 *
	 * @returns A pointer to the radio interface associated with the given index.
	 * @retval nullptr If the index is out of range or the interface is not available.
	 *
	 * @note Ensure that the index is within the valid range of available radio interfaces.
	 */
	em_interface_t *get_radio_interface(unsigned int index) { return m_radio[index].get_radio_interface(); }
    
	/**!
	 * @brief Retrieves the radio information for a given index.
	 *
	 * This function returns a pointer to the radio information structure
	 * corresponding to the specified index.
	 *
	 * @param[in] index The index of the radio for which information is requested.
	 *
	 * @returns A pointer to the em_radio_info_t structure containing the radio information.
	 * @retval nullptr if the index is out of range or invalid.
	 *
	 * @note Ensure that the index is within the valid range of available radios.
	 */
	em_radio_info_t *get_radio_info(unsigned int index) { return m_radio[index].get_radio_info(); }
    
	/**!
	 * @brief Retrieves radio information for a given index.
	 *
	 * This function accesses the radio information from the EasyMesh data structure
	 * using the provided index.
	 *
	 * @param[in] dm Pointer to the EasyMesh data structure.
	 * @param[in] index The index of the radio information to retrieve.
	 *
	 * @returns A pointer to the radio information structure.
	 *
	 * @note Ensure that the index is within the valid range of available radios.
	 */
	static em_radio_info_t *get_radio_info(void *dm, unsigned int index) { return (static_cast<dm_easy_mesh_t *>(dm))->get_radio_info(index); }
    
	/**!
	 * @brief Retrieves the radio data for a given interface.
	 *
	 * This function fetches the radio data associated with the specified
	 * interface and returns a pointer to the radio data structure.
	 *
	 * @param[in] radio Pointer to the interface for which radio data is required.
	 *
	 * @returns Pointer to the radio data structure.
	 * @retval NULL if the radio data could not be retrieved.
	 *
	 * @note Ensure that the radio interface is valid before calling this function.
	 */
	rdk_wifi_radio_t    *get_radio_data(em_interface_t *radio);
    
	/**!
	 * @brief Retrieves the number of radios.
	 *
	 * This function returns the total number of radios available.
	 *
	 * @returns The number of radios.
	 */
	unsigned int get_num_radios() { return m_num_radios; }
    
	/**!
	 * @brief Retrieves the number of radios.
	 *
	 * This function returns the number of radios available in the given
	 * dm_easy_mesh_t instance.
	 *
	 * @param[in] dm Pointer to the dm_easy_mesh_t instance.
	 *
	 * @returns The number of radios as an unsigned integer.
	 */
	static unsigned int get_num_radios(void *dm) { return (static_cast<dm_easy_mesh_t *>(dm))->get_num_radios(); }
    
	/**!
	 * @brief Sets the number of radios.
	 *
	 * This function assigns the given number to the member variable m_num_radios.
	 *
	 * @param[in] num The number of radios to be set.
	 */
	void set_num_radios(unsigned int num) { m_num_radios = num; }
    
	/**!
	 * @brief Sets the number of radios in the mesh network.
	 *
	 * This function updates the number of radios in the mesh network configuration.
	 *
	 * @param[in] dm Pointer to the mesh network configuration object.
	 * @param[in] num The number of radios to be set.
	 *
	 * @note Ensure that the mesh network configuration object is properly initialized before calling this function.
	 */
	static void set_num_radios(void *dm, unsigned int num) { (static_cast<dm_easy_mesh_t *>(dm))->set_num_radios(num); }
    
	/**!
	 * @brief Finds a matching radio from a given radio object.
	 *
	 * This function searches for a radio that matches the specified radio object.
	 *
	 * @param[in] radio A pointer to the radio object to be matched.
	 *
	 * @returns A pointer to the matching radio object if found, otherwise NULL.
	 *
	 * @note Ensure that the radio object passed is valid and initialized.
	 */
	dm_radio_t *find_matching_radio(dm_radio_t *radio);
    
	/**!
	 * @brief Retrieves the radio capabilities for a given MAC address.
	 *
	 * This function queries the system to obtain the radio capabilities
	 * associated with the specified MAC address.
	 *
	 * @param[in] mac The MAC address for which the radio capabilities are requested.
	 *
	 * @returns A pointer to a dm_radio_cap_t structure containing the radio capabilities.
	 * @retval NULL if the MAC address is not found or an error occurs.
	 *
	 * @note Ensure that the MAC address provided is valid and registered in the system.
	 */
	dm_radio_cap_t *get_radio_cap(mac_address_t mac);

    
	/**!
	 * @brief Retrieves the manufacturer of the device.
	 *
	 * This function returns the manufacturer name of the device as a string.
	 *
	 * @returns A pointer to a character string containing the manufacturer's name.
	 *
	 * @note The returned string is managed by the device and should not be modified or freed by the caller.
	 */
	char *get_manufacturer() { return m_device.get_manufacturer(); }
    
	/**!
	 * @brief Retrieves the manufacturer model of the device.
	 *
	 * @returns A pointer to a character string representing the manufacturer model.
	 *
	 * @note This function returns the model information stored in the device object.
	 */
	char *get_manufacturer_model() { return m_device.get_manufacturer_model(); }
    
	/**!
	 * @brief Retrieves the software version of the device.
	 *
	 * @returns A pointer to a character string containing the software version.
	 */
	char *get_software_version() { return m_device.get_software_version(); }
    
	/**!
	 * @brief Retrieves the serial number of the device.
	 *
	 * @returns A pointer to a character array containing the serial number.
	 */
	char *get_serial_number() { return m_device.get_serial_number(); }
    
	/**!
	 * @brief Retrieves the primary device type.
	 *
	 * This function returns the primary device type as a string.
	 *
	 * @returns A pointer to a character string representing the primary device type.
	 *
	 * @note Ensure that the returned string is not modified or freed by the caller.
	 */
	char *get_primary_device_type() { return m_device.get_primary_device_type(); }

    
	/**!
	 * @brief Retrieves the message ID.
	 *
	 * @returns The message ID as an unsigned short.
	 */
	unsigned short get_msg_id() { return msg_id; }
    
	/**!
	 * @brief Sets the message ID.
	 *
	 * This function assigns the provided ID to the message ID.
	 *
	 * @param[in] id The ID to be set for the message.
	 */
	void set_msg_id(unsigned short id) { msg_id = id; }

    
	/**!
	 * @brief Sets the manufacturer name for the device.
	 *
	 * This function assigns the provided manufacturer name to the device's manufacturer attribute.
	 *
	 * @param[in] manufacturer A pointer to a character array containing the manufacturer name.
	 *
	 * @note Ensure that the manufacturer name is a valid string and the pointer is not null.
	 */
	void set_manufacturer(char *manufacturer) { m_device.set_manufacturer(manufacturer); }
    
	/**!
	 * @brief Sets the manufacturer model for the device.
	 *
	 * This function assigns the provided model string to the device's manufacturer model.
	 *
	 * @param[in] model A pointer to a character array containing the model name.
	 *
	 * @note Ensure that the model string is null-terminated and valid.
	 */
	void set_manufacturer_model(char *model) { m_device.set_manufacturer_model(model); }
    
	/**!
	 * @brief Sets the software version for the device.
	 *
	 * This function updates the software version of the device to the specified version.
	 *
	 * @param[in] version A pointer to a character array containing the new software version.
	 *
	 * @note Ensure that the version string is null-terminated.
	 */
	void set_software_version(char *version) { m_device.set_software_version(version); }
    
	/**!
	 * @brief Sets the serial number for the device.
	 *
	 * This function assigns a serial number to the device by calling the
	 * set_serial_number method of the m_device object.
	 *
	 * @param[in] serial A pointer to a character array containing the serial number.
	 *
	 * @note Ensure that the serial number is null-terminated and does not exceed
	 * the maximum allowed length for the device.
	 */
	void set_serial_number(char *serial) { m_device.set_serial_number(serial); }
    
	/**!
	 * @brief Sets the primary device type.
	 *
	 * This function assigns the specified device type to the primary device.
	 *
	 * @param[in] type A pointer to a character array representing the device type.
	 *
	 * @note Ensure that the `type` parameter is a valid string representing the device type.
	 */
	void set_primary_device_type(char *type) { m_device.set_primary_device_type(type); }
    //void operator =(dm_easy_mesh_t const& obj);
    dm_easy_mesh_t& operator =(dm_easy_mesh_t const& obj);
    bool operator ==(dm_easy_mesh_t const& obj);
    
	/**!
	 * @brief Retrieves the command context.
	 *
	 * This function returns a pointer to the command context structure used in the EasyMesh module.
	 *
	 * @returns A pointer to the command context structure.
	 */
	em_cmd_ctx_t *get_cmd_ctx() { return &m_cmd_ctx; }
    
	/**!
	 * @brief Sets the command context.
	 *
	 * This function copies the provided command context into the internal command context structure.
	 *
	 * @param[in] ctx Pointer to the command context to be set.
	 *
	 * @note Ensure that the provided context is properly initialized before calling this function.
	 */
	void    set_cmd_ctx(em_cmd_ctx_t *ctx) { memcpy(&m_cmd_ctx, ctx, sizeof(em_cmd_ctx_t)); }
    
	/**!
	 * @brief Resets the command context to its initial state.
	 *
	 * This function clears the memory of the command context structure,
	 * effectively resetting it to its default state.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void    reset_cmd_ctx() { memset(&m_cmd_ctx, 0, sizeof(em_cmd_ctx_t)); }

    
	/**!
	 * @brief Retrieves the first station information from the target station map.
	 *
	 * This function searches through the provided target station map and returns
	 * the first station information found.
	 *
	 * @param[in] target The target station map from which the first station
	 * information is to be retrieved.
	 *
	 * @returns A pointer to the first station information structure found in the
	 * target station map.
	 * @retval NULL if no station information is found or if the target is invalid.
	 *
	 * @note Ensure that the target station map is properly initialized before
	 * calling this function.
	 */
	em_sta_info_t *get_first_sta_info(em_target_sta_map_t target);
    
	/**!
	 * @brief Retrieves the next station information from the given station info.
	 *
	 * This function takes the current station information and a target station map,
	 * and returns the next station information in the sequence.
	 *
	 * @param[in] info Pointer to the current station information structure.
	 * @param[in] target The target station map used to determine the next station.
	 *
	 * @returns Pointer to the next station information structure.
	 * @retval NULL if there is no next station information available.
	 *
	 * @note Ensure that the `info` parameter is not NULL before calling this function.
	 */
	em_sta_info_t *get_next_sta_info(em_sta_info_t *info, em_target_sta_map_t target);
    
	/**!
	 * @brief Retrieves station information based on the provided MAC address, BSSID, RUID, and target station map.
	 *
	 * This function searches for the station information using the given identifiers and returns a pointer to the
	 * em_sta_info_t structure containing the relevant data.
	 *
	 * @param[in] sta The MAC address of the station.
	 * @param[in] bssid The BSSID associated with the station.
	 * @param[in] ruid The RUID of the station.
	 * @param[in] target The target station map used for searching.
	 *
	 * @returns A pointer to the em_sta_info_t structure containing the station information.
	 * @retval NULL if the station information is not found.
	 *
	 * @note Ensure that the provided MAC address, BSSID, RUID, and target are valid and correctly formatted.
	 */
	em_sta_info_t *get_sta_info(mac_address_t sta, bssid_t bssid, mac_address_t ruid, em_target_sta_map_t target);
    
	/**!
	 * @brief Puts station information into the target station map.
	 *
	 * This function updates the target station map with the provided station information.
	 *
	 * @param[in] info Pointer to the station information structure.
	 * @param[in] target The target station map where the information will be placed.
	 *
	 * @note Ensure that the `info` pointer is valid and points to a properly initialized `em_sta_info_t` structure.
	 */
	void put_sta_info(em_sta_info_t *info, em_target_sta_map_t target);
    
	/**!
	 * @brief Retrieves the first station information.
	 *
	 * This function returns the first station information from the given target.
	 *
	 * @param[in] dm Pointer to the dm_easy_mesh_t structure.
	 * @param[in] target The target station map from which to retrieve the information.
	 *
	 * @returns A pointer to the em_sta_info_t structure containing the station information.
	 * @retval NULL if no station information is available.
	 *
	 * @note Ensure that the dm pointer is valid before calling this function.
	 */
	static em_sta_info_t *get_first_sta_info(void *dm, em_target_sta_map_t target) { return (static_cast<dm_easy_mesh_t *>(dm))->get_first_sta_info(target); }
    
	/**!
	 * @brief Retrieves the next station information from the mesh network.
	 *
	 * This function is used to iterate over the station information in the mesh network.
	 *
	 * @param[in] dm Pointer to the mesh network data structure.
	 * @param[in] info Pointer to the current station information structure.
	 * @param[in] target The target station map to be used for retrieval.
	 *
	 * @returns Pointer to the next station information structure.
	 * @retval NULL if there are no more stations to retrieve.
	 *
	 * @note Ensure that the `dm` pointer is valid and points to a properly initialized mesh network structure.
	 */
	static em_sta_info_t *get_next_sta_info(void *dm, em_sta_info_t *info, em_target_sta_map_t target) { return (static_cast<dm_easy_mesh_t *>(dm))->get_first_sta_info(info, target); }
    
	/**!
	 * @brief Retrieves station information.
	 *
	 * This function fetches the station information based on the provided parameters.
	 *
	 * @param[in] dm Pointer to the EasyMesh instance.
	 * @param[in] sta MAC address of the station.
	 * @param[in] bssid BSSID of the network.
	 * @param[in] ruid MAC address of the radio unit.
	 * @param[in] target Target station map.
	 *
	 * @returns Pointer to the station information structure.
	 *
	 * @note Ensure that the EasyMesh instance is properly initialized before calling this function.
	 */
	static em_sta_info_t *get_sta_info(void *dm, mac_address_t sta, bssid_t bssid, mac_address_t ruid, em_target_sta_map_t target) { return (static_cast<dm_easy_mesh_t *>(dm))->get_sta_info(sta, bssid, ruid, target); }
    
	/**!
	 * @brief Puts station information into the EasyMesh data structure.
	 *
	 * This function updates the station information within the EasyMesh context.
	 *
	 * @param[in] dm Pointer to the EasyMesh data structure.
	 * @param[in] info Pointer to the station information structure to be added.
	 * @param[in] target The target station map where the information should be placed.
	 *
	 * @note This function is a wrapper around the put_sta_info method of the dm_easy_mesh_t class.
	 */
	static void put_sta_info(void *dm, em_sta_info_t *info, em_target_sta_map_t target) { (static_cast<dm_easy_mesh_t *>(dm))->put_sta_info(info, target); }

    
	/**!
	 * @brief Finds a station (STA) based on its MAC address and BSSID.
	 *
	 * This function searches for a station in the network using the provided
	 * MAC address and BSSID, and returns a pointer to the station information
	 * if found.
	 *
	 * @param[in] sta_mac The MAC address of the station to find.
	 * @param[in] bssid The BSSID of the network to search within.
	 *
	 * @returns A pointer to the `dm_sta_t` structure representing the station
	 *          if found, or `nullptr` if the station is not found.
	 *
	 * @note Ensure that the MAC address and BSSID are valid and correspond to
	 *       the network's configuration.
	 */
	dm_sta_t *find_sta(mac_address_t sta_mac, bssid_t bssid);
    
	/**!
	 * @brief Retrieves the first station associated with the given MAC address.
	 *
	 * This function searches for the first station entry that matches the provided
	 * MAC address and returns a pointer to the station data structure.
	 *
	 * @param[in] sta_mac The MAC address of the station to be retrieved.
	 *
	 * @returns A pointer to the `dm_sta_t` structure representing the station.
	 * @retval NULL if no station with the given MAC address is found.
	 *
	 * @note Ensure that the MAC address provided is valid and that the station
	 * list is initialized before calling this function.
	 */
	dm_sta_t *get_first_sta(mac_address_t sta_mac);
    
	/**!
	 * @brief Retrieves the next station in the list based on the given MAC address.
	 *
	 * This function searches for the station with the specified MAC address and returns the next station in the list.
	 *
	 * @param[in] sta_mac The MAC address of the station to search for.
	 * @param[in] psta Pointer to the current station structure.
	 *
	 * @returns Pointer to the next station structure if found, otherwise NULL.
	 *
	 * @note Ensure that the list of stations is properly initialized before calling this function.
	 */
	dm_sta_t *get_next_sta(mac_address_t sta_mac, dm_sta_t *psta);
    
	/**!
	 * @brief Checks if there is at least one associated station.
	 *
	 * This function determines whether there is at least one station
	 * associated with the mesh network.
	 *
	 * @returns True if there is at least one associated station, false otherwise.
	 */
	bool has_at_least_one_associated_sta();
    
	/**!
	 * @brief Retrieves the number of BSS (Basic Service Set) for a given associated station.
	 *
	 * This function takes the MAC address of a station and returns the number of BSS
	 * that the station is associated with.
	 *
	 * @param[in] sta_mac The MAC address of the station.
	 *
	 * @returns The number of BSS associated with the given station.
	 */
	int get_num_bss_for_associated_sta(mac_address_t sta_mac);
    
    
	/**!
	 * @brief Converts a byte array to a hexadecimal string representation.
	 *
	 * This function takes a byte array and converts it into a hexadecimal string.
	 * The output string is null-terminated.
	 *
	 * @param[in] in_len The length of the input byte array.
	 * @param[in] in The input byte array to be converted.
	 * @param[in] out_len The length of the output buffer.
	 * @param[out] out The buffer where the hexadecimal string will be stored.
	 *
	 * @returns A pointer to the output buffer containing the hexadecimal string.
	 * @retval NULL if the output buffer is too small to hold the result.
	 *
	 * @note Ensure that the output buffer is large enough to hold the resulting
	 * hexadecimal string and the null terminator. The required size is
	 * (2 * in_len + 1) bytes.
	 */
	static char *hex(unsigned int in_len, unsigned char *in, unsigned int out_len, char *out);
    
	/**!
	 * @brief Converts a hexadecimal string to a byte array.
	 *
	 * This function takes a string of hexadecimal characters and converts it into a byte array.
	 *
	 * @param[in] in_len The length of the input hexadecimal string.
	 * @param[in] in The input string containing hexadecimal characters.
	 * @param[in] out_len The length of the output byte array.
	 * @param[out] out The output byte array where the converted bytes will be stored.
	 *
	 * @returns A pointer to the output byte array.
	 *
	 * @note Ensure that the output buffer is large enough to hold the converted bytes.
	 */
	static unsigned char *unhex(unsigned int in_len, char *in, unsigned int out_len, unsigned char *out);
    
	/**!
	 * @brief Converts a MAC address to a string representation.
	 *
	 * This function takes a MAC address in the form of a `mac_address_t` and converts it into a human-readable string format.
	 *
	 * @param[in] mac The MAC address to be converted.
	 * @param[out] string The buffer where the resulting string representation of the MAC address will be stored.
	 *
	 * @returns A pointer to the resulting string.
	 *
	 * @note Ensure that the `string` buffer is large enough to hold the MAC address string.
	 */
	static char *macbytes_to_string(mac_address_t mac, char* string);
    
	/**!
	 * @brief Converts a string representation of a MAC address to a byte array.
	 *
	 * This function takes a string containing a MAC address in the format
	 * "XX:XX:XX:XX:XX:XX" and converts it into a byte array representation.
	 *
	 * @param[in] key A pointer to a string containing the MAC address.
	 * @param[out] bmac A mac_address_t array where the converted MAC address will be stored.
	 *
	 * @note The input string must be properly formatted and null-terminated.
	 */
	static void string_to_macbytes (char *key, mac_address_t bmac);
    
	/**!
	 * @brief Retrieves the MAC address associated with a given interface name.
	 *
	 * This function looks up the MAC address for the specified network interface name
	 * and stores it in the provided mac_address_t structure.
	 *
	 * @param[in] ifname The name of the network interface to query.
	 * @param[out] mac The structure where the MAC address will be stored.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure, such as if the interface name is not found.
	 *
	 * @note Ensure that the mac parameter is a valid pointer to a mac_address_t structure.
	 */
	static int mac_address_from_name(const char *ifname, mac_address_t mac);
    
	/**!
	 * @brief Retrieves the interface name associated with a given MAC address.
	 *
	 * This function searches for the network interface name that corresponds to the provided MAC address.
	 *
	 * @param[in] mac Pointer to the MAC address structure.
	 * @param[out] ifname Buffer to store the resulting interface name.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 if the MAC address is not found.
	 *
	 * @note Ensure that the buffer for `ifname` is sufficiently large to hold the interface name.
	 */
	static int name_from_mac_address(const mac_address_t *mac, char *ifname);
	
	/**!
	 * @brief Retrieves the list of interfaces.
	 *
	 * This function populates the provided array with the available interfaces
	 * and updates the number of interfaces found.
	 *
	 * @param[out] interfaces Array to be filled with interface data.
	 * @param[in,out] num_interfaces Pointer to the number of interfaces.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the array is large enough to hold all interfaces.
	 */
	static int get_interfaces_list(em_interface_t interfaces[], unsigned int *num_interfaces);
    
	/**!
	 * @brief Converts a security mode to its string representation.
	 *
	 * This function takes a security mode represented as an unsigned short and converts it
	 * into a human-readable string format, storing the result in the provided buffer.
	 *
	 * @param[in] mode The security mode to be converted.
	 * @param[out] sec_mode_str A buffer where the string representation of the security mode will be stored.
	 * @param[in] len The length of the buffer `sec_mode_str`.
	 *
	 * @note Ensure that the buffer `sec_mode_str` is large enough to hold the resulting string.
	 */
	static void securitymode_to_str(unsigned short mode, char *sec_mode_str, size_t len);
	
	/**!
	 * @brief Converts a string representation of a security mode to its corresponding numeric value.
	 *
	 * This function takes a string that represents a security mode and converts it into a numeric value
	 * that can be used in further processing or decision making.
	 *
	 * @param[out] mode Pointer to an unsigned short where the converted security mode will be stored.
	 * @param[in] sec_mode_str String containing the security mode to be converted.
	 * @param[in] len Length of the security mode string.
	 *
	 * @note Ensure that the `sec_mode_str` is a valid representation of a security mode before calling this function.
	 */
	static void str_to_securitymode(unsigned short *mode, char *sec_mode_str, size_t len);


    
	/**!
	 * @brief Creates a JSON command for auto-configuration renewal.
	 *
	 * This function generates a JSON command used for renewing the auto-configuration
	 * settings based on the provided MAC addresses and frequency band.
	 *
	 * @param[in] src_mac_addr Source MAC address as a string.
	 * @param[in] agent_al_mac Agent AL MAC address as a string.
	 * @param[in] freq_band Frequency band for the auto-configuration.
	 * @param[out] autoconfig_renew_json Buffer to store the generated JSON command.
	 *
	 * @note Ensure that the buffer for `autoconfig_renew_json` is sufficiently large
	 * to hold the generated JSON command.
	 */
	static void create_autoconfig_renew_json_cmd(char* src_mac_addr, char* agent_al_mac, em_freq_band_t freq_band, char* autoconfig_renew_json);
    
	/**!
	 * @brief Creates a JSON command for client capability query.
	 *
	 * This function generates a JSON command to query the capabilities of a client device.
	 *
	 * @param[in] src_mac_addr Source MAC address of the client.
	 * @param[in] agent_al_mac AL MAC address of the agent.
	 * @param[out] ap_query_json Buffer to store the generated JSON command.
	 * @param[in] msg_id Message identifier for the query.
	 * @param[in] mac MAC address of the device to query.
	 *
	 * @note Ensure that the buffer for `ap_query_json` is adequately sized to hold the generated JSON.
	 */
	static void create_client_cap_query_json_cmd(char* src_mac_addr, char* agent_al_mac, char* ap_query_json, short msg_id, char *mac);
    
	/**!
	 * @brief Creates a JSON command for AP capability query.
	 *
	 * This function generates a JSON formatted string for querying the capabilities of an Access Point (AP).
	 *
	 * @param[in] src_mac_addr Source MAC address of the device initiating the query.
	 * @param[in] agent_al_mac AL MAC address of the agent.
	 * @param[out] ap_query_json Buffer to store the generated JSON command.
	 * @param[in] msg_id Message identifier for the query.
	 *
	 * @note Ensure that the buffer `ap_query_json` is large enough to hold the generated JSON string.
	 */
	static void create_ap_cap_query_json_cmd(char* src_mac_addr, char* agent_al_mac, char* ap_query_json, short msg_id);
    
	/**!
	 * @brief Prints the current configuration settings.
	 *
	 * This function outputs the current configuration settings to the standard output.
	 * It is useful for debugging and verifying the current state of the configuration.
	 *
	 * @note This function does not modify any configuration settings.
	 */
	void print_config();

    
	/**!
	 * @brief Sets the database configuration parameter.
	 *
	 * This function sets a specific configuration parameter for the database
	 * based on the provided type and parameter string.
	 *
	 * @param[in] type The type of the database configuration parameter to set.
	 * @param[in] param The parameter value to be set for the specified type.
	 *
	 * @note Ensure that the type and param are valid and supported by the database.
	 */
	void set_db_cfg_param(db_cfg_type_t type, const char *param);
	
	/**!
	 * @brief Resets the database configuration of the specified type.
	 *
	 * This function resets the configuration settings for the given database type,
	 * ensuring that it returns to its default state.
	 *
	 * @param[in] type The type of database configuration to reset.
	 *
	 * @note Ensure that the type provided is valid and supported by the system.
	 */
	void reset_db_cfg_type(db_cfg_type_t type);
	
	/**!
	 * @brief Checks if a specific database configuration type is set.
	 *
	 * This function evaluates whether the given database configuration type is set in the current configuration.
	 *
	 * @param[in] type The database configuration type to check.
	 *
	 * @returns True if the specified configuration type is set, false otherwise.
	 */
	bool db_cfg_type_is_set(db_cfg_type_t type) { return m_db_cfg_param.db_cfg_type & static_cast<unsigned int>(type); }
	
	/**!
	 * @brief Retrieves the criteria for the specified configuration type.
	 *
	 * This function returns a string that represents the criteria associated with the given configuration type.
	 *
	 * @param[in] type The configuration type for which criteria is to be retrieved.
	 *
	 * @returns A pointer to a character string containing the criteria.
	 *
	 * @note Ensure that the type provided is valid and supported by the system.
	 */
	char *db_cfg_type_get_criteria(db_cfg_type_t type);
	
	/**!
	 * @brief Checks if the database configuration type is set.
	 *
	 * This function evaluates whether the database configuration type is greater than zero.
	 *
	 * @returns True if the database configuration type is set, false otherwise.
	 */
	bool db_cfg_type_is_set() { return m_db_cfg_param.db_cfg_type > 0; }

    
	/**!
	 * @brief Handles the dirty device management state.
	 *
	 * This function is responsible for processing and managing the state when the device management is marked as dirty.
	 *
	 * @note Ensure that the device management state is properly initialized before calling this function.
	 */
	void handle_dirty_dm();
    
	/**!
	 * @brief Sets the Easy Mesh object.
	 *
	 * This function assigns the provided Easy Mesh object to the internal member.
	 *
	 * @param[in] em Pointer to the Easy Mesh object to be set.
	 *
	 * @note Ensure that the pointer is valid and points to a properly initialized Easy Mesh object.
	 */
	void set_em(em_t *em) { m_em = em; }
    
	/**!
	 * @brief Sets the colocated status.
	 *
	 * This function updates the colocated status of the mesh.
	 *
	 * @param[in] col Boolean value indicating the colocated status.
	 *
	 * @note This function modifies the internal state of the mesh.
	 */
	void set_colocated(bool col) { m_colocated = col; }
    
	/**!
	 * @brief Retrieves the colocated status.
	 *
	 * This function returns the current status of the colocated flag.
	 *
	 * @returns bool
	 * @retval true if colocated, false otherwise.
	 */
	bool get_colocated() { return m_colocated; }
	
	/**!
	 * @brief Sets the list of channels for the specified operating class.
	 *
	 * This function configures the channel list for a given operating class.
	 *
	 * @param[in] op_class Array of operating classes to be configured.
	 * @param[in] num Number of operating classes in the array.
	 *
	 * @note Ensure that the array is properly initialized before calling this function.
	 */
	void set_channels_list(dm_op_class_t op_class[], unsigned int num);
	
	/**!
	 * @brief Sets the policy for the device management.
	 *
	 * This function configures the device management policy based on the provided
	 * policy parameter.
	 *
	 * @param[in] policy The policy to be set for device management.
	 *
	 * @note Ensure that the policy parameter is valid and supported by the system.
	 */
	void set_policy(dm_policy_t policy);
   
        void set_csi_container(dm_csi_container_t cont);

	/**!
	 * @brief Retrieves the current em_t instance.
	 *
	 * @returns A pointer to the current em_t instance.
	 */
	em_t *get_em() { return m_em; }
    
	/**!
	 * @brief Clones the hash maps from the given dm_easy_mesh_t object.
	 *
	 * This function duplicates the hash maps contained within the provided
	 * dm_easy_mesh_t object, allowing for independent manipulation of the
	 * cloned data.
	 *
	 * @param[in] obj The dm_easy_mesh_t object whose hash maps are to be cloned.
	 *
	 * @note Ensure that the dm_easy_mesh_t object is properly initialized
	 * before calling this function to avoid undefined behavior.
	 */
	void clone_hash_maps(dm_easy_mesh_t& obj);

    
	/**!
	 * @brief Retrieves the subdocument type for a given frequency band.
	 *
	 * This function determines the webconfig subdocument type based on the provided frequency band.
	 *
	 * @param[in] band The frequency band for which the subdocument type is required.
	 *
	 * @returns The corresponding webconfig subdocument type for the specified frequency band.
	 *
	 * @note This function supports 2.4GHz, 5GHz, and 6GHz frequency bands.
	 */
	static inline webconfig_subdoc_type_t get_subdoc_vap_type_for_freq(em_freq_band_t band) {
        if (band == em_freq_band_24) return webconfig_subdoc_type_vap_24G;
        if (band == em_freq_band_5) return webconfig_subdoc_type_vap_5G;
        return webconfig_subdoc_type_vap_6G;
    }

    
	/**!
	 * @brief Retrieves the subdocument radio type for a given frequency band.
	 *
	 * This function determines the appropriate subdocument radio type based on the provided frequency band.
	 *
	 * @param[in] band The frequency band for which the subdocument radio type is required.
	 *
	 * @returns The corresponding webconfig subdocument radio type for the specified frequency band.
	 *
	 * @note The function supports 2.4GHz, 5GHz, and 6GHz frequency bands.
	 */
	static inline webconfig_subdoc_type_t get_subdoc_radio_type_for_freq(em_freq_band_t band) {
        if (band == em_freq_band_24) return webconfig_subdoc_type_radio_24G;
        if (band == em_freq_band_5) return webconfig_subdoc_type_radio_5G;
        return webconfig_subdoc_type_radio_6G;
    }

	
	/**!
	 * @brief Resets the mesh network to its initial state.
	 *
	 * This function is used to reset all configurations and states of the mesh network,
	 * effectively starting it from scratch.
	 *
	 * @note This operation cannot be undone and all current settings will be lost.
	 */
	void reset();
    
	/**!
	 * @brief Initializes the Easy Mesh module.
	 *
	 * This function sets up the necessary resources and configurations
	 * required for the Easy Mesh module to operate.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the system is properly configured before calling this function.
	 */
	int init();
    
	/**!
	 * @brief Deinitializes the Easy Mesh module.
	 *
	 * This function is responsible for cleaning up resources and
	 * shutting down the Easy Mesh module properly.
	 *
	 * @note Ensure that all operations using the Easy Mesh module
	 * are completed before calling this function.
	 */
	void deinit();

    
	/**!
	 * @brief Constructor for the dm_easy_mesh_t class.
	 *
	 * Initializes a new instance of the dm_easy_mesh_t class.
	 *
	 * @note This constructor does not take any parameters.
	 */
	dm_easy_mesh_t();
    
	/**!
	 * @brief Constructor for the dm_easy_mesh_t class.
	 *
	 * Initializes a new instance of the dm_easy_mesh_t class using the provided network configuration.
	 *
	 * @param[in] net A constant reference to a dm_network_t object representing the network configuration.
	 *
	 * @note Ensure that the dm_network_t object is properly configured before passing it to this constructor.
	 */
	dm_easy_mesh_t(const dm_network_t& net);
    
	/**!
	 * @brief Destructor for the dm_easy_mesh_t class.
	 *
	 * This function cleans up any resources used by the dm_easy_mesh_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	virtual ~dm_easy_mesh_t();  
};

#endif

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

#ifndef DM_EM_AGENT_H
#define DM_EM_AGENT_H

#include "em_base.h"
#include "wifi_webconfig.h"
#include "dm_easy_mesh.h"
#include "webconfig_external_proto.h"
#include "bus.h"

class dm_easy_mesh_agent_t : public dm_easy_mesh_t {

public:

    
	/**!
	 * @brief Analyzes the device initialization event and command.
	 *
	 * This function processes the initialization event and the associated command array.
	 *
	 * @param[in] evt Pointer to the event structure containing initialization details.
	 * @param[out] pcmd Array of pointers to command structures to be processed.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the event and command pointers are valid before calling this function.
	 */
	int analyze_dev_init(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    
	/**!
	 * @brief Analyzes the station list based on the provided event and command.
	 *
	 * This function processes the station list using the event data and command array.
	 *
	 * @param[in] evt Pointer to the event data structure containing information about the event.
	 * @param[in] pcmd Array of command pointers to be processed.
	 *
	 * @returns Integer status code indicating the result of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command data are properly initialized before calling this function.
	 */
	int analyze_sta_list(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    
	/**!
	 * @brief Analyzes the auto-configuration renewal process.
	 *
	 * This function processes the event and command data to renew the auto-configuration.
	 *
	 * @param[in] evt Pointer to the event structure containing the auto-configuration data.
	 * @param[out] pcmd Array of pointers to command structures that will be populated with renewal data.
	 *
	 * @returns int Status code indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_autoconfig_renew(em_bus_event_t *evt, em_cmd_t *pcmd[]);

    
	/**!
	 * @brief Translates the OneWiFi DML data.
	 *
	 * This function is responsible for processing and translating the data
	 * received from the OneWiFi Data Model Layer (DML).
	 *
	 * @param[in] data A pointer to the character array containing the DML data to be translated.
	 *
	 * @note Ensure that the data passed is properly formatted and null-terminated.
	 */
	void translate_onewifi_dml_data(char *);
    
    /**!
     * @brief Translates the OneWiFi statistics data.
     *
     * This function processes the given data and translates it into a format
     * suitable for further analysis or reporting.
     *
     * @param[in] data Pointer to the OneWiFi statistics data to be translated.
     * @param[in] type Type of the webconfig subdocument.
     * @param[in] logname Name of the log file.
     *
     * @note Ensure that the data pointer is valid and points to a properly
     * formatted statistics data structure.
     */
    void translate_and_decode_onewifi_subdoc(char *, webconfig_subdoc_type_t type, const char* logname);// translate when we receive ap , radio, client stats

	/**!
	 * @brief Analyzes the OneWiFi VAP callback event.
	 *
	 * This function processes the event and command data related to the OneWiFi VAP.
	 *
	 * @param[in] evt Pointer to the event structure containing the VAP event data.
	 * @param[out] pcmd Array of pointers to command structures to be filled with the analysis results.
	 *
	 * @returns Integer status code indicating the success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_onewifi_vap_cb(em_bus_event_t *evt, em_cmd_t *pcmd[]);
	
	/**!
	 * @brief Analyzes the OneWiFi radio callback event.
	 *
	 * This function processes the event and command data related to OneWiFi radio.
	 *
	 * @param[in] evt Pointer to the event structure containing radio event data.
	 * @param[out] pcmd Array of pointers to command structures to be filled with analysis results.
	 *
	 * @returns int Status code indicating success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_onewifi_radio_cb(em_bus_event_t *evt, em_cmd_t *pcmd[]);
	
	/**!
	 * @brief Analyzes the M2 control configuration.
	 *
	 * This function processes the event and descriptor to analyze the M2 control configuration.
	 *
	 * @param[in] evt Pointer to the event structure containing the M2 control data.
	 * @param[in] desc Pointer to the descriptor structure for the WiFi bus.
	 * @param[out] bus_hdl Pointer to the bus handle that will be updated based on the analysis.
	 *
	 * @returns int Status code indicating the success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the event and descriptor are properly initialized before calling this function.
	 */
	int analyze_m2ctrl_configuration(em_bus_event_t *evt, wifi_bus_desc_t *desc,bus_handle_t *bus_hdl);
    
	/**!
	 * @brief Analyzes the channel preference query.
	 *
	 * This function processes the channel preference query event and command.
	 *
	 * @param[in] evt Pointer to the event structure containing the channel preference query.
	 * @param[in] pcmd Array of pointers to command structures to be processed.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the event and command pointers are valid before calling this function.
	 */
	int analyze_channel_pref_query(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    
	/**!
	 * @brief Analyzes the channel selection request.
	 *
	 * This function processes the channel selection request event and updates the
	 * WiFi bus descriptor accordingly.
	 *
	 * @param[in] evt Pointer to the event structure containing channel selection request details.
	 * @param[in] desc Pointer to the WiFi bus descriptor to be updated.
	 * @param[in] bus_hdl Handle to the bus where the event is processed.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and descriptor pointers are valid before calling this function.
	 */
	int analyze_channel_sel_req(em_bus_event_t *evt, wifi_bus_desc_t *desc,bus_handle_t *bus_hdl);
    
	/**!
	 * @brief Analyzes the station link metrics.
	 *
	 * This function processes the event and command data to analyze the link metrics
	 * for a station in the EasyMesh network.
	 *
	 * @param[in] evt Pointer to the event data structure containing the link metrics.
	 * @param[in] pcmd Array of pointers to command structures for processing.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the event and command data are properly initialized before
	 * calling this function.
	 */
	int analyze_sta_link_metrics(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    
	/**!
	 * @brief Analyzes the BTM request action frame.
	 *
	 * This function processes the BTM (BSS Transition Management) request action frame
	 * and performs necessary actions based on the event and bus descriptor provided.
	 *
	 * @param[in] evt Pointer to the event structure containing BTM request details.
	 * @param[in] desc Pointer to the bus descriptor structure.
	 * @param[in] bus_hdl Handle to the bus for communication.
	 *
	 * @returns int Status code indicating success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and descriptor pointers are valid before calling this function.
	 */
	int analyze_btm_request_action_frame(em_bus_event_t *evt, wifi_bus_desc_t *desc,bus_handle_t *bus_hdl);
    
	/**!
	 * @brief Analyzes the BTM response action frame.
	 *
	 * This function processes the BTM (BSS Transition Management) response action frame
	 * and performs necessary actions based on the event and command parameters provided.
	 *
	 * @param[in] evt Pointer to the bus event structure containing event details.
	 * @param[in] pcmd Array of pointers to command structures for processing.
	 *
	 * @returns int Status code indicating success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized
	 * before calling this function.
	 */
	int analyze_btm_response_action_frame(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    
	/**!
	 * @brief Analyzes the scan result from the event bus.
	 *
	 * This function processes the scan results encapsulated in the event bus event and populates the command structure accordingly.
	 *
	 * @param[in] evt Pointer to the event bus event containing scan results.
	 * @param[out] pcmd Array of command structures to be populated based on the scan results.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_scan_result(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    
	/**!
	 * @brief Analyzes and sets the policy based on the provided event and bus description.
	 *
	 * This function processes the event and bus description to determine the appropriate policy settings.
	 *
	 * @param[in] evt Pointer to the event structure containing the event details.
	 * @param[in] desc Pointer to the bus description structure.
	 * @param[in] bus_hdl Pointer to the bus handle used for communication.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that all pointers are valid and initialized before calling this function.
	 */
	int analyze_set_policy(em_bus_event_t *evt, wifi_bus_desc_t *desc, bus_handle_t *bus_hdl);
    
	/**!
	 * @brief Analyzes the beacon report.
	 *
	 * This function processes the beacon report received in the event and command structures.
	 *
	 * @param[in] evt Pointer to the event structure containing the beacon report.
	 * @param[in] pcmd Array of pointers to command structures for processing.
	 *
	 * @returns int Status code indicating the success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_beacon_report(em_bus_event_t *evt, em_cmd_t *pcmd[]);

	/**!
	 * @brief Analyzes the AP Metrics report.
	 *
	 * This function processes the AP Metrics report received in the event and command structures.
	 *
	 * @param[in] evt Pointer to the event structure containing the AP Metrics report.
	 * @param[in] pcmd Array of pointers to command structures for processing.
	 *
	 * @returns int Status code indicating the success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_ap_metrics_report(em_bus_event_t *evt, em_cmd_t *pcmd[]);

	/**!
	 * @brief Refreshes the OneWiFi subdocument.
	 *
	 * This function refreshes the OneWiFi subdocument based on the provided parameters.
	 *
	 * @param[in] desc Pointer to the WiFi bus descriptor.
	 * @param[in] bus_hdl Pointer to the bus handle.
	 * @param[in] logname Name of the log file.
	 * @param[in] type Type of the webconfig subdocument.
	 * @param[in] m2_cfg Optional pointer to the M2 control radio configuration. Defaults to NULL.
	 * @param[in] policy_config Optional pointer to the policy configuration parameters. Defaults to NULL.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the provided pointers are valid and initialized before calling this function.
	 */
	int refresh_onewifi_subdoc(wifi_bus_desc_t *desc, bus_handle_t *bus_hdl, const char* logname,
                               webconfig_subdoc_type_t type, m2ctrl_radioconfig *m2_cfg=NULL, 
                               em_policy_cfg_params_t *policy_config=NULL);

    
	/**!
	 * @brief Apply the webconfig dummy settings.
	 *
	 * This function applies the settings specified in the webconfig dummy document.
	 *
	 * @param[in] doc Pointer to the webconfig subdocument containing the settings to be applied.
	 * @param[out] data Pointer to the webconfig subdocument data where the results of the apply operation will be stored.
	 *
	 * @returns webconfig_error_t
	 * @retval WEBCONFIG_SUCCESS if the settings were applied successfully.
	 * @retval WEBCONFIG_FAILURE if there was an error applying the settings.
	 *
	 * @note Ensure that the document and data pointers are valid before calling this function.
	 */
	static webconfig_error_t webconfig_dummy_apply(webconfig_subdoc_t *doc, webconfig_subdoc_data_t *data);
    
	/**!
	* @brief Constructor for the dm_easy_mesh_agent class.
	*
	* This constructor initializes a new instance of the dm_easy_mesh_agent class.
	*
	* @note This is a default constructor and does not take any parameters.
	*/
	dm_easy_mesh_agent_t();
    
	/**!
	 * @brief Destructor for the dm_easy_mesh_agent_t class.
	 *
	 * This function is responsible for cleaning up resources used by the dm_easy_mesh_agent_t instance.
	 *
	 * @note Ensure that all dynamically allocated resources are properly released.
	 */
	~dm_easy_mesh_agent_t();  
};

#endif


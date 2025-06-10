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

#ifndef EMAGNT_H
#define EMAGNT_H

#include "em.h"
#include "em_mgr.h"
#include "ieee80211.h"
#include "dm_easy_mesh_agent.h"
#include "em_crypto.h"
#include "em_orch_agent.h"
#include "em_simulator.h"
#include "bus.h"

#include <string>

class em_cmd_agent_t;
class AlServiceAccessPoint;

class em_agent_t : public em_mgr_t {

    em_orch_agent_t *m_orch;
    dm_easy_mesh_agent_t m_data_model;
    em_short_string_t   m_data_model_path;
    em_cmd_agent_t  *m_agent_cmd;
	em_simulator_t	m_simulator;

	
	/**!
	 * @brief Starts the completion process.
	 *
	 * This function initiates the completion process for the agent.
	 *
	 * @note Ensure that the agent is properly initialized before calling this function.
	 */
	void start_complete();
    
	/**!
	 * @brief Executes an I/O operation using the provided buffer.
	 *
	 * This function initiates an I/O operation using the buffer passed as an argument.
	 *
	 * @param[in] buff A pointer to a character array that contains the data to be processed.
	 *
	 * @note Ensure that the buffer is properly allocated and initialized before calling this function.
	 */
	void io_run(char *buff);
	
	/**!
	 * @brief Updates the network topology.
	 *
	 * This function is responsible for updating the network topology based on the current configuration and state.
	 *
	 * @note Ensure that the network configuration is correctly set before calling this function.
	 */
	void update_network_topology() { }

    
	/**!
	 * @brief Handles the 5-second tick event.
	 *
	 * This function is called every 5 seconds to perform periodic tasks.
	 *
	 * @note Ensure that this function is called regularly to maintain system stability.
	 */
	void handle_5s_tick();
    
	/**!
	 * @brief Handles the 2-second tick event.
	 *
	 * This function is called every 2 seconds to perform periodic tasks.
	 *
	 * @note Ensure that this function is called regularly to maintain system timing.
	 */
	void handle_2s_tick();
    
	/**!
	 * @brief Handles the 1-second tick event.
	 *
	 * This function is called every second to perform time-based operations.
	 *
	 * @note Ensure that this function is called precisely every second to maintain timing accuracy.
	 */
	void handle_1s_tick();
    
	/**!
	 * @brief Handles the 500ms tick event.
	 *
	 * This function is called every 500 milliseconds to perform periodic tasks.
	 *
	 * @note Ensure that this function is called at the correct interval to maintain system timing.
	 */
	void handle_500ms_tick();

    
	/**!
	 * @brief Handles a bus event.
	 *
	 * This function processes the bus event passed to it.
	 *
	 * @param[in] evt Pointer to the bus event structure.
	 *
	 * @note Ensure that the event structure is properly initialized before passing it to this function.
	 */
	void handle_bus_event(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the action frame received.
	 *
	 * This function processes the action frame provided in the form of an
	 * ieee80211_mgmt structure.
	 *
	 * @param[in] frame Pointer to the ieee80211_mgmt structure containing
	 * the action frame to be handled.
	 *
	 * @note Ensure that the frame is properly initialized before passing
	 * it to this function.
	 */
	void handle_action_frame(struct ieee80211_mgmt *frame);
    
	/**!
	 * @brief Handles a public action frame.
	 *
	 * This function processes the given IEEE 802.11 management frame.
	 *
	 * @param[in] frame Pointer to the IEEE 802.11 management frame structure.
	 *
	 * @note Ensure that the frame is properly initialized before calling this function.
	 */
	void handle_public_action_frame(struct ieee80211_mgmt *frame);
    
	/**!
	 * @brief Handles the vendor public action frame.
	 *
	 * This function processes the vendor-specific public action frame received in the IEEE 802.11 management frame.
	 *
	 * @param[in] frame Pointer to the IEEE 802.11 management frame structure.
	 *
	 * @note Ensure that the frame is properly validated before calling this function.
	 */
	void handle_vendor_public_action_frame(struct ieee80211_mgmt *frame);
    
	/**!
	 * @brief Handles the BTM request action frame.
	 *
	 * This function processes the BTM (BSS Transition Management) request action frame
	 * received via the event bus.
	 *
	 * @param[in] evt Pointer to the event structure containing the BTM request action frame.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_btm_request_action_frame(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the reception of WFA action frames.
	 *
	 * This function processes the received WFA action frames and performs necessary actions based on the event data.
	 *
	 * @param[in] evt Pointer to the em_bus_event_t structure containing event data.
	 *
	 * @note Ensure that the evt parameter is properly initialized before calling this function.
	 */
	void handle_recv_wfa_action_frame(em_bus_event_t *evt);

	/**
	 * @brief Handles the reception of BSS info reports from OneWifi
	 * 
	 * Used for DPP for building the Enrollee's channel list for Reconfiguration Announcement
	 * 
	 * @param event The event containing the `bss_info_t` including an SSID which the Enrollee will check
	 * to conditionally include the channel (frequency) that the SSID was heard on in its
	 * Reconfiguration Announcement channel list
	 */
	void handle_bss_info(em_bus_event_t *event);

	/**
	 * @brief Handles the reception of association status of a STA
	 * 
	 * @param event The event containing the `rdk_sta_data_t` info which includes the association status along with other information
	 */
	void handle_recv_assoc_status(em_bus_event_t *event);
    
	/**!
	 * @brief Handles the BTM response action frame.
	 *
	 * This function processes the BTM (BSS Transition Management) response action frame
	 * received in the event.
	 *
	 * @param[in] evt Pointer to the em_bus_event_t structure containing the event data.
	 *
	 * @note Ensure that the evt parameter is not null before calling this function.
	 */
	void handle_btm_response_action_frame(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the result of a channel scan.
	 *
	 * This function processes the event data received from a channel scan.
	 *
	 * @param[in] evt Pointer to the event data structure containing scan results.
	 *
	 * @note Ensure that the event data is valid before calling this function.
	 */
	void handle_channel_scan_result(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the channel scan parameters.
	 *
	 * This function processes the event related to channel scan parameters.
	 *
	 * @param[in] evt Pointer to the event structure containing channel scan parameters.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_channel_scan_params(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the setting of policy based on the event received.
	 *
	 * This function processes the event and applies the necessary policy changes.
	 *
	 * @param[in] evt Pointer to the event structure containing policy details.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_set_policy(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the beacon report event.
	 *
	 * This function processes the beacon report event received from the event bus.
	 *
	 * @param[in] evt Pointer to the event structure containing the beacon report data.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_beacon_report(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the reception of a GAS frame.
	 *
	 * This function processes the received GAS frame and performs necessary actions
	 * based on the event data provided.
	 *
	 * @param[in] evt Pointer to the em_bus_event_t structure containing event data.
	 *
	 * @note Ensure that the evt parameter is properly initialized before calling this function.
	 */
	void handle_recv_gas_frame(em_bus_event_t *evt);

	/**!
	 * @brief Handles the AP Metrics report event.
	 *
	 * This function processes the AP Metrics report event received from the event bus.
	 *
	 * @param[in] evt Pointer to the event structure containing the AP Metrics report data.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_ap_metrics_report(em_bus_event_t *evt);

public:

    bus_handle_t m_bus_hdl;
    bool do_start_dpp_onboarding = false;
    bool do_regen_dpp_uri = false;

	/**!
	 * @brief Listens for input events and processes them accordingly.
	 *
	 * This function is responsible for handling input events from various sources
	 * and triggering the appropriate actions based on the input received.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void input_listener();

    
	/**
	 * @brief Refresh the OneWifi subdoc with current information + provided data and send to OneWifi.
	 *
	 * This function updates the OneWifi subdoc using the current system information combined with the provided data.
	 * It then sends the updated subdoc to the OneWifi service.
	 *
	 * @param[in] log_name The string to use when logging.
	 * @param[in] type The subdoc type.
	 *
	 * @return int Returns 1 if successful, 0 if encode fails, -1 if send fails, -2 if unimplemented.
	 *
	 * @note Ensure that the subdoc type is valid and supported before calling this function.
	 */
	int refresh_onewifi_subdoc(const char *log_name, const webconfig_subdoc_type_t type) override;

    
	/**
	 * @brief Send an action frame
	 *
	 * This function sends an action frame to a specified destination MAC address.
	 *
	 * @param[in] dest_mac The destination MAC address.
	 * @param[in] action_frame The action frame to send.
	 * @param[in] action_frame_len The length of the action frame.
	 * @param[in] frequency The frequency to send the frame on (0 for current frequency).
	 * @param[in] wait_time_ms The time to dwell on the frequency before switching back to the original frequency (0 for no wait).
	 *
	 * @return true if the action frame was sent successfully, false otherwise.
	 */
	bool send_action_frame(uint8_t dest_mac[ETH_ALEN], uint8_t *action_frame, size_t action_frame_len, unsigned int frequency=0, unsigned int wait_time_ms=0) override;


	/**
	 * @brief Set the disconnected steady state.
	 * 
	 * This function temporarily interupts the disconnected-scanning state machine in OneWifi
	 * and sets the device to an unstable steady state, stopping the constant scanning process
	 * 
	 * @note This only works when OneWifi is in a `disconnected*` state
	 */
	bool set_disconnected_steady_state() override;

	/**
	 * @brief Set the disconnected scan none state (the initial state of the disconnected-scanning state machine).
	 * 
	 * This function returns from the disconnected-steady state to the disconnected-scanning state machine.
	 * 
	 * @note This only works when OneWifi is in the disconnected steady state.
	 */
	bool set_disconnected_scan_none_state() override;

	/**
	 * @brief Send a scan request to OneWifi
	 *
	 * This function sends a scan request with the specified parameters to the mesh.
	 *
	 * @param[in] scan_params Pointer to the scan parameters structure.
	 * @param[in] perform_fresh_scan If true, performs a fresh scan; otherwise, uses cached results.
	 * @param[in] is_sta_vap If true, performs a `wifi_hal_startScan` (STA compatable), 
	 * 								  otherwise, performs a `wifi_hal_startNeighborScan` (not STA compatible)
	 * @return true if the scan request was sent successfully, false otherwise.
	 */
	bool send_scan_request(em_scan_params_t* scan_params, bool perform_fresh_scan, bool is_sta_vap = false) override;

    
	/**
	 * @brief Callback to determine if the mesh is capable of supporting additional onboarded APs.
	 *
	 * Spec does not determine what the threshold for onboarding more APs is, so this is vendor/deployment specific.
	 *
	 * @return true if the mesh can support an additional AP, otherwise false.
	 */
	bool can_onboard_additional_aps();

    
	/**
	 * @brief Try to create a default EasymeshCfg.json file if one does not exist.
	 *
	 * A default EasymeshCfg.json file only contains the `AL_MAC_ADDR` and `Colocated_mode` fields.
	 *
	 * @param[in] interface The interface to use for filling the `AL_MAC_ADDR` field.
	 *
	 * @return true if successful or if the file already exists, false otherwise.
	 */
	bool try_create_default_em_cfg(std::string interface);

    
	/**!
	* @brief Attempts to start DPP onboarding process.
	*
	* This function tries to initiate the Device Provisioning Protocol (DPP) onboarding.
	* It returns a boolean indicating the success or failure of the operation.
	*
	* @returns True if the DPP onboarding process starts successfully, false otherwise.
	*/
	bool try_start_dpp_onboarding();

    
	/**!
	 * @brief Initializes the data model with the specified path.
	 *
	 * This function sets up the data model using the provided file path.
	 *
	 * @param[in] data_model_path The path to the data model file.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure the file path is valid and accessible.
	 */
	int data_model_init(const char *data_model_path);
    
	/**!
	* @brief Checks if the data model is initialized.
	*
	* @returns True if the data model is initialized, otherwise false.
	*/
	bool is_data_model_initialized() { return true; }

    
	/**!
	 * @brief Initializes the orchestration module.
	 *
	 * This function sets up the necessary components for the orchestration module to function properly.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that all dependencies are initialized before calling this function.
	 */
	int orch_init();

    
	/**!
	 * @brief Handles the timeout event.
	 *
	 * This function is called when a timeout occurs.
	 *
	 * @note Ensure that the timeout duration is correctly set before calling this function.
	 */
	void handle_timeout();
    
	/**!
	 * @brief Handles an event.
	 *
	 * This function processes the given event and performs the necessary actions.
	 *
	 * @param[in] evt Pointer to the event to be handled.
	 *
	 * @note Ensure that the event pointer is not null before calling this function.
	 */
	void handle_event(em_event_t *evt);
    
	/**!
	 * @brief Handles a frame event.
	 *
	 * This function processes the given frame event and performs necessary actions.
	 *
	 * @param[in] evt Pointer to the frame event structure that needs to be handled.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_frame_event(em_frame_event_t *evt);

    
	/**!
	 * @brief Handles the initialization of the device.
	 *
	 * This function processes the device initialization event.
	 *
	 * @param[in] evt Pointer to the event structure containing initialization details.
	 *
	 * @note Ensure that the event structure is properly populated before calling this function.
	 */
	void handle_dev_init(em_bus_event_t *evt);  
    
	/**!
	 * @brief Handles the radio configuration event.
	 *
	 * This function processes the radio configuration event received from the event bus.
	 *
	 * @param[in] evt Pointer to the event structure containing radio configuration details.
	 *
	 * @note Ensure that the event structure is properly initialized before passing it to this function.
	 */
	void handle_radio_config(em_bus_event_t *evt);  
    
	/**!
	 * @brief Handles the VAP configuration event.
	 *
	 * This function processes the VAP configuration event received from the bus.
	 *
	 * @param[in] evt Pointer to the event structure containing VAP configuration details.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_vap_config(em_bus_event_t *evt);    
    
	/**!
	 * @brief Handles the station list event.
	 *
	 * This function processes the event related to the station list.
	 *
	 * @param[in] evt Pointer to the event structure containing station list information.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_sta_list(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the access point capability query event.
	 *
	 * This function processes the event related to access point capability queries.
	 *
	 * @param[in] evt Pointer to the event structure containing the access point capability query details.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_ap_cap_query(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the auto-configuration renewal process.
	 *
	 * This function is responsible for processing the auto-configuration renewal event.
	 *
	 * @param[in] evt Pointer to the event structure containing the auto-configuration renewal details.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_autoconfig_renew(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the client capability query event.
	 *
	 * This function processes the client capability query event received
	 * through the event bus and performs necessary actions based on the
	 * event data.
	 *
	 * @param[in] evt Pointer to the event structure containing the client
	 * capability query details.
	 *
	 * @note Ensure that the event structure is properly initialized before
	 * calling this function.
	 */
	void handle_client_cap_query(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the OneWiFi private subdocument event.
	 *
	 * This function processes the event related to the OneWiFi private subdocument.
	 *
	 * @param[in] evt Pointer to the event structure containing the OneWiFi private subdocument data.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_onewifi_private_subdoc(em_bus_event_t *evt);
	
	/**!
	 * @brief Handles the private callback for OneWiFi events.
	 *
	 * This function processes the event received from the OneWiFi bus and performs necessary actions.
	 *
	 * @param[in] evt Pointer to the event structure containing OneWiFi event data.
	 *
	 * @note Ensure that the event structure is properly initialized before passing it to this function.
	 */
	void handle_onewifi_private_cb(em_bus_event_t *evt);

	/**!
	 * @brief Handles the mesh station callback for OneWiFi events.
	 *
	 * This function processes the event received from the OneWiFi bus and performs necessary actions.
	 *
	 * @param[in] evt Pointer to the event structure containing OneWiFi event data.
	 *
	 * @note Ensure that the event structure is properly initialized before passing it to this function.
	 */
	void handle_onewifi_mesh_sta_cb(em_bus_event_t *evt);
	
	/**!
	 * @brief Handles the OneWiFi radio callback event.
	 *
	 * This function processes the event received from the OneWiFi radio.
	 *
	 * @param[in] evt Pointer to the event structure containing the radio event data.
	 *
	 * @note Ensure that the event structure is properly initialized before passing it to this function.
	 */
	void handle_onewifi_radio_cb(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the M2 control configuration event.
	 *
	 * This function processes the M2 control configuration event received
	 * through the event bus and applies the necessary configuration changes.
	 *
	 * @param[in] evt Pointer to the event structure containing the M2 control
	 * configuration details.
	 *
	 * @note Ensure that the event structure is properly initialized before
	 * calling this function.
	 */
	void handle_m2ctrl_configuration(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the channel preference query event.
	 *
	 * This function processes the channel preference query event received from the event bus.
	 *
	 * @param[in] evt Pointer to the event structure containing channel preference query details.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_channel_pref_query(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the channel selection request event.
	 *
	 * This function processes the channel selection request event received
	 * from the event bus and performs necessary actions to handle the request.
	 *
	 * @param[in] evt Pointer to the event structure containing the channel
	 * selection request details.
	 *
	 * @note Ensure that the event structure is properly initialized before
	 * calling this function.
	 */
	void handle_channel_sel_req(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the station link metrics event.
	 *
	 * This function processes the event related to station link metrics.
	 *
	 * @param[in] evt Pointer to the event structure containing station link metrics.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_sta_link_metrics(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the steering station event.
	 *
	 * This function processes the steering station event received from the bus.
	 *
	 * @param[in] evt Pointer to the event structure containing the steering station event data.
	 *
	 * @note Ensure that the event data is valid before calling this function.
	 */
	void handle_steer_sta(em_bus_event_t *evt);

    
	/**!
	 * @brief Retrieves the command associated with the given input.
	 *
	 * @param[in] in A pointer to a character array representing the input command.
	 *
	 * @returns A reference to an em_cmd_t object corresponding to the input command.
	 *
	 * @note Ensure that the input is valid and properly formatted to avoid unexpected behavior.
	 */
	em_cmd_t& get_command(char *in);
    
    
	/**!
	 * @brief Retrieves the data model for a given network ID.
	 *
	 * This function returns a pointer to the data model associated with the specified network ID.
	 * If an AL MAC address is provided, it may be used to refine the selection.
	 *
	 * @param[in] net_id The network ID for which the data model is requested.
	 * @param[in] al_mac Optional AL MAC address to refine the data model selection.
	 *
	 * @returns A pointer to the data model associated with the given network ID.
	 *
	 * @note If no AL MAC address is provided, the default data model is returned.
	 */
	dm_easy_mesh_t *get_data_model(const char *net_id, const unsigned char *al_mac = NULL) { return &m_data_model; }
    
	/**!
	 * @brief Creates a data model for the specified network ID and interface.
	 *
	 * This function initializes a data model using the provided network ID,
	 * interface, and profile type.
	 *
	 * @param[in] net_id The network identifier.
	 * @param[in] al_intf Pointer to the interface structure.
	 * @param[in] profile The profile type to be used (default is em_profile_type_3).
	 *
	 * @returns Pointer to the initialized data model.
	 */
	dm_easy_mesh_t *create_data_model(const char *net_id, const em_interface_t *al_intf, em_profile_type_t profile = em_profile_type_3) { return &m_data_model; }
    
	/**!
	 * @brief Deletes a data model associated with a given network ID and AL MAC address.
	 *
	 * This function removes the data model identified by the specified network ID and AL MAC address.
	 *
	 * @param[in] net_id The network identifier for which the data model is to be deleted.
	 * @param[in] al_mac The AL MAC address associated with the data model.
	 *
	 * @note Ensure that the network ID and AL MAC address are valid and correspond to an existing data model.
	 */
	void delete_data_model(const char *net_id, const unsigned char *al_mac) { }
    
	/**!
	 * @brief Deletes all data models.
	 *
	 * This function is responsible for removing all data models from the system.
	 *
	 * @note Ensure that no data models are in use before calling this function.
	 */
	void delete_all_data_models() { }
    
	/**!
	 * @brief Updates the tables with the provided EasyMesh data.
	 *
	 * This function takes a pointer to a dm_easy_mesh_t structure and updates
	 * the relevant tables accordingly.
	 *
	 * @param[in] dm Pointer to a dm_easy_mesh_t structure containing EasyMesh data.
	 *
	 * @returns int Status code of the update operation.
	 * @retval 0 on success.
	 *
	 * @note Ensure that the dm pointer is valid and properly initialized before calling this function.
	 */
	int update_tables(dm_easy_mesh_t *dm) { return 0; }
    
	/**!
	 * @brief Loads the network SSID table.
	 *
	 * This function initializes and loads the network SSID table.
	 *
	 * @returns int
	 * @retval 0 on success
	 *
	 * @note This function currently returns a fixed value of 0.
	 */
	int load_net_ssid_table() { return 0; }
    
	/**!
	 * @brief Debug probe function.
	 *
	 * This function is used to initiate a debug probe.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void debug_probe() { }

    
	/**!
	 * @brief Retrieves the service type for the agent.
	 *
	 * @returns The service type of the agent.
	 * @retval em_service_type_agent The service type is agent.
	 */
	em_service_type_t get_service_type() { return em_service_type_agent; }
    
	/**!
	 * @brief Finds the EM for a given message type.
	 *
	 * This function searches for the EM (Event Manager) associated with a specific message type
	 * based on the provided data and length.
	 *
	 * @param[in] data Pointer to the data buffer containing the message.
	 * @param[in] len Length of the data buffer.
	 * @param[in] al_em Pointer to the alternative EM to be used if no match is found.
	 *
	 * @returns Pointer to the found EM if successful, or the alternative EM if no match is found.
	 *
	 * @note Ensure that the data buffer is valid and the length is correctly specified.
	 */
	em_t *find_em_for_msg_type(unsigned char *data, unsigned int len, em_t *al_em);

    
	/**!
	 * @brief Callback function for handling station events.
	 *
	 * This function is triggered when a station event occurs, providing the event name and associated data.
	 *
	 * @param[in] event_name Name of the event that occurred.
	 * @param[in] data Pointer to the raw data associated with the event.
	 * @param[in] userData User-defined data passed to the callback.
	 *
	 * @note Ensure that the `event_name` and `data` are valid before processing.
	 */
	static void sta_cb(char *event_name, raw_data_t *data, void *userData);
    
	/**!
	 * @brief Callback function for handling WiFi events.
	 *
	 * This function is triggered when a WiFi event occurs, processing the event
	 * and associated data.
	 *
	 * @param[in] event_name Name of the WiFi event.
	 * @param[in] data Pointer to the raw data associated with the event.
	 * @param[in] userData User-defined data passed to the callback.
	 *
	 * @note Ensure that the data pointer is valid and properly initialized before
	 * passing it to this function.
	 */
	static void onewifi_cb(char *event_name, raw_data_t *data, void *userData);
    
	/**!
	 * @brief Callback function for association statistics.
	 *
	 * This function is triggered when association statistics are available.
	 *
	 * @param[in] event_name Name of the event triggering the callback.
	 * @param[in] data Pointer to the raw data structure containing statistics.
	 * @param[in] userData User-defined data passed to the callback.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the data pointer is valid before calling this function.
	 */
	static int assoc_stats_cb(char *event_name, raw_data_t *data, void *userData);
    
	/**!
	 * @brief Callback function for management action frames.
	 *
	 * This function is triggered when a management action frame event occurs.
	 *
	 * @param[in] event_name The name of the event that triggered the callback.
	 * @param[in] data Pointer to the raw data associated with the event.
	 * @param[in] userData User-defined data passed to the callback function.
	 *
	 * @returns int Status code indicating the success or failure of the callback execution.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the data pointer is valid and points to the correct data structure.
	 */
	static int mgmt_action_frame_cb(char *event_name, raw_data_t *data, void *userData);
    
	/**!
	 * @brief Callback function for channel scanning.
	 *
	 * This function is triggered when a channel scan event occurs.
	 *
	 * @param[in] event_name Name of the event that triggered the callback.
	 * @param[in] data Pointer to the raw data associated with the event.
	 * @param[in] userData User-defined data passed to the callback.
	 *
	 * @returns int Status code indicating the result of the callback execution.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the event_name and data are valid before processing.
	 */
	static int channel_scan_cb(char *event_name, raw_data_t *data, void *userData);
    
	/**!
	 * @brief Callback function for handling beacon reports.
	 *
	 * This function is triggered when a beacon report event occurs.
	 *
	 * @param[in] event_name The name of the event that triggered the callback.
	 * @param[in] data Pointer to the raw data associated with the beacon report.
	 * @param[in] userData User-defined data passed to the callback function.
	 *
	 * @returns int Status code indicating the success or failure of the callback execution.
	 * @retval 0 Success.
	 * @retval -1 Failure.
	 *
	 * @note Ensure that the data pointer is valid before accessing its contents.
	 */
	static int beacon_report_cb(char *event_name, raw_data_t *data, void *userData);

	/**
	 * @brief Callback for association status event
	 * 
	 * @param event_name The name of the event
	 * @param data The raw event data
	 * @param userData Optional user-provided callback data
	 * @return int 1 on success, otherwise -1
	 */
	static int association_status_cb(char *event_name, raw_data_t *data, void *userData);

	/**
	 * @brief Callback for BSS scan events
	 * 
	 * @param event_name The name of the event
	 * @param data The raw event data
	 * @param userData Optional user-provided callback data
	 * @return int 1 on success, otherwise -1
	 */
	static int bss_info_cb(char *event_name, raw_data_t *data, void *userData);

	/**!
	 * @brief Callback function for handling AP Metrics reports.
	 *
	 * This function is triggered when an AP Metrics report event occurs.
	 *
	 * @param[in] event_name The name of the event that triggered the callback.
	 * @param[in] data Pointer to the raw data associated with the AP Metrics report.
	 * @param[in] userData User-defined data passed to the callback function.
	 *
	 * @returns int Status code indicating the success or failure of the callback execution.
	 * @retval 0 Success.
	 * @retval -1 Failure.
	 *
	 * @note Ensure that the data pointer is valid before accessing its contents.
	 */
	static int ap_metrics_report_cb(char *event_name, raw_data_t *data, void *userData);
    
	/**!
	 * @brief Retrieves the associated data for the given input.
	 *
	 * @param[in] input A pointer to the input data for which the associated data is to be retrieved.
	 *
	 * @returns A pointer to the associated data.
	 *
	 * @note Ensure that the input pointer is valid and points to the correct data structure.
	 */
	void *get_assoc(void*);
    
	/**!
	 * @brief 
	 *
	 * This function handles input/output operations.
	 *
	 * @param[in,out] data Pointer to the data to be processed.
	 * @param[in] input Boolean flag indicating the operation mode. True for input, false for output.
	 *
	 * @note Ensure that the data pointer is valid and points to a sufficient memory block.
	 */
	void io(void *data, bool input = true);
    
	/**!
	 * @brief Outputs data from the agent.
	 *
	 * This function processes the given data and outputs it according to the agent's specifications.
	 *
	 * @param[in] data Pointer to the data to be processed and output.
	 *
	 * @returns True if the operation is successful, false otherwise.
	 */
	bool agent_output(void *data);

#ifdef AL_SAP
    
	/**!
	 * @brief Registers a new service access point.
	 *
	 * This function is responsible for creating and registering a new
	 * AlServiceAccessPoint instance.
	 *
	 * @returns A pointer to the newly created AlServiceAccessPoint instance.
	 * @retval nullptr If the registration fails.
	 *
	 * @note Ensure that the returned pointer is properly managed to avoid memory leaks.
	 */
	AlServiceAccessPoint* al_sap_register();
#endif

    
	/**!
	 * @brief Constructor for em_agent_t class.
	 *
	 * This constructor initializes an instance of the em_agent_t class.
	 *
	 * @note Ensure that all necessary resources are available before instantiation.
	 */
	em_agent_t();
    
	/**!
	 * @brief Destructor for the em_agent_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the em_agent_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	~em_agent_t();

};

#endif

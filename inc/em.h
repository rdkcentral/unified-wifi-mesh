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

#ifndef EM_H
#define EM_H

#include "collection.h"
#include "em_base.h"
#include "em_crypto.h"
#include "em_configuration.h"
#include "em_discovery.h"
#include "em_provisioning.h"
#include "em_channel.h"
#include "em_capability.h"
#include "em_metrics.h"
#include "em_steering.h"
#include "em_policy_cfg.h"
#include "dm_easy_mesh.h"
#include "em_sm.h"

#include "util.h"

#include <set>
#include <string>

class em_mgr_t;

class em_t : 
    public em_configuration_t, public em_discovery_t, 
    public em_provisioning_t, public em_channel_t,
    public em_capability_t, public em_metrics_t,
    public em_steering_t, public em_policy_cfg_t  {
    
    dm_easy_mesh_t*  m_data_model;
	em_mgr_t	*m_mgr;

    em_orch_state_t m_orch_state;
    em_cmd_t *m_cmd;
    em_sm_t  m_sm;
	em_service_type_t   m_service_type;
    int m_fd;
    em_interface_t  m_ruid;
    em_freq_band_t  m_band;
    em_profile_type_t   m_profile_type;
    em_queue_t  m_iq;
    pthread_t   m_tid;
    bool    m_exit;
    bool m_is_al_em;
    bool dev_test_enable;
	
	/**
	 * @brief Set of hashed messages that have been sent in co-located systems
	 * 
	 * This set is used to track the messages that have been sent 
	 * to avoid recieving the same message that was sent by another co-located 1905 object.
	 * 
	 * For example: {Controller} -> {Controller, Co-located Agent}, or 
	 * 				{Co-located Agent} -> {Controller, Co-located Agent})
	 * 
	 * This occurs because both the Controller and the Co-located Agent have the same AL-mac, 
	 * resulting in them both recieving the messages they sent each other when infact, it should be:
	 * 
	 * {Controller} -> {Co-located Agent} and
	 * {Co-located Agent} -> {Controller}
	 */
	std::set<std::string> m_coloc_sent_hashed_msgs;

    
	/**!
	 * @brief Executes the protocol run sequence.
	 *
	 * This function initiates the protocol run, setting up necessary
	 * configurations and starting the process.
	 *
	 * @note Ensure that all preconditions are met before calling this function.
	 */
	void proto_run();
    
	/**!
	 * @brief Exits the protocol.
	 *
	 * This function is responsible for terminating the protocol operations
	 * and performing necessary cleanup.
	 *
	 * @note Ensure that all protocol operations are completed before calling this function.
	 */
	void proto_exit();
    
	/**!
	 * @brief Processes the protocol data.
	 *
	 * This function processes the given protocol data of specified length.
	 *
	 * @param[in] data Pointer to the data to be processed.
	 * @param[in] len Length of the data to be processed.
	 *
	 * @note Ensure that the data pointer is valid and the length is correct.
	 */
	void proto_process(unsigned char *data, unsigned int len);
    
	/**!
	 * @brief Handles the protocol timeout event.
	 *
	 * This function is called when a protocol operation exceeds the allowed time limit.
	 * It ensures that the system can recover or retry the operation as necessary.
	 *
	 * @note This function does not take any parameters and does not return a value.
	 */
	void proto_timeout();

    // em socket read and write
    
	/**!
	 * @brief Creates a raw header in the provided buffer.
	 *
	 * This function initializes a raw header in the buffer provided by the caller.
	 *
	 * @param[out] buff Pointer to the buffer where the raw header will be created.
	 * @param[in] len The length of the buffer.
	 *
	 * @note Ensure that the buffer is large enough to hold the header.
	 */
	void create_raw_header(unsigned char *buff, unsigned int len);
    
	/**!
	 * @brief Sets the BP filter.
	 *
	 * This function configures the BP filter settings.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure the filter parameters are correctly set before calling this function.
	 */
	int set_bp_filter();
    
	/**!
	 * @brief Starts the AL interface.
	 *
	 * This function initializes and starts the AL interface, preparing it for use.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the necessary configurations are set before calling this function.
	 */
	int start_al_interface();
    
	/**!
	 * @brief Sends a frame of data.
	 *
	 * This function is responsible for sending a frame of data over the network. It can send the data as a multicast if specified.
	 *
	 * @param[in] buff Pointer to the buffer containing the data to be sent.
	 * @param[in] len Length of the data in the buffer.
	 * @param[in] multicast Boolean flag indicating whether to send the data as multicast. Defaults to false.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified to avoid buffer overflow.
	 */
	int send_frame(unsigned char *buff, unsigned int len, bool multicast = false);
    
	/**!
	 * @brief Sends a command to the specified service type.
	 *
	 * This function is responsible for sending a command of a given type to a specified service.
	 *
	 * @param[in] type The type of command to be sent.
	 * @param[in] svc The service type to which the command is directed.
	 * @param[in] buff Pointer to the buffer containing the command data.
	 * @param[in] len The length of the command data in the buffer.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified to avoid buffer overflow.
	 */
	int send_cmd(em_cmd_type_t type, em_service_type_t svc, unsigned char *buff, unsigned int len);
	
	/**!
	 * @brief Push an event onto the event queue.
	 *
	 * This function takes an event of type `em_event_t` and pushes it onto the event queue for processing.
	 *
	 * @param[in] evt Pointer to the event to be pushed onto the queue.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the event pointer is not null before calling this function.
	 */
	int push_event(em_event_t *evt);


public:
    
	/**!
	 * @brief Initializes the system or component.
	 *
	 * This function sets up necessary configurations and prepares the system for operation.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that all dependencies are met before calling this function.
	 */
	int init();
    
	/**!
	 * @brief Deinitializes the module.
	 *
	 * This function is responsible for cleaning up resources and
	 * performing any necessary shutdown procedures for the module.
	 *
	 * @note Ensure that all operations using the module are complete
	 * before calling this function.
	 */
	void deinit();
    
	/**!
	 * @brief Stops the current process by calling the proto_exit function.
	 *
	 * This function is responsible for terminating the current protocol operation.
	 *
	 * @note Ensure that all necessary cleanup operations are performed before calling this function.
	 */
	void stop() { proto_exit(); }
    
	/**!
	 * @brief Handles the timeout event.
	 *
	 * This function is called when a timeout occurs.
	 *
	 * @note Ensure that the timeout duration is set correctly before calling this function.
	 */
	void handle_timeout();
    
	/**!
	 * @brief Handles the state of the agent.
	 *
	 * This function is responsible for managing the current state of the agent
	 * and performing necessary actions based on the state transitions.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void handle_agent_state();
    
	/**!
	 * @brief Handles the control state.
	 *
	 * This function is responsible for managing the control state of the system.
	 *
	 * @note Ensure that the system is initialized before calling this function.
	 */
	void handle_ctrl_state();

    
	/**!
	 * @brief Checks if the interface is an AL EM.
	 *
	 * @returns True if the interface is an AL EM, false otherwise.
	 */
	bool is_al_interface_em() { return m_is_al_em; }
    
	/**!
	 * @brief Checks if the given SSID is a candidate.
	 *
	 * This function determines if the provided network SSID is a candidate
	 * based on the current interface state.
	 *
	 * @param[in] net_ssid Pointer to the network SSID structure to be checked.
	 *
	 * @returns True if the SSID is a candidate, false otherwise.
	 *
	 * @note The function returns false if the interface is in AL mode.
	 */
	bool is_set_ssid_candidate(dm_network_ssid_t *net_ssid) { return (is_al_interface_em() == true) ? false:true; }
    
	/**!
	 * @brief Checks if the current device is a test candidate.
	 *
	 * This function determines whether the device is suitable for testing
	 * by evaluating the AL interface.
	 *
	 * @returns True if the device is a test candidate, false otherwise.
	 */
	bool is_dev_test_candidate() { return is_al_interface_em(); }
    
	/**!
	 * @brief Determines if the given DPP candidate is a start candidate.
	 *
	 * This function checks if the DPP candidate can be considered as a start candidate
	 * based on the AL interface status.
	 *
	 * @param[in] dpp Pointer to the DPP candidate structure.
	 *
	 * @returns True if the DPP candidate is a start candidate, false otherwise.
	 *
	 * @note The function returns false if the AL interface is active.
	 */
	bool is_start_dpp_candidate(dm_dpp_t *dpp) { return (is_al_interface_em() == true) ? false:true; }
    
	/**!
	 * @brief Checks if the device initialization has started.
	 *
	 * This function determines whether the device initialization process has started
	 * by evaluating the status of the AL interface.
	 *
	 * @param[in] radio A pointer to the dm_radio_t structure representing the radio device.
	 *
	 * @returns A boolean value indicating the initialization status.
	 * @retval true If the device initialization has not started.
	 * @retval false If the device initialization has started.
	 *
	 * @note This function relies on the status of the AL interface to determine the initialization state.
	 */
	bool is_start_dev_init(dm_radio_t *radio) { return (is_al_interface_em() == true) ? false:true; }
    
	/**!
	 * @brief Checks if the current configuration is a candidate for renewal.
	 *
	 * This function determines if the current transmission configuration
	 * should be considered for renewal based on the AL interface.
	 *
	 * @returns True if the configuration is a renewal candidate, false otherwise.
	 */
	bool is_tx_cfg_renew_candidate() { return is_al_interface_em(); }
    
	/**!
	 * @brief Checks if the current configuration is a candidate for renewal.
	 *
	 * This function evaluates the current state of the state machine to determine
	 * if the configuration is misconfigured and thus a candidate for renewal.
	 *
	 * @returns True if the configuration is a renewal candidate, false otherwise.
	 */
	bool is_cfg_renew_candidate() { return (m_sm.get_state() == em_state_ctrl_misconfigured) ? true:false;; }
	
	/**!
	 * @brief Checks if the given MAC address is a candidate for device initialization.
	 *
	 * Compares the provided MAC address with the radio interface MAC address to determine if they match.
	 *
	 * @param[in] mac Pointer to the MAC address to be checked.
	 *
	 * @returns true if the MAC address matches the radio interface MAC address, false otherwise.
	 */
	bool is_dev_init_candidate(unsigned char *mac) { return (memcmp(mac, get_radio_interface_mac(), sizeof(mac_address_t)) == 0); }
    
	/**!
	 * @brief Checks if the given frequency bands are candidates for auto-configuration renewal.
	 *
	 * This function compares two frequency bands and determines if they are the same,
	 * indicating that they are candidates for auto-configuration renewal.
	 *
	 * @param[in] radio_freq_band The frequency band of the radio.
	 * @param[in] em_freq_band The frequency band to compare against.
	 *
	 * @returns true if the frequency bands are the same, false otherwise.
	 */
	bool is_autoconfig_renew_candidate(em_freq_band_t radio_freq_band , em_freq_band_t em_freq_band) { return (radio_freq_band == em_freq_band) ? true:false;}
    
	/**!
	 * @brief Checks if the given frequency band matches a specific criterion.
	 *
	 * This function evaluates the provided frequency band and determines if it matches
	 * a predefined set of criteria or conditions.
	 *
	 * @param[in] band Pointer to the frequency band structure to be evaluated.
	 *
	 * @returns True if the frequency band matches the criteria, false otherwise.
	 *
	 * @note Ensure that the `band` pointer is not null before calling this function.
	 */
	bool is_matching_freq_band(em_freq_band_t *band);
    
	/**!
	 * @brief Sets the AL type for the EM.
	 *
	 * This function assigns the AL type based on the provided boolean value.
	 *
	 * @param[in] is_al_mac Boolean value indicating the AL type.
	 *
	 * @note This function directly modifies the member variable m_is_al_em.
	 */
	void set_al_type(bool is_al_mac) {m_is_al_em = is_al_mac;}

    
	/**
	 * @brief Set the CCE IEs in the beacon and probe response frames.
	 *
	 * This function enables or disables the inclusion of CCE IEs in the beacon and probe response frames.
	 *
	 * @param[in] enable A boolean value indicating whether to enable or disable the inclusion of CCE IEs.
	 * @return true if the operation is successful, false otherwise.
	 *
	 * @note If the operation fails, all CCE IEs are removed before the function exits.
	 */
	bool toggle_cce(bool enable);

	/**
	 * @brief Attempts a connection between the backhaul STA to the specified BSS.
	 * 
	 * @param[in] ssid The SSID of the BSS to connect to.
	 * @param[in] passphrase The passphrase for the BSS.
	 * @param[in] bssid The BSSID of the BSS to connect to.
	 * 
	 * @returns true if the attempt at a connection was successful, false otherwise.
	 * 
	 * @note The return value being true only indicates that OneWifi will attempt to connect to the BSS
	 * and does mean that the connection was successful and the bSTA is associated to the BSS.
	 */
	bool bsta_connect_bss(const std::string& ssid, const std::string passphrase, bssid_t bssid);

	/**
	 * @brief Triggers a station scan on all channels
	 * 
	 * @return true if the action was successful, false otherwise.
	 */
	bool trigger_sta_scan();

	/**!
	 * @brief Retrieves the `em_bss_info_t` for the bSTA BSS.
	 *
	 *
	 * @returns A pointer to the em_bss_info_t structure containing BSTA BSS information. NULL if not found.
	 *
	 */
	em_bss_info_t* get_bsta_bss_info();
	
	/**!
	 * @brief Retrieves the manager instance.
	 *
	 * This function returns a pointer to the manager instance.
	 *
	 * @returns A pointer to the manager instance.
	 */
	em_mgr_t *get_mgr() { return m_mgr; }

    
	/**!
	 * @brief Retrieves the EC Manager instance.
	 *
	 * This function returns a reference to the EC Manager, which is responsible for managing
	 * the execution context within the system.
	 *
	 * @returns A reference to the EC Manager instance.
	 *
	 * @note Ensure that the EC Manager has been initialized before calling this function.
	 */
	ec_manager_t& get_ec_mgr();

    
	/**!
	 * @brief Executes the given command.
	 *
	 * This function processes the command pointed to by `pcmd` and performs the necessary operations.
	 *
	 * @param[in] pcmd Pointer to the command structure to be executed.
	 *
	 * @note Ensure that `pcmd` is properly initialized before calling this function.
	 */
	void orch_execute(em_cmd_t *pcmd);
    
	/**!
	 * @brief Retrieves the current orchestration state.
	 *
	 * @returns The current orchestration state as an em_orch_state_t.
	 */
	em_orch_state_t get_orch_state() { return m_orch_state; }
    
	/**!
	 * @brief Sets the state of the orchestrator.
	 *
	 * This function updates the current state of the orchestrator to the specified state.
	 *
	 * @param[in] state The new state to set for the orchestrator.
	 *
	 * @note Ensure that the state provided is valid and within the defined range of em_orch_state_t.
	 */
	void set_orch_state(em_orch_state_t state);
	
	/**!
	 * @brief Clears the command by setting it to NULL.
	 *
	 * This function resets the command to its default state by assigning NULL to it.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void clear_cmd() { m_cmd = NULL; }

    
	/**!
	 * @brief Retrieves the current state of the state machine.
	 *
	 * @returns The current state of the state machine as an em_state_t.
	 */
	em_state_t get_state() { return m_sm.get_state(); }
    
	/**!
	 * @brief Sets the state of the state machine.
	 *
	 * This function updates the state of the state machine to the specified state.
	 *
	 * @param[in] state The new state to set for the state machine.
	 *
	 * @note Ensure that the state provided is valid and within the expected range of states.
	 */
	void set_state(em_state_t state) {  m_sm.set_state(state); }
	
	/**!
	 * @brief Retrieves the service type.
	 *
	 * @returns The current service type.
	 */
	em_service_type_t   get_service_type() { return m_service_type; }
    
	/**!
	 * @brief Retrieves the current profile type.
	 *
	 * @returns The current profile type as an em_profile_type_t.
	 */
	em_profile_type_t   get_profile_type() { return m_profile_type; }
    
	/**!
	 * @brief Sets the profile type.
	 *
	 * This function assigns the given profile type to the member variable.
	 *
	 * @param[in] profile The profile type to be set.
	 *
	 * @note Ensure that the profile type is valid before calling this function.
	 */
	void set_profile_type(em_profile_type_t profile) { m_profile_type = profile; }


    
	/**!
	 * @brief Retrieves the data model instance.
	 *
	 * This function returns a pointer to the current data model instance.
	 *
	 * @returns A pointer to the dm_easy_mesh_t data model instance.
	 *
	 * @note Ensure that the returned pointer is not null before using it.
	 */
	dm_easy_mesh_t *get_data_model() { return m_data_model; }  
    
	/**!
	 * @brief Copies the data model into the member variable.
	 *
	 * @param[in] dm The data model to be copied.
	 */
	void copy_data_model(dm_easy_mesh_t& dm) { *m_data_model = dm; }

    
	/**!
	 * @brief Retrieves the radio data for the specified interface.
	 *
	 * @param[in] radio The interface for which the radio data is requested.
	 *
	 * @returns A pointer to the radio data structure.
	 */
	rdk_wifi_radio_t    *get_radio_data(em_interface_t *radio) { return m_data_model->get_radio_data(radio); };
    
	/**!
	 * @brief Retrieves the radio interface.
	 *
	 * This function returns a pointer to the radio interface structure.
	 *
	 * @returns A pointer to the `em_interface_t` structure representing the radio interface.
	 */
	em_interface_t  *get_radio_interface() { return &m_ruid; }
    
	/**!
	 * @brief Retrieves the MAC address of the radio interface.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 */
	unsigned char   *get_radio_interface_mac() { return m_ruid.mac; }
    
	/**!
	 * @brief Retrieves the name of the radio interface.
	 *
	 * This function returns the name associated with the radio interface.
	 *
	 * @returns A pointer to a character string representing the radio interface name.
	 *
	 * @note The returned string is managed internally and should not be modified or freed by the caller.
	 */
	char *get_radio_interface_name() { return m_ruid.name; }
	
	/**!
	 * @brief Retrieves the radio instance from the device manager.
	 *
	 * This function fetches the radio instance associated with the device manager.
	 * If the command_dm parameter is set to true, it retrieves the command device manager's radio.
	 *
	 * @param[in] command_dm A boolean flag indicating whether to retrieve the command device manager's radio.
	 *
	 * @returns A pointer to the dm_radio_t instance.
	 *
	 * @note Ensure that the device manager is properly initialized before calling this function.
	 */
	dm_radio_t *get_radio_from_dm(bool command_dm = false);

    
	/**!
	 * @brief Retrieves the MAC address of the AL interface.
	 *
	 * Depending on the service type, this function returns the MAC address of either the agent or the controller AL interface.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 *
	 * @note Ensure that the service type is correctly set before calling this function.
	 */
	unsigned char *get_al_interface_mac() { return (m_service_type == em_service_type_agent) ? 
            m_data_model->get_agent_al_interface_mac():m_data_model->get_ctrl_al_interface_mac(); }
    
	/**!
	 * @brief Retrieves the AL interface name.
	 *
	 * This function returns the name of the AL interface used by the agent.
	 *
	 * @returns A pointer to a character string containing the AL interface name.
	 *
	 * @note The returned string is managed by the data model and should not be freed by the caller.
	 */
	char *get_al_interface_name() { return m_data_model->get_agent_al_interface_name(); }
    
	/**!
	 * @brief Retrieves the current command.
	 *
	 * @returns A pointer to the current command.
	 */
	em_cmd_t *get_current_cmd()  { return m_cmd; }    

    
	/**!
	 * @brief Retrieves the crypto object.
	 *
	 * @returns A pointer to the crypto object.
	 */
	em_crypto_t *get_crypto() { return &m_crypto; }
    
	/**!
	 * @brief Retrieves the cryptographic information.
	 *
	 * This function returns a pointer to the cryptographic information structure.
	 *
	 * @returns A pointer to an em_crypto_info_t structure containing the cryptographic information.
	 *
	 * @note Ensure that the returned pointer is not null before using it.
	 */
	em_crypto_info_t    *get_crypto_info() { return m_crypto.get_crypto_info(); }
    
	/**!
	 * @brief Retrieves the IEEE 1905 security information.
	 *
	 * This function returns a pointer to the IEEE 1905 security information
	 * from the data model.
	 *
	 * @returns A pointer to the `em_ieee_1905_security_info_t` structure containing
	 * the security information.
	 *
	 * @note Ensure that the returned pointer is not null before accessing
	 * the security information.
	 */
	em_ieee_1905_security_info_t *get_ieee_1905_security_info() { return m_data_model->get_ieee_1905_security_info(); }
    
	/**!
	 * @brief Retrieves the IEEE 1905 security capabilities.
	 *
	 * This function returns a pointer to the IEEE 1905 security capabilities
	 * structure from the data model.
	 *
	 * @returns A pointer to the `em_ieee_1905_security_cap_t` structure.
	 * @retval nullptr if the security capabilities are not available.
	 *
	 * @note Ensure that the returned pointer is not null before dereferencing.
	 */
	em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() { return m_data_model->get_ieee_1905_security_cap(); }
    
	/**!
	 * @brief Retrieves the device information.
	 *
	 * @returns A pointer to the device information structure.
	 *
	 * @note This function returns the device information from the data model.
	 */
	em_device_info_t    *get_device_info() { return m_data_model->get_device_info(); }

    
	/**!
	 * @brief Retrieves the MAC address of the peer.
	 *
	 * Depending on the service type, this function returns the MAC address of either the agent AL interface or the controller interface.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 *
	 * @note The returned MAC address is dependent on the current service type.
	 */
	unsigned char *get_peer_mac() { return (m_service_type == em_service_type_ctrl) ? m_data_model->get_agent_al_interface_mac():m_data_model->get_controller_interface_mac(); }

    
	/**!
	 * @brief Checks if there is at least one associated STA.
	 *
	 * This function determines whether there is at least one associated
	 * station (STA) in the data model.
	 *
	 * @returns True if there is at least one associated STA, false otherwise.
	 */
	bool has_at_least_one_associated_sta() { return get_data_model()->has_at_least_one_associated_sta(); }
    
	/**!
	 * @brief Finds a station based on its MAC address and BSSID.
	 *
	 * This function searches for a station in the network using the provided
	 * MAC address and BSSID, and returns a pointer to the station information
	 * if found.
	 *
	 * @param[in] sta_mac The MAC address of the station to find.
	 * @param[in] bssid The BSSID of the network to search within.
	 *
	 * @returns A pointer to the station information (dm_sta_t) if the station
	 * is found, or NULL if the station is not found.
	 *
	 * @note Ensure that the MAC address and BSSID are valid and correspond to
	 * the network being queried.
	 */
	dm_sta_t *find_sta(mac_address_t sta_mac, bssid_t bssid);

    
	/**!
	 * @brief Pushes an event to the queue.
	 *
	 * This function takes an event and adds it to the queue for processing.
	 *
	 * @param[in] evt Pointer to the event to be pushed to the queue.
	 *
	 * @note Ensure that the event is properly initialized before calling this function.
	 */
	void push_to_queue(em_event_t *evt);
    
	/**!
	 * @brief Pops an event from the queue.
	 *
	 * This function retrieves and removes the event at the front of the queue.
	 *
	 * @returns A pointer to the event popped from the queue.
	 * @retval NULL if the queue is empty.
	 *
	 * @note Ensure the queue is not empty before calling this function to avoid NULL returns.
	 */
	em_event_t *pop_from_queue();

    
	/**!
	 * @brief Retrieves the file descriptor.
	 *
	 * @returns The file descriptor.
	 */
	int get_fd() { return m_fd; }

    //Msg Construction supporting API
    
	/**!
	 * @brief Creates an AP capability TLV.
	 *
	 * This function is responsible for creating an Access Point (AP) capability
	 * Type-Length-Value (TLV) structure and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before
	 * calling this function.
	 */
	short create_ap_cap_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a HT TLV (Type-Length-Value) structure.
	 *
	 * This function initializes a HT TLV structure in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the HT TLV will be created.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	short create_ht_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a VHT TLV (Very High Throughput Tag Length Value) structure.
	 *
	 * This function initializes a VHT TLV structure in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the VHT TLV will be created.
	 *
	 * @returns short
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure the buffer is allocated with sufficient size before calling this function.
	 */
	short create_vht_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a HE TLV.
	 *
	 * This function initializes a HE TLV structure in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the HE TLV will be created.
	 *
	 * @returns short The size of the created HE TLV.
	 */
	short create_he_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a WiFi 6 TLV (Type-Length-Value) structure.
	 *
	 * This function initializes a WiFi 6 TLV structure in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be created.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before calling this function.
	 */
	short create_wifi6_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a WiFi 7 TLV (Type-Length-Value) structure.
	 *
	 * This function initializes a WiFi 7 TLV structure in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be created.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before calling this function.
	 */
	short create_wifi7_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates an EHT operations TLV.
	 *
	 * This function is responsible for creating an EHT (Extremely High Throughput) operations TLV (Type-Length-Value) structure and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns The size of the TLV created in bytes.
	 *
	 * @note Ensure that the buffer provided is large enough to hold the TLV structure.
	 */
	short create_eht_operations_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a channel scan TLV.
	 *
	 * This function initializes a channel scan TLV using the provided buffer.
	 *
	 * @param[in] buff Pointer to the buffer where the TLV will be created.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is properly allocated before calling this function.
	 */
	short create_channelscan_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a profile 2 TLV.
	 *
	 * This function is responsible for creating a profile 2 TLV (Type-Length-Value) structure
	 * and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before calling this function.
	 */
	short create_prof_2_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a device inventory TLV (Type-Length-Value) structure.
	 *
	 * This function initializes a TLV structure for device inventory and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV structure will be stored.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is allocated with sufficient size before calling this function.
	 */
	short create_device_inventory_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a radio advertisement TLV.
	 *
	 * This function is responsible for creating a radio advertisement TLV (Type-Length-Value) structure
	 * and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	short create_radioad_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a metric collection integer TLV.
	 *
	 * This function initializes a metric collection integer TLV using the provided buffer.
	 *
	 * @param[in] buff Pointer to the buffer where the TLV will be created.
	 *
	 * @returns short The size of the created TLV.
	 */
	short create_metric_col_int_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a CAC CAP TLV.
	 *
	 * This function is responsible for creating a CAC CAP TLV and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the CAC CAP TLV will be stored.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	short create_cac_cap_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a basic capability for the AP radio.
	 *
	 * This function initializes the basic capabilities of the AP radio and stores
	 * the result in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the basic capability data will be stored.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	short create_ap_radio_basic_cap(unsigned char *buff);   
    //Msg-End

    
	/**!
	 * @brief Retrieves the manufacturer information.
	 *
	 * This function returns the manufacturer information from the data model.
	 *
	 * @returns A pointer to a character string containing the manufacturer information.
	 *
	 * @note The returned string is managed by the data model and should not be modified or freed by the caller.
	 */
	char *get_manufacturer() { return m_data_model->get_manufacturer(); }
    
	/**!
	 * @brief Retrieves the manufacturer model.
	 *
	 * This function returns the manufacturer model from the data model.
	 *
	 * @returns A pointer to a character string representing the manufacturer model.
	 *
	 * @note Ensure that the returned string is not modified or freed by the caller.
	 */
	char *get_manufacturer_model() { return m_data_model->get_manufacturer_model(); }
    
	/**!
	 * @brief Retrieves the software version.
	 *
	 * This function returns the current software version as a string.
	 *
	 * @returns A pointer to a character string representing the software version.
	 *
	 * @note The returned string is managed internally and should not be modified or freed by the caller.
	 */
	char *get_software_version() { return m_data_model->get_software_version(); }
    
	/**!
	 * @brief Retrieves the serial number.
	 *
	 * This function returns the serial number from the data model.
	 *
	 * @returns A pointer to a character array containing the serial number.
	 *
	 * @note Ensure that the data model is properly initialized before calling this function.
	 */
	char *get_serial_number() { return m_data_model->get_serial_number(); }
    
	/**!
	 * @brief Retrieves the primary device type.
	 *
	 * This function returns the primary device type from the data model.
	 *
	 * @returns A pointer to a character string representing the primary device type.
	 *
	 * @note Ensure that the returned string is not modified or freed by the caller.
	 */
	char *get_primary_device_type() { return m_data_model->get_primary_device_type(); }
    
	/**!
	 * @brief Retrieves the network SSID information based on the specified haul type.
	 *
	 * This function queries the data model to obtain the SSID information
	 * associated with the given haul type.
	 *
	 * @param[in] haul_type The type of haul for which the SSID information is requested.
	 *
	 * @returns A pointer to the `em_network_ssid_info_t` structure containing the SSID information.
	 * @retval nullptr If the SSID information for the specified haul type is not found.
	 *
	 * @note Ensure that the haul type provided is valid and supported by the data model.
	 */
	em_network_ssid_info_t *get_network_ssid_info_by_haul_type(em_haul_type_t haul_type) { return m_data_model->get_network_ssid_info_by_haul_type(haul_type); }

    
	/**!
	 * @brief Sets the manufacturer name.
	 *
	 * This function assigns the provided manufacturer name to the data model.
	 *
	 * @param[in] manufacturer A pointer to a character array containing the manufacturer name.
	 *
	 * @note Ensure that the manufacturer string is null-terminated.
	 */
	void set_manufacturer(char *manufacturer) { m_data_model->set_manufacturer(manufacturer); }
    
	/**!
	 * @brief Sets the manufacturer model.
	 *
	 * This function assigns the provided model string to the manufacturer's model data.
	 *
	 * @param[in] model A pointer to a character array representing the model name.
	 *
	 * @note Ensure that the model string is null-terminated and valid.
	 */
	void set_manufacturer_model(char *model) { m_data_model->set_manufacturer_model(model); }
    
	/**!
	 * @brief Sets the software version.
	 *
	 * This function updates the software version in the data model.
	 *
	 * @param[in] version A pointer to a character array containing the new software version.
	 *
	 * @note Ensure that the version string is null-terminated.
	 */
	void set_software_version(char *version) { m_data_model->set_software_version(version); }
    
	/**!
	 * @brief Sets the serial number for the data model.
	 *
	 * This function assigns a serial number to the data model by calling the
	 * `set_serial_number` method of the `m_data_model` object.
	 *
	 * @param[in] serial A pointer to a character array containing the serial number.
	 *
	 * @note Ensure that the `serial` parameter is a valid, null-terminated string.
	 */
	void set_serial_number(char *serial) { m_data_model->set_serial_number(serial); }
    
	/**!
	 * @brief Sets the primary device type.
	 *
	 * This function assigns the specified device type to the primary device.
	 *
	 * @param[in] type A character pointer representing the device type to be set.
	 *
	 * @note Ensure that the type is a valid device type string before calling this function.
	 */
	void set_primary_device_type(char *type) { m_data_model->set_primary_device_type(type); }
    
	/**!
	 * @brief Retrieves the current frequency band.
	 *
	 * This function returns the frequency band currently set in the system.
	 *
	 * @returns The current frequency band as an em_freq_band_t.
	 */
	em_freq_band_t get_band() { return m_band; }
    
	/**!
	 * @brief Sets the frequency band.
	 *
	 * @param[in] band The frequency band to be set.
	 */
	void set_band(em_freq_band_t band) { m_band = band; }
    
    
	/**!
	 * @brief Brief description of the function.
	 *
	 * This function is responsible for [describe the purpose of the function].
	 *
	 * @param[in] param_name Description of the input parameter.
	 *
	 * @returns A pointer to [describe what the pointer points to].
	 *
	 * @note Additional notes about the function.
	 */
	static void *em_func(void *);
    
	/**!
	 * @brief Retrieves the string representation of the frequency band type.
	 *
	 * This function takes a frequency band type and returns its corresponding string representation.
	 *
	 * @param[in] band The frequency band type to be converted to a string.
	 *
	 * @returns A constant character pointer to the string representation of the frequency band type.
	 *
	 * @note Ensure that the input band is a valid em_freq_band_t value to avoid undefined behavior.
	 */
	static const char *get_band_type_str(em_freq_band_t band);
    
	/**!
	 * @brief Converts an em_state_t state to its string representation.
	 *
	 * This function takes an em_state_t enumeration value and returns a
	 * corresponding string that represents the state.
	 *
	 * @param[in] state The state to be converted to a string.
	 *
	 * @returns A constant character pointer to the string representation of the state.
	 *
	 * @note Ensure that the state provided is valid within the em_state_t enumeration.
	 */
	static const char *state_2_str(em_state_t state);


	bool get_devteststatus(){return dev_test_enable;}
	void set_devteststatus(bool enable ) { dev_test_enable = enable;} 
	/**!
	 * @brief Initializes the EasyMesh interface with the specified parameters.
	 *
	 * This function sets up the EasyMesh interface using the provided frequency band,
	 * device manager, manager, profile type, and service type. Optionally, it can be
	 * configured as an AL entity.
	 *
	 * @param[in] ruid Pointer to the EasyMesh interface structure.
	 * @param[in] band Frequency band to be used for the EasyMesh interface.
	 * @param[in] dm Pointer to the device manager structure.
	 * @param[in] mgr Pointer to the manager structure.
	 * @param[in] profile Profile type for the EasyMesh configuration.
	 * @param[in] type Service type for the EasyMesh configuration.
	 * @param[in] is_al_em Boolean flag indicating if the interface should be configured as an AL entity.
	 *
	 * @returns em_t Returns an initialized EasyMesh interface structure.
	 *
	 * @note Ensure that all pointers provided are valid and properly initialized before calling this function.
	 */
	em_t(em_interface_t *ruid, em_freq_band_t band, dm_easy_mesh_t *dm, em_mgr_t *mgr, em_profile_type_t profile, em_service_type_t type, bool is_al_em = false);
    
	/**!
	 * @brief Destructor for the em_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the em_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	~em_t();

};

#endif

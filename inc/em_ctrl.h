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

#ifndef EMCTRL_H
#define EMCTRL_H

#include "em.h"
#include "em_mgr.h"
#include "dm_easy_mesh_ctrl.h"
#include "em_orch_ctrl.h"
#include "bus.h"
#include "em_dev_test_ctrl.h"

#ifdef AL_SAP
#define DATA_SOCKET_PATH "/tmp/al_data_socket"
#define CONTROL_SOCKET_PATH "/tmp/al_control_socket"
#endif

class em_cmd_ctrl_t;
class AlServiceAccessPoint;

class em_ctrl_t : public em_mgr_t {

    dm_easy_mesh_ctrl_t m_data_model;
    em_cmd_ctrl_t   *m_ctrl_cmd;
    em_orch_ctrl_t *m_orch;
	bus_handle_t m_bus_hdl;
	em_dev_test_t dev_test;
    
	/**!
	 * @brief Handles a bus event.
	 *
	 * This function processes the given bus event and performs the necessary actions.
	 *
	 * @param[in] evt Pointer to the bus event to be handled.
	 *
	 * @note Ensure that the event pointer is valid before calling this function.
	 */
	void handle_bus_event(em_bus_event_t *evt);

public:

    
	/**!
	 * @brief Listens for input events and processes them accordingly.
	 *
	 * This function is responsible for handling input events from various sources
	 * and triggering the appropriate actions based on the input received.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void input_listener();

    
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
	 * @note Ensure the path is valid and accessible.
	 */
	int data_model_init(const char *data_model_path);
    
	/**!
	 * @brief Checks if the data model is initialized.
	 *
	 * @returns True if the data model is initialized, false otherwise.
	 */
	bool is_data_model_initialized() { return m_data_model.is_initialized(); }
    
	/**!
	 * @brief Checks if the network topology is initialized.
	 *
	 * This function returns the initialization status of the network topology.
	 *
	 * @returns True if the network topology is initialized, false otherwise.
	 */
	bool is_network_topology_initialized() { return m_data_model.is_network_initialized(); }

	
	/**!
	 * @brief Initiates the completion process.
	 *
	 * This function is responsible for starting the completion process.
	 * It does not take any parameters and does not return any value.
	 *
	 * @note Ensure that all prerequisites are met before calling this function.
	 */
	void start_complete();
    
	/**!
	 * @brief Initializes the orchestration module.
	 *
	 * This function sets up necessary configurations and prepares the orchestration module for operation.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that all dependencies are met before calling this function.
	 */
	int orch_init();

    
	/**!
	 * @brief Handles the 5-second tick event.
	 *
	 * This function is called every 5 seconds to perform periodic tasks.
	 *
	 * @note Ensure that this function is called in a timely manner to maintain system performance.
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
	 * @note Ensure that this function is called regularly to maintain accurate timing.
	 */
	void handle_1s_tick();
    
	/**!
	 * @brief Handles the 500ms tick event.
	 *
	 * This function is called every 500 milliseconds to perform periodic tasks.
	 *
	 * @note Ensure that this function executes quickly to avoid delays in the tick handling.
	 */
	void handle_500ms_tick();

    
	/**!
	 * @brief Handles the dirty data management.
	 *
	 * This function is responsible for managing the dirty data within the system.
	 * It ensures that all necessary operations are performed to maintain data integrity.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void handle_dirty_dm();
    
	/**!
	 * @brief Handles the specified event.
	 *
	 * This function processes the event passed to it and performs the necessary actions.
	 *
	 * @param[in] evt Pointer to the event structure that needs to be handled.
	 *
	 * @note Ensure that the event pointer is valid and properly initialized before calling this function.
	 */
	void handle_event(em_event_t *evt);
    
	/**!
	 * @brief Handles the start of the DPP process.
	 *
	 * This function is responsible for initiating the DPP (Device Provisioning Protocol) process
	 * when the corresponding event is received.
	 *
	 * @param[in] evt Pointer to the event structure containing the DPP start event details.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_start_dpp(em_bus_event_t *evt);

        void handle_csi_event(em_bus_event_t *evt);

	/**!
	 * @brief Handles client steering based on the event provided.
	 *
	 * This function processes the client steering event and performs necessary actions.
	 *
	 * @param[in] evt Pointer to the event structure containing client steering information.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_client_steer(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the disassociation of a client.
	 *
	 * This function processes the event when a client is disassociated from the network.
	 *
	 * @param[in] evt Pointer to the event structure containing disassociation details.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_client_disassoc(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the client bottom event.
	 *
	 * This function processes the event received from the client bottom.
	 *
	 * @param[in] evt Pointer to the event structure containing event data.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_client_btm(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the setting of the radio.
	 *
	 * This function processes the event to set the radio state.
	 *
	 * @param[in] evt Pointer to the event structure containing radio settings.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_set_radio(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the setting of the SSID list.
	 *
	 * This function processes the event to set the SSID list in the system.
	 *
	 * @param[in] evt Pointer to the event structure containing SSID list information.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_set_ssid_list(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the removal of a device from the bus.
	 *
	 * This function processes the event associated with the removal of a device.
	 *
	 * @param[in] evt Pointer to the event structure containing details of the device removal.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_remove_device(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the setting of the channel list.
	 *
	 * This function processes the event to set the channel list.
	 *
	 * @param[in] evt Pointer to the event structure containing channel list information.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_set_channel_list(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the scan channel list event.
	 *
	 * This function processes the scan channel list event received from the bus.
	 *
	 * @param[in] evt Pointer to the event structure containing scan channel list data.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_scan_channel_list(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the setting of policy based on the event.
	 *
	 * This function processes the event and applies the necessary policy changes.
	 *
	 * @param[in] evt Pointer to the event structure containing policy information.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_set_policy(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the reset event for the EM bus.
	 *
	 * This function processes the reset event received from the EM bus and performs necessary actions.
	 *
	 * @param[in] evt Pointer to the EM bus event structure containing event details.
	 *
	 * @note Ensure that the event structure is properly initialized before passing it to this function.
	 */
	void handle_reset(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the device test event.
	 *
	 * This function processes the device test event received on the event bus.
	 *
	 * @param[in] evt Pointer to the event structure containing the device test event data.
	 *
	 * @note Ensure that the event structure is properly initialized before passing it to this function.
	 */
	void handle_get_dev_test(em_bus_event_t *evt);
	void handle_set_dev_test(em_bus_event_t *evt);

	/**!
	 * @brief Handles the get database event.
	 *
	 * This function processes the event related to database retrieval.
	 *
	 * @param[in] evt Pointer to the event structure containing event data.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_getdb(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the topology request.
	 *
	 * This function is responsible for processing the topology request.
	 *
	 * @note Ensure that the system is initialized before calling this function.
	 */
	void handle_topology_req();
    
	/**!
	 * @brief Handles the radio metrics request.
	 *
	 * This function processes the incoming radio metrics request and performs the necessary actions.
	 *
	 * @note Ensure that the radio metrics are properly initialized before calling this function.
	 */
	void handle_radio_metrics_req();
    
	/**!
	 * @brief Handles the AP metrics request.
	 *
	 * This function processes the request for AP metrics.
	 *
	 * @note Ensure that the request is valid before calling this function.
	 */
	void handle_ap_metrics_req();
    
	/**!
	 * @brief Handles client metrics request.
	 *
	 * This function processes the metrics request from the client and performs necessary actions.
	 *
	 * @note Ensure that the client metrics are correctly formatted before calling this function.
	 */
	void handle_client_metrics_req();
    
	/**!
	 * @brief Handles the retrieval of DM data.
	 *
	 * This function processes the event to get DM data.
	 *
	 * @param[in] evt Pointer to the event structure containing DM data.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_get_dm_data(em_bus_event_t *evt);
   
        void handle_get_csi_data(em_bus_event_t *evt);

	/**!
	 * @brief Handles the DM commit event.
	 *
	 * This function processes the DM commit event received through the event bus.
	 *
	 * @param[in] evt Pointer to the event structure containing DM commit details.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_dm_commit(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the M2 transmission event.
	 *
	 * This function processes the M2 transmission event and performs necessary actions.
	 *
	 * @param[in] evt Pointer to the event structure containing M2 transmission details.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_m2_tx(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the renewal of configuration based on the event received.
	 *
	 * This function processes the event and updates the configuration accordingly.
	 *
	 * @param[in] evt Pointer to the event structure containing configuration details.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_config_renew(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the station association event.
	 *
	 * This function processes the event when a station associates with the network.
	 *
	 * @param[in] evt Pointer to the event structure containing details of the association.
	 *
	 * @note Ensure that the event structure is properly initialized before passing it to this function.
	 */
	void handle_sta_assoc_event(em_bus_event_t *evt);
    
	/**!
	 * @brief Handles the MLD reconfiguration event.
	 *
	 * This function processes the MLD reconfiguration event received on the bus.
	 *
	 * @param[in] evt Pointer to the event structure containing MLD reconfiguration details.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	void handle_mld_reconfig(em_bus_event_t *evt);

    
	/**!
	 * @brief 
	 * This function handles input/output operations.
	 *
	 * @param[in] data Pointer to the data to be processed.
	 * @param[in] input Boolean flag indicating the operation mode. True for input, false for output.
	 *
	 * @note Ensure that the data pointer is valid and points to the correct data structure.
	 */
	void io(void *data, bool input = true);

	
	/**!
	 * @brief Initializes the network topology.
	 *
	 * This function sets up the network topology by initializing the data model's network topology.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void init_network_topology() { m_data_model.init_network_topology(); }
	
	/**!
	 * @brief Updates the network topology using the data model.
	 *
	 * This function calls the `update_network_topology` method on the `m_data_model` object
	 * to refresh or modify the current network topology.
	 *
	 * @note Ensure that `m_data_model` is properly initialized before calling this function.
	 */
	void update_network_topology() { m_data_model.update_network_topology(); }

	/**!
	 * @brief Retrieves the first data model in the agent list.
	 *
	 * @returns A pointer to the first `dm_easy_mesh_t` data model, or nullptr if no dms are available.
	 */
	dm_easy_mesh_t *get_first_dm() override { return m_data_model.get_first_dm(); }

	/**!
	 * @brief Retrieves the next data model in the agent list.
	 *
	 * @param[in] dm Pointer to the current `dm_easy_mesh_t` data model.
	 *
	 * @returns A pointer to the next `dm_easy_mesh_t` data model, or nullptr if there are no more dms.
	 */
	dm_easy_mesh_t *get_next_dm(dm_easy_mesh_t *dm) override { return m_data_model.get_next_dm(dm); }

	/**!
	 * @brief Retrieves the data model for a given network ID and optional AL MAC address.
	 *
	 * This function fetches the data model associated with the specified network ID.
	 * If an AL MAC address is provided, it will be used in the retrieval process.
	 *
	 * @param[in] net_id The network ID for which the data model is requested.
	 * @param[in] al_mac Optional. The AL MAC address to be used in the retrieval process.
	 *
	 * @returns A pointer to the `dm_easy_mesh_t` data model associated with the given network ID.
	 * @note If the AL MAC address is not provided, the function will use a default value.
	 */
	dm_easy_mesh_t *get_data_model(const char *net_id, const unsigned char *al_mac = NULL) { return m_data_model.get_data_model(net_id, al_mac); }
    
	/**!
	 * @brief Creates a data model for the specified network ID and interface.
	 *
	 * This function initializes a data model using the provided network ID,
	 * interface, and profile type. It returns a pointer to the created data model.
	 *
	 * @param[in] net_id The network identifier for which the data model is created.
	 * @param[in] al_intf Pointer to the interface structure used in the data model.
	 * @param[in] profile The profile type to be used for the data model. Defaults to em_profile_type_3.
	 *
	 * @returns Pointer to the created data model of type dm_easy_mesh_t.
	 *
	 * @note Ensure that the network ID and interface are valid before calling this function.
	 */
	dm_easy_mesh_t *create_data_model(const char *net_id, const em_interface_t *al_intf, em_profile_type_t profile = em_profile_type_3) { return m_data_model.create_data_model(net_id, al_intf, profile); }
    
	/**!
	 * @brief Deletes the data model associated with the given network ID and AL MAC address.
	 *
	 * This function removes the data model entry corresponding to the specified network identifier and AL MAC address.
	 *
	 * @param[in] net_id The network identifier for which the data model is to be deleted.
	 * @param[in] al_mac The AL MAC address associated with the data model to be deleted.
	 *
	 * @note Ensure that the network ID and AL MAC address are valid and correspond to an existing data model entry.
	 */
	void delete_data_model(const char *net_id, const unsigned char *al_mac) { m_data_model.delete_data_model(net_id, al_mac); }
    
	/**!
	 * @brief Deletes all data models.
	 *
	 * This function calls the delete_all_data_models method on the m_data_model object,
	 * effectively removing all data models managed by it.
	 *
	 * @note Ensure that any necessary data is backed up before calling this function,
	 * as it will remove all data models without the possibility of recovery.
	 */
	void delete_all_data_models() { m_data_model.delete_all_data_models(); }
    
	/**!
	 * @brief Updates the tables in the data model.
	 *
	 * This function updates the tables using the provided data model object.
	 *
	 * @param[in] dm Pointer to a dm_easy_mesh_t object containing the data to update the tables.
	 *
	 * @returns int Status of the update operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the dm pointer is valid and properly initialized before calling this function.
	 */
	int update_tables(dm_easy_mesh_t *dm) { return m_data_model.update_tables(dm); }
    
	/**!
	 * @brief Loads the network SSID table.
	 *
	 * This function is responsible for loading the network SSID table from the data model.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note Ensure that the data model is properly initialized before calling this function.
	 */
	int load_net_ssid_table() { return m_data_model.load_net_ssid_table(); }
    
	/**!
	 * @brief Debugs the probe using the data model.
	 *
	 * This function calls the debug_probe method on the m_data_model object.
	 *
	 * @note Ensure that m_data_model is properly initialized before calling this function.
	 */
	void debug_probe() { m_data_model.debug_probe(); }

    
	/**!
	 * @brief Retrieves the service type for the EM control.
	 *
	 * This function returns the service type associated with the EM control module.
	 *
	 * @returns em_service_type_t The service type for the EM control.
	 */
	em_service_type_t get_service_type() { return em_service_type_ctrl; }
    
	/**!
	 * @brief Finds the EM for a given message type.
	 *
	 * This function searches for the EM (Entity Manager) associated with a specific message type
	 * based on the provided data and its length.
	 *
	 * @param[in] data Pointer to the data buffer containing the message.
	 * @param[in] len Length of the data buffer.
	 * @param[in] al_em Pointer to the alternative EM to be used if no match is found.
	 *
	 * @returns Pointer to the found EM if successful, or NULL if no matching EM is found.
	 *
	 * @note Ensure that the data buffer is valid and the length is correctly specified.
	 */
	em_t *find_em_for_msg_type(unsigned char *data, unsigned int len, em_t *al_em);

#ifdef AL_SAP
    
	/**!
	 * @brief Registers a new AL Service Access Point.
	 *
	 * This function is responsible for creating and registering a new AL Service Access Point.
	 *
	 * @returns A pointer to the newly registered AlServiceAccessPoint.
	 * @retval nullptr If the registration fails.
	 *
	 * @note Ensure that the system has enough resources to register a new service access point.
	 */
	AlServiceAccessPoint* al_sap_register(const std::string& data_socket_path=DATA_SOCKET_PATH, const std::string& control_socket_path=CONTROL_SOCKET_PATH);
#endif

	/**!
	 * @brief Registers a new AL Service Access Point.
	 *
	 * This function is responsible for creating and registering a new AL Service Access Point.
	 *
	 * @returns A pointer to the newly registered AlServiceAccessPoint.
	 * @retval nullptr If the registration fails.
	 *
	 * @note Ensure that the system has enough resources to register a new service access point.
	 */
	em_cmd_ctrl_t *get_ctrl_cmd() { return m_ctrl_cmd; }

    
	/**!
	 * @brief Constructor for the em_ctrl_t class.
	 *
	 * This constructor initializes an instance of the em_ctrl_t class.
	 *
	 * @note This is a default constructor and does not take any parameters.
	 */
	em_ctrl_t();
    
	/**!
	 * @brief Destructor for the em_ctrl_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the em_ctrl_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	~em_ctrl_t();

};

#endif

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

#ifndef EM_MGR_H
#define EM_MGR_H

#include "em.h"
#include "em_orch.h"
#include "ieee80211.h"

class em_mgr_t {
   
    pthread_t   m_tid;
    bool m_exit;
    em_queue_t  m_queue;
	unsigned int m_tick_demultiplex;

public:
	pthread_mutex_t m_mutex;
    hash_map_t      *m_em_map;
    unsigned int m_timeout;
    fd_set  m_rset;
    
    
	/**!
	 * @brief Initializes the system with the specified data model path.
	 *
	 * This function sets up the necessary environment and configurations
	 * required for the system to operate using the provided data model.
	 *
	 * @param[in] data_model_path A constant character pointer to the path
	 * of the data model file. This path is used to locate and load the
	 * data model into the system.
	 *
	 * @returns An integer indicating the success or failure of the
	 * initialization process.
	 * @retval 0 Initialization was successful.
	 * @retval -1 Initialization failed due to an invalid path or other
	 * errors.
	 *
	 * @note Ensure that the data model path is correct and accessible
	 * before calling this function.
	 */
	int init(const char *data_model_path);
    
	/**!
	 * @brief Starts the process or service.
	 *
	 * This function initiates the necessary operations to start the process or service.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that all prerequisites are met before calling this function.
	 */
	int start();

    
	/**!
	 * @brief Checks if the data model is initialized.
	 *
	 * @returns True if the data model is initialized, false otherwise.
	 *
	 * @note This is a Pure Virtual function, to be implemented.
	 */
	virtual bool    is_data_model_initialized() = 0;

    
	/**!
	 * @brief Pushes an event to the queue.
	 *
	 * This function takes an event of type `em_event_t` and adds it to the processing queue.
	 *
	 * @param[in] evt Pointer to the event to be added to the queue.
	 *
	 * @note Ensure that the event pointer is not null before calling this function.
	 */
	void push_to_queue(em_event_t *evt);
    
	/**!
	 * @brief Pops an event from the queue.
	 *
	 * This function retrieves and removes the front event from the event queue.
	 *
	 * @returns A pointer to the event that was at the front of the queue.
	 * @retval nullptr If the queue is empty.
	 *
	 * @note Ensure that the queue is not empty before calling this function to avoid null pointer dereference.
	 */
	em_event_t *pop_from_queue();

    
	/**!
	 * @brief Listens to the nodes for incoming data or signals.
	 *
	 * This function initiates a listening process on the nodes, allowing the system to
	 * receive and process incoming data or signals from connected nodes.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the nodes are properly initialized before calling this function.
	 */
	int nodes_listen();
    
	/**!
	 * @brief Listens for input events.
	 *
	 * This function is responsible for listening to input events and processing them accordingly.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the input system is initialized before calling this function.
	 */
	int input_listen();
    
	/**!
	 * @brief Processes the protocol data.
	 *
	 * This function processes the given protocol data and performs necessary actions.
	 *
	 * @param[in] data Pointer to the data buffer that contains the protocol data to be processed.
	 * @param[in] len Length of the data buffer.
	 * @param[in] em Optional pointer to an em_t structure. If provided, it will be used during processing.
	 *
	 * @note If the em parameter is not provided, the function will operate with default settings.
	 */
	void proto_process(unsigned char *data, unsigned int len, em_t *em = NULL);

    
	/**!
	 * @brief Creates a new node with the specified parameters.
	 *
	 * This function initializes a new node using the provided interface, frequency band,
	 * and other parameters. It returns a pointer to the newly created node.
	 *
	 * @param[in] ruid Pointer to the interface structure.
	 * @param[in] band Frequency band for the node.
	 * @param[in] dm Pointer to the easy mesh structure.
	 * @param[in] is_al_mac Boolean flag indicating if AL MAC is used.
	 * @param[in] profile Profile type for the node, default is em_profile_type_3.
	 * @param[in] type Service type for the node, default is em_service_type_agent.
	 *
	 * @returns Pointer to the created node of type em_t.
	 *
	 * @note Ensure that the parameters are valid and properly initialized before calling this function.
	 */
	em_t *create_node(em_interface_t *ruid, em_freq_band_t band, dm_easy_mesh_t *dm, bool is_al_mac = false, em_profile_type_t profile = em_profile_type_3, em_service_type_t type = em_service_type_agent);
    
	/**!
	 * @brief Deletes a node from the specified interface.
	 *
	 * This function removes a node associated with the given interface identifier.
	 *
	 * @param[in] ruid Pointer to the interface from which the node will be deleted.
	 *
	 * @note Ensure that the interface is valid and initialized before calling this function.
	 */
	void delete_node(em_interface_t* ruid);
    
	/**!
	 * @brief Deletes nodes from the data structure.
	 *
	 * This function is responsible for removing nodes from the current data structure.
	 * It ensures that all resources associated with the nodes are properly released.
	 *
	 * @note Ensure that the data structure is not in use before calling this function.
	 */
	void delete_nodes();
    
	/**!
	 * @brief Retrieves a node based on the specified frequency band.
	 *
	 * This function searches for and returns a node that matches the given frequency band.
	 *
	 * @param[in] band Pointer to the frequency band structure to search for.
	 *
	 * @returns Pointer to the node that matches the specified frequency band.
	 * @retval NULL if no matching node is found.
	 *
	 * @note Ensure that the band parameter is not NULL before calling this function.
	 */
	em_t *get_node_by_freq_band(em_freq_band_t *band);
    
	/**!
	 * @brief Retrieves the AL node.
	 *
	 * This function returns a pointer to the AL node.
	 *
	 * @returns em_t* Pointer to the AL node.
	 */
	em_t *get_al_node();

    
	/**
	* @brief Get the physical AL node.
	* In other words, the actual `em_t` node that is being used to perform EasyMesh operations.
	*
	* @return em_t Pointer to the physical AL node.
	*/
	em_t *get_phy_al_node();

    
	/**!
	 * @brief Listener for node events.
	 *
	 * This function is responsible for handling events related to nodes.
	 *
	 * @note Ensure that the node system is initialized before calling this listener.
	 */
	void nodes_listener();
    
	/**!
	 * @brief Resets all listeners to their initial state.
	 *
	 * This function is responsible for resetting the state of all listeners
	 * that have been registered. It ensures that they are ready to be used
	 * again without any previous state interference.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that all listeners are properly initialized before calling
	 * this function to avoid unexpected behavior.
	 */
	int reset_listeners();
    
	/**!
	 * @brief Handles the timeout event.
	 *
	 * This function is called when a timeout occurs. It performs necessary
	 * actions to handle the timeout situation.
	 *
	 * @note Ensure that the timeout duration is set appropriately before
	 * calling this function.
	 */
	void handle_timeout();

    
	/**!
	 * @brief Listens to manager nodes.
	 *
	 * This function is responsible for listening to the manager nodes and processing
	 * the incoming data or events. It runs in a separate thread and handles the
	 * communication with the nodes.
	 *
	 * @param[in] arg A pointer to the arguments required for the listening operation.
	 *
	 * @returns A pointer to the result of the listening operation, or NULL if an error occurs.
	 *
	 * @note Ensure that the argument passed is valid and properly initialized before
	 * calling this function.
	 */
	static void *mgr_nodes_listen(void *arg);
    
	/**!
	 * @brief Listens for input events in the manager.
	 *
	 * This function is responsible for handling input events and processing them
	 * accordingly within the manager context.
	 *
	 * @param[in] arg A pointer to the argument passed to the thread function.
	 *
	 * @returns A pointer to the result of the input listening operation.
	 *
	 * @note This function is designed to be run in a separate thread.
	 */
	static void *mgr_input_listen(void *arg);

    
	/**
	 * @brief Refresh the OneWifi subdoc with current information + provided data and send to OneWifi.
	 *
	 * This function attempts to refresh the OneWifi subdoc using the current information
	 * combined with the provided data. It then sends the updated subdoc to OneWifi.
	 *
	 * @param[in] log_name The string to use when logging.
	 * @param[in] type The subdoc type.
	 *
	 * @return int Status code indicating the result of the operation.
	 * @retval 1 if successful.
	 * @retval 0 if encode fails.
	 * @retval -1 if send fails.
	 * @retval -2 if unimplemented.
	 *
	 * @note Currently, this function is not implemented and will always return -2.
	 */
	virtual int refresh_onewifi_subdoc(const char *log_name, const webconfig_subdoc_type_t type) {
        printf("refresh_onewifi_subdoc not implemented\n");
        return -2;
    }

    
	/**
	 * @brief Send an action frame. Optional to implement.
	 *
	 * This function attempts to send an action frame to a specified destination
	 * MAC address. It allows specifying the frequency and wait time for the action.
	 *
	 * @param[in] dest_mac The destination MAC address.
	 * @param[in] action_frame The action frame to send.
	 * @param[in] action_frame_len The length of the action frame.
	 * @param[in] frequency The frequency to send the frame on (0 for current frequency).
	 * @param[in] wait_time_ms The time to dwell on the frequency before switching back to the original frequency (0 for no wait).
	 *
	 * @return true if the action frame was sent successfully, false otherwise.
	 *
	 * @note This function is optional to implement and may not be supported on all platforms.
	 */
	virtual bool send_action_frame(uint8_t dest_mac[ETH_ALEN], uint8_t *action_frame, size_t action_frame_len, unsigned int frequency=0, unsigned int wait_time_ms=0) {
        printf("send_action_frame not implemented\n");
        return false;
    }

	/**
	 * @brief Set the disconnected steady state.
	 * 
	 * This function temporarily interupts the disconnected-scanning state machine in OneWifi
	 * and sets the device to an unstable steady state, stopping the constant scanning process
	 * 
	 * @note This only works when OneWifi is in a `disconnected*` state
	 * @note This function is optional to implement and may not be supported on all platforms.
	 */
	virtual bool set_disconnected_steady_state() {
        printf("set_disconnected_steady_state not implemented\n");
        return false;
    }

	/**
	 * @brief Set the disconnected scan none state (the initial state of the disconnected-scanning state machine).
	 * 
	 * This function returns from the disconnected-steady state to the disconnected-scanning state machine.
	 * 
	 * @note This only works when OneWifi is in the disconnected steady state.
	 * @note This function is optional to implement and may not be supported on all platforms.
	 */
	virtual bool set_disconnected_scan_none_state() {
        printf("set_disconnected_steady_state not implemented\n");
        return false;
    }

	/**
	 * @brief Send a scan request to OneWifi
	 *
	 * This function sends a scan request with the specified parameters to the mesh.
	 *
	 * @param[in] scan_params Pointer to the scan parameters structure.
	 * @param[in] perform_fresh_scan If true, performs a fresh scan; otherwise, uses cached results.
	 *
	 * @return true if the scan request was sent successfully, false otherwise.
	 * 
	 * @note This function is optional to implement and may not be supported on all platforms.
	 */
	virtual bool send_scan_request(em_scan_params_t* scan_params, bool perform_fresh_scan, bool is_sta_vap = false) {
		printf("send_scan_request not implemented\n");
		return false;
	}

    
	/**
	 * @brief Callback to determine if the mesh is capable of supporting additional onboarded APs.
	 *
	 * Spec does not determine what the threshold for onboarding more APs is, so this is vendor/deployment specific.
	 *
	 * @return true if the mesh can support an additional AP, otherwise false.
	 */
	virtual bool can_onboard_additional_aps() {
        printf("%s not implemented\n", __func__);
        return true;
    }

    
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
	 * @returns Pointer to the found EM, or nullptr if no matching EM is found.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual em_t *find_em_for_msg_type(unsigned char *data, unsigned int len, em_t *al_em) = 0;
    
	/**!
	 * @brief Initializes the data model with the specified path.
	 *
	 * This function sets up the data model using the path provided.
	 *
	 * @param[in] data_model_path The path to the data model file.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual int data_model_init(const char *data_model_path) = 0;
    
	/**!
	 * @brief Initializes the orchestrator.
	 *
	 * This function is responsible for setting up the initial state of the orchestrator.
	 *
	 * @returns An integer indicating the success or failure of the initialization process.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual int orch_init() = 0;
    
	/**!
	 * @brief This function serves as an input listener.
	 *
	 * This is a pure virtual function that must be implemented by derived classes.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	virtual void input_listener() = 0;
	
	/**!
	 * @brief Initiates the completion process for the start operation.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	virtual void	start_complete() = 0;
    
    
	/**!
	 * @brief Handles the specified event.
	 *
	 * This function processes the event passed to it and performs necessary actions.
	 *
	 * @param[in] evt Pointer to the event to be handled.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void handle_event(em_event_t *evt) = 0;

    
	/**!
	 * @brief Handles the 5-second tick event.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 * It is called every 5 seconds to perform periodic tasks.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	virtual void handle_5s_tick() = 0;
    
	/**!
	 * @brief Handles the 2-second tick event.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 * It is called every 2 seconds to perform time-based operations.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	virtual void handle_2s_tick() = 0;
    
	/**!
	 * @brief Handles the 1-second tick event.
	 *
	 * This function is called every second to perform time-based operations.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void handle_1s_tick() = 0;
    
	/**!
	 * @brief Handles the 500ms tick event.
	 *
	 * This function is called every 500 milliseconds to perform periodic tasks.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void handle_500ms_tick() = 0;

    
	/**!
	 * @brief Handles input/output operations.
	 *
	 * This function performs input or output operations based on the provided parameters.
	 *
	 * @param[in] data Pointer to the data to be processed.
	 * @param[in] input Boolean flag indicating the operation type. True for input, false for output.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void io(void *data, bool input = true) = 0;
    
	/**!
	 * @brief Updates the network topology.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	virtual void update_network_topology() = 0;
    
    
	/**!
	 * @brief Retrieves the data model for a given network ID.
	 *
	 * This function fetches the data model associated with the specified network ID.
	 * Optionally, an AL MAC address can be provided to refine the search.
	 *
	 * @param[in] net_id The network ID for which the data model is requested.
	 * @param[in] al_mac Optional AL MAC address to specify a particular device.
	 *
	 * @returns A pointer to the data model structure associated with the given network ID.
	 * @retval NULL if the data model cannot be found or an error occurs.
	 *
	 * @note Ensure that the network ID is valid and corresponds to an existing network.
	 * @note This is a pure virtual function and must be implemented by derived classes
	 */
	virtual dm_easy_mesh_t *get_data_model(const char *net_id, const unsigned char *al_mac = NULL) = 0;
    
	/**!
	 * @brief Creates a data model for the specified network ID and interface.
	 *
	 * This function initializes a data model based on the provided network ID,
	 * interface, and profile type. It returns a pointer to the created data model.
	 *
	 * @param[in] net_id The network identifier for which the data model is created.
	 * @param[in] al_intf Pointer to the interface structure used for the data model.
	 * @param[in] profile The profile type to be used for the data model. Defaults to em_profile_type_3.
	 *
	 * @returns A pointer to the created dm_easy_mesh_t data model.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_easy_mesh_t *create_data_model(const char *net_id, const em_interface_t *al_intf, em_profile_type_t profile = em_profile_type_3) = 0;
    
	/**!
	 * @brief Deletes a data model associated with a given network ID and MAC address.
	 *
	 * This function is responsible for removing the data model that corresponds to the specified
	 * network identifier and MAC address. It is a pure virtual function, meaning it must be
	 * implemented by any derived class.
	 *
	 * @param[in] net_id A pointer to a character array representing the network ID.
	 * @param[in] al_mac A pointer to an unsigned character array representing the MAC address.
	 *
	 * @note Ensure that the pointers provided are valid and point to the correct data.
	 */
	virtual void delete_data_model(const char *net_id, const unsigned char *al_mac) = 0;
    
	/**!
	 * @brief Deletes all data models.
	 *
	 * This function is responsible for removing all existing data models.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void delete_all_data_models() = 0;
    
	/**!
	 * @brief Updates the tables with the provided Easy Mesh data.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @param[in] dm Pointer to the Easy Mesh data structure that contains the information to update the tables.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note Ensure that the dm pointer is valid and properly initialized before calling this function.
	 */
	virtual int update_tables(dm_easy_mesh_t *dm) = 0;
    
	/**!
	 * @brief Loads the network SSID table.
	 *
	 * This function is responsible for loading the network SSID table into memory.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual int load_net_ssid_table() = 0;
    
	/**!
	 * @brief Debug probe function.
	 *
	 * This function is a pure virtual function intended to be overridden by derived classes.
	 * It is used for debugging purposes.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	virtual void debug_probe() = 0;

    
	/**!
	 * @brief Retrieves the service type.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns The service type as an em_service_type_t.
	 */
	virtual em_service_type_t get_service_type() = 0;

	
	/**!
	 * @brief Processes an event.
	 *
	 * This function handles the processing of an event passed to it.
	 *
	 * @param[in] evt Pointer to the event to be processed.
	 *
	 * @returns True if the event was processed successfully, false otherwise.
	 */
	bool io_process(em_event_t *evt);
	
	/**!
	 * @brief Processes input/output events based on the event type and data provided.
	 *
	 * This function handles the processing of events received on the event bus. It takes in the event type, associated data, and optional command parameters to execute the necessary actions.
	 *
	 * @param[in] type The type of event to process. This determines the kind of processing to be performed.
	 * @param[in] data Pointer to the data associated with the event. This data is used in the processing logic.
	 * @param[in] len The length of the data provided. This helps in determining the size of the data buffer.
	 * @param[in] params Optional command parameters that can modify the processing behavior. If not provided, default processing is applied.
	 *
	 * @note Ensure that the data buffer is valid and the length is correctly specified to avoid buffer overflows.
	 */
	void io_process(em_bus_event_type_t type, char *data, unsigned int len, em_cmd_params_t *params = NULL);
	
	/**!
	 * @brief Processes the input/output operations based on the event type.
	 *
	 * This function handles the data processing for the specified event type,
	 * utilizing the provided parameters if available.
	 *
	 * @param[in] type The type of the bus event to process.
	 * @param[in] data Pointer to the data buffer to be processed.
	 * @param[in] len The length of the data buffer.
	 * @param[in] params Optional command parameters for processing.
	 *
	 * @note Ensure that the data buffer is valid and the length is correctly specified.
	 */
	void io_process(em_bus_event_type_t type, unsigned char *data, unsigned int len, em_cmd_params_t *params = NULL);

    
	/**!
	 * @brief Constructor for the em_mgr_t class.
	 *
	 * This constructor initializes the em_mgr_t object.
	 *
	 * @note This is a default constructor.
	 */
	em_mgr_t();
    
	/**!
	 * @brief Destructor for the em_mgr_t class.
	 *
	 * This function cleans up any resources used by the em_mgr_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	virtual ~em_mgr_t();
};

#endif

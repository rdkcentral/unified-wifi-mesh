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

#ifndef EM_PROVISIONING_H
#define EM_PROVISIONING_H

#include "em_base.h"
#include "ec_manager.h"
#include <memory>

struct cJSON;
class em_cmd_t;
class em_provisioning_t {

    
	/**!
	 * @brief Creates a BSS configuration request message.
	 *
	 * This function initializes a buffer with the necessary data to form a BSS configuration request message.
	 *
	 * @param[out] buff Pointer to the buffer where the request message will be stored.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is allocated with sufficient size before calling this function.
	 */
	int create_bss_config_req_msg(uint8_t *buff);
    
	/**!
	 * @brief Creates a BSS configuration response message.
	 *
	 * This function is responsible for creating a BSS configuration response message
	 * and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the response message will be stored.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is allocated with sufficient size before calling this function.
	 */
	int create_bss_config_rsp_msg(uint8_t *buff);
    
	/**!
	 * @brief Creates a BSS configuration response message.
	 *
	 * This function initializes a buffer with the BSS configuration response message.
	 *
	 * @param[out] buff Pointer to the buffer where the response message will be stored.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure the buffer is allocated with sufficient size before calling this function.
	 */
	int create_bss_config_res_msg(uint8_t *buff);
    
	/**!
	 * @brief Creates a DPP direct encapsulation message.
	 *
	 * This function constructs a DPP direct encapsulation message using the provided buffer and frame.
	 *
	 * @param[out] buff Pointer to the buffer where the encapsulated message will be stored.
	 * @param[in] frame Pointer to the frame data to be encapsulated.
	 * @param[in] len Length of the frame data.
	 *
	 * @returns int Status code indicating success or failure of the message creation.
	 *
	 * @retval 0 Success.
	 * @retval -1 Failure due to invalid parameters.
	 *
	 * @note Ensure that the buffer is sufficiently large to hold the encapsulated message.
	 */
	int create_dpp_direct_encap_msg(uint8_t *buff, uint8_t *frame, uint16_t len);

    
	/**!
	 * @brief Handles the CCE indication message.
	 *
	 * This function processes the CCE indication message received in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the message.
	 * @param[in] len Length of the message in the buffer.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 Success.
	 * @retval -1 Failure due to invalid parameters.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is valid.
	 */
	int handle_cce_ind_msg(uint8_t *buff, unsigned int len);
    
	/**!
	 * @brief Handles the DPP chirp notification.
	 *
	 * This function processes the DPP chirp notification received in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the chirp notification data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the buffer is valid and contains the expected data format.
	 */
	int handle_dpp_chirp_notif(uint8_t *buff, unsigned int len);
    
	/**!
	 * @brief Handles a Proxied Encap DPP Message (EM 17.1.48)
	 *
	 *
	 * @param[in] buff Pointer to the buffer containing the data to be processed.
	 * @param[in] len Length of the buffer in bytes.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified
	 * before calling this function.
	 */
	int handle_proxy_encap_dpp(uint8_t *buff, unsigned int len);


	/**!
	 * @brief Handles a Direct Encap DPP Message (EM 17.1.56)
	 *
	 * @param[in] buff Pointer to the buffer containing the data to be processed.
	 * @param[in] len Length of the buffer in bytes.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified
	 * before calling this function.
	 */
	int handle_direct_encap_dpp(uint8_t *buff, unsigned int len);

    // states
    
	/**!
	 * @brief Handles the provisioning state when none is active.
	 *
	 * This function is responsible for managing the state when no provisioning
	 * is currently being processed.
	 *
	 * @note Ensure that the system is ready to handle transitions from this state.
	 */
	void handle_state_prov_none();
    
	/**!
	 * @brief Handles the provisioning state.
	 *
	 * This function is responsible for managing the state transitions during the provisioning process.
	 *
	 * @note Ensure that the provisioning context is properly initialized before calling this function.
	 */
	void handle_state_prov();
    
	/**!
	 * @brief Handles the state when an authentication request is pending.
	 *
	 * This function is responsible for managing the operations required
	 * when the system is in a state where an authentication request is
	 * pending. It ensures that all necessary checks and balances are
	 * maintained until the request is resolved.
	 *
	 * @note This function should be called only when the system is in
	 * the appropriate state to handle pending authentication requests.
	 */
	void handle_state_auth_req_pending();
    
	/**!
	 * @brief Handles the state when authentication response is pending.
	 *
	 * This function is responsible for managing the operations required
	 * when the system is awaiting an authentication response.
	 *
	 * @note Ensure that all prerequisites for authentication are met
	 * before invoking this function.
	 */
	void handle_state_auth_rsp_pending();
    
	/**!
	 * @brief Handles the state authentication confirmation when pending.
	 *
	 * This function is responsible for managing the state when an authentication
	 * confirmation is pending. It ensures that the necessary steps are taken to
	 * process the pending confirmation.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void handle_state_auth_cnf_pending();
    
	/**!
	 * @brief Handles the state configuration request when it is pending.
	 *
	 * This function is responsible for managing the state configuration
	 * request when it is in a pending state. It ensures that the request
	 * is processed appropriately and transitions to the next state as needed.
	 *
	 * @note This function should be called when a state configuration
	 * request is detected to be in a pending state.
	 */
	void handle_state_config_req_pending();
    
	/**!
	 * @brief Handles the state configuration response when it is pending.
	 *
	 * This function is responsible for managing the state when a configuration
	 * response is pending. It ensures that the system remains in a consistent
	 * state until the response is fully processed.
	 *
	 * @note This function should be called only when a configuration response
	 * is expected and is currently pending.
	 */
	void handle_state_config_rsp_pending();
    
	/**!
	 * @brief Handles the state configuration response when it is pending.
	 *
	 * This function is responsible for managing the state when a configuration
	 * response is awaited and is currently in a pending state.
	 *
	 * @note Ensure that the state is correctly transitioned once the response is received.
	 */
	void handle_state_config_res_pending();

    
	/**!
	 * @brief Retrieves the service type.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes to return the specific service type.
	 *
	 * @returns The service type as an em_service_type_t.
	 */
	virtual em_service_type_t   get_service_type() = 0;
    
	/**!
	 * @brief Retrieves the current state of the entity.
	 *
	 * @returns The current state as an em_state_t value.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
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
	 * @brief Retrieves the name of the radio interface.
	 *
	 * This function returns the name of the radio interface as a string.
	 *
	 * @returns A pointer to a character array containing the radio interface name.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual char *get_radio_interface_name() = 0;
    
	/**!
	 * @brief Retrieves the MAC address of the peer.
	 *
	 * This function returns the MAC address of the peer device as a pointer to an array of uint8_t.
	 *
	 * @returns A pointer to an array of uint8_t representing the MAC address of the peer.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual uint8_t *get_peer_mac() = 0;
    
	/**!
	 * @brief Retrieves the MAC address of the AL interface.
	 *
	 * This function returns the MAC address associated with the AL interface.
	 *
	 * @returns A pointer to an array of uint8_t representing the MAC address.
	 *
	 * @note The returned pointer should not be freed by the caller.
	 */
	virtual uint8_t *get_al_interface_mac() = 0;
    
	/**!
	 * @brief Retrieves the MAC address of the radio interface.
	 *
	 * This function returns a pointer to the MAC address of the radio interface.
	 *
	 * @returns A pointer to an array of uint8_t representing the MAC address.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual uint8_t *get_radio_interface_mac() = 0;
    
	/**!
	 * @brief Sends a frame of data.
	 *
	 * This function is responsible for sending a frame of data with the option to multicast.
	 *
	 * @param[in] buff Pointer to the buffer containing the data to be sent.
	 * @param[in] len The length of the data in the buffer.
	 * @param[in] multicast A boolean flag indicating whether the data should be sent as multicast. Defaults to false.
	 *
	 * @returns An integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual int send_frame(uint8_t *buff, unsigned int len, bool multicast = false) = 0;
    
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
	 * @retval non-zero error code on failure
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual int send_cmd(em_cmd_type_t type, em_service_type_t svc, uint8_t *buff, unsigned int len) = 0;
    
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
	 * @brief Retrieves the data model instance.
	 *
	 * This function is a pure virtual function that must be implemented by the derived class.
	 *
	 * @returns A pointer to the data model instance of type dm_easy_mesh_t.
	 *
	 * @note This function does not take any parameters and returns a pointer to the data model.
	 */
	virtual dm_easy_mesh_t *get_data_model() = 0;

protected:

	/**!
	 * @brief Creates a CCE indication message.
	 *
	 * This function is responsible for creating a CCE indication message and storing it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the CCE indication message will be stored.
	 * @param enable Enable/disable CCE indication
	 *
	 * @returns int Size of the CMDU created
	 *
	 * @note Ensure the buffer is properly allocated before calling this function.
	 */
	int create_cce_ind_msg(uint8_t *buff, bool enable);
    
	/**!
	 * @brief Sends a chirp notification message.
	 *
	 * This function is responsible for sending a chirp notification message using the provided chirp data and its length.
	 *
	 * @param[in] chirp Pointer to the chirp data to be sent.
	 * @param[in] chirp_len Length of the chirp data.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the chirp data is properly initialized before calling this function.
	 */
	int send_chirp_notif_msg(em_dpp_chirp_value_t *chirp, size_t chirp_len);
    
	/**!
	 * @brief Sends a proxied encapsulated DPP message.
	 *
	 * @param[in] encap_dpp_tlv Pointer to the encapsulated DPP TLV structure.
	 * @param[in] encap_dpp_len Length of the encapsulated DPP TLV.
	 * @param[in] chirp Pointer to the DPP chirp value structure.
	 * @param[in] chirp_len Length of the chirp value.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the encapsulated DPP TLV and chirp values are properly initialized before calling this function.
	 */
	int send_prox_encap_dpp_msg(em_encap_dpp_t* encap_dpp_tlv, size_t encap_dpp_len, em_dpp_chirp_value_t *chirp, size_t chirp_len);

	/**!
	 * @brief Sends a direct encapsulated DPP message. 
	 *
	 * @param[in] dpp_frame Pointer to the DPP frame data to be sent.
	 * @param[in] dpp_frame_len Length of the DPP frame data.
	 * @param[in] dest_al_mac Pointer to the destination AL MAC address (6 bytes).
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 */
	int send_direct_encap_dpp_msg(uint8_t* dpp_frame, size_t dpp_frame_len, uint8_t dest_al_mac[ETH_ALEN]);
    
	/**!
	 * @brief Creates a list of enrollee BSTA.
	 *
	 * This function generates a cJSON object representing the list of enrollee BSTA
	 * based on the provided connection context.
	 *
	 * @param[in] conn_ctx Pointer to the connection context used to create the list.
	 *
	 * @returns A pointer to a cJSON object representing the enrollee BSTA list.
	 *
	 * @note Ensure that the connection context is properly initialized before calling this function.
	 */
	cJSON *create_enrollee_bsta_list(ec_connection_context_t *conn_ctx);
    
	/**!
	 * @brief Creates a configurator BSTA response object.
	 *
	 * This function generates a cJSON object representing the BSTA response
	 * based on the provided connection context.
	 *
	 * @param[in] conn_ctx Pointer to the connection context used to create the response.
	 *
	 * @returns A pointer to the created cJSON object representing the BSTA response.
	 *
	 * @note Ensure that the connection context is properly initialized before calling this function.
	 */
	cJSON *create_configurator_bsta_response_obj(ec_connection_context_t *conn_ctx);
    
	/**!
	 * @brief Creates an IEEE 1905 response object.
	 *
	 * This function generates a cJSON object that represents an IEEE 1905 response.
	 *
	 * @param[in] conn_ctx Pointer to the connection context used for creating the response.
	 *
	 * @returns A pointer to the created cJSON object representing the IEEE 1905 response.
	 *
	 * @note Ensure that the connection context is properly initialized before calling this function.
	 */
	cJSON *create_ieee1905_response_obj(ec_connection_context_t *conn_ctx);

	/**
	 * @brief Create a fBSS (fronthaul BSS) Configuration response object for DPP STA onboarding
	 * 
	 * @param conn_ctx The connection context used to create the response object.
	 * @return cJSON* Configuration response object on success, nullptr otherwise
	 */
	cJSON *create_fbss_response_obj(ec_connection_context_t *conn_ctx);

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
	void    process_msg(uint8_t *data, unsigned int len);
    
	/**!
	 * @brief Processes the current state of the agent.
	 *
	 * This function handles the logic required to process the agent's state.
	 * It should be called whenever the agent's state needs to be evaluated or updated.
	 *
	 * @note Ensure that the agent is initialized before calling this function.
	 */
	void    process_agent_state();
    
	/**!
	 * @brief Processes the control state.
	 *
	 * This function handles the control state processing within the system.
	 *
	 * @note Ensure that the system is initialized before calling this function.
	 */
	void    process_ctrl_state();

    std::unique_ptr<ec_manager_t> m_ec_manager;

    
	/**!
	 * @brief Constructor for em_provisioning_t class.
	 *
	 * Initializes a new instance of the em_provisioning_t class.
	 *
	 * @note This constructor does not take any parameters.
	 */
	em_provisioning_t();
    
	/**!
	 * @brief Destructor for the em_provisioning_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the em_provisioning_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	virtual ~em_provisioning_t();

};

#endif

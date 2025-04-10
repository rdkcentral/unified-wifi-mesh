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

#ifndef EM_POLICY_CFG_H
#define EM_POLICY_CFG_H

#include "em_base.h"

class em_cmd_t;
class em_policy_cfg_t {

    
	/**!
	 * @brief Sends a frame of data.
	 *
	 * This function is responsible for sending a frame of data with the option to send it as multicast.
	 *
	 * @param[in] buff Pointer to the buffer containing the data to be sent.
	 * @param[in] len Length of the data in the buffer.
	 * @param[in] multicast Boolean flag indicating whether the frame should be sent as multicast. Defaults to false.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;

public:
    
	/**!
	 * @brief Retrieves the manager instance.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns A pointer to the manager instance of type em_mgr_t.
	 *
	 * @note This function does not take any parameters and returns a non-null pointer.
	 */
	virtual em_mgr_t *get_mgr() = 0;
    
	/**!
	 * @brief Retrieves the data model.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns A pointer to the data model of type dm_easy_mesh_t.
	 *
	 * @note This function does not take any parameters and returns a pointer to the data model.
	 */
	virtual dm_easy_mesh_t *get_data_model() = 0;
    
	/**!
	 * @brief Retrieves the MAC address of the radio interface.
	 *
	 * This function returns the MAC address associated with the radio interface.
	 *
	 * @returns A pointer to an unsigned char array representing the MAC address.
	 * @note The caller is responsible for managing the memory of the returned MAC address.
	 */
	virtual unsigned char *get_radio_interface_mac() = 0;
    
	/**!
	 * @brief Retrieves the current state of the entity.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns The current state of the entity as an em_state_t.
	 *
	 * @note This function does not modify any member variables.
	 */
	virtual em_state_t get_state() = 0;
    
	/**!
	 * @brief Sets the state of the policy.
	 *
	 * This function sets the current state of the policy to the specified state.
	 *
	 * @param[in] state The state to set, represented by em_state_t.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void set_state(em_state_t state) = 0;
    
	/**!
	 * @brief Retrieves the service type.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @returns The service type as an em_service_type_t.
	 *
	 * @note This function does not take any parameters and must be overridden in derived classes.
	 */
	virtual em_service_type_t get_service_type() = 0;
    
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
	 * @brief Retrieves the current command.
	 *
	 * This function returns a pointer to the current command being processed.
	 *
	 * @returns A pointer to the current command of type em_cmd_t.
	 * @retval nullptr if no command is currently being processed.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual em_cmd_t *get_current_cmd() = 0;

    
	/**!
	 * @brief Creates a steering policy TLV (Type-Length-Value) structure.
	 *
	 * This function initializes a steering policy TLV using the provided buffer.
	 *
	 * @param[in] buff Pointer to the buffer where the TLV will be created.
	 *
	 * @returns A short integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the buffer is properly allocated before calling this function.
	 */
	short create_steering_policy_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a metrics report policy TLV.
	 *
	 * This function generates a metrics report policy TLV (Type-Length-Value) and stores it in the provided buffer.
	 *
	 * @param[out] buff Pointer to the buffer where the TLV will be stored.
	 *
	 * @returns short The length of the created TLV.
	 *
	 * @note Ensure that the buffer is large enough to hold the TLV.
	 */
	short create_metrics_rep_policy_tlv(unsigned char *buff);
    
	/**!
	 * @brief Creates a vendor policy configuration TLV.
	 *
	 * This function is responsible for creating a vendor-specific policy
	 * configuration TLV (Type-Length-Value) structure and storing it in the
	 * provided buffer.
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
	short create_vendor_policy_cfg_tlv(unsigned char *buff);

    
	/**!
	 * @brief Sends a policy configuration request message.
	 *
	 * This function is responsible for initiating a request to configure policy settings.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the system is initialized before calling this function.
	 */
	int send_policy_cfg_request_msg();

    
	/**!
	 * @brief Handles the policy configuration request.
	 *
	 * This function processes the policy configuration request received in the buffer.
	 *
	 * @param[in] buff Pointer to the buffer containing the policy configuration data.
	 * @param[in] len Length of the data in the buffer.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Success.
	 * @retval -1 Failure due to invalid input.
	 *
	 * @note Ensure that the buffer is properly allocated and the length is correctly specified.
	 */
	int handle_policy_cfg_req(unsigned char *buff, unsigned int len);

    
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
	* @brief Processes the control state.
	*
	* This function is responsible for handling the control state transitions
	* and ensuring the system operates within the defined parameters.
	*
	* @note This function does not take any parameters and does not return any value.
	*/
	void process_ctrl_state();
    
	/**!
	* @brief Processes the current state.
	*
	* This function is responsible for handling the current state of the system.
	*
	* @note Ensure that the system is initialized before calling this function.
	*/
	void process_state();

    
	/**!
	 * @brief Constructor for the em_policy_cfg_t class.
	 *
	 * Initializes a new instance of the em_policy_cfg_t class.
	 *
	 * @note This constructor does not take any parameters and does not return any values.
	 */
	em_policy_cfg_t();
    
	/**!
	 * @brief Destructor for the em_policy_cfg_t class.
	 *
	 * Cleans up any resources used by the em_policy_cfg_t instance.
	 *
	 * @note This is a virtual destructor, allowing for proper cleanup of derived classes.
	 */
	virtual ~em_policy_cfg_t();
};

#endif

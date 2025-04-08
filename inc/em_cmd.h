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

#ifndef EM_CMD_H
#define EM_CMD_H

#include "em_base.h"
#include "em_ctrl.h"
#include <sys/time.h>
#include "dm_easy_mesh.h"

class em_cmd_t {
public:
    em_cmd_type_t   m_type;
    em_service_type_t   m_svc;
    em_cmd_params_t m_param;
    em_event_t  *m_evt;
    em_string_t m_name;
    queue_t *m_em_candidates;
    dm_easy_mesh_t  m_data_model;
    struct timeval  m_start_time;

    unsigned int m_orch_op_idx;
    em_orch_desc_t  m_orch_desc[EM_MAX_CMD];
    unsigned int m_num_orch_desc;
    unsigned int m_rd_op_class;
    unsigned int m_rd_channel;
    unsigned int m_db_cfg_type;

public:
    
	/**!
	 * @brief Validates the current state or input.
	 *
	 * This function checks the validity of the current state or input and returns a boolean value indicating the result.
	 *
	 * @returns True if the validation is successful, false otherwise.
	 */
	bool validate();

    
	/**!
	 * @brief Converts the command output status to a string representation.
	 *
	 * This function takes a status of type `em_cmd_out_status_t` and converts it
	 * into a human-readable string, storing the result in the provided buffer.
	 *
	 * @param[in] status The status to be converted.
	 * @param[out] str The buffer where the resulting string will be stored.
	 *
	 * @returns A pointer to the resulting string.
	 *
	 * @note Ensure that the buffer `str` is large enough to hold the resulting string.
	 */
	char *status_to_string(em_cmd_out_status_t status, char *str);

    
	/**!
	 * @brief Retrieves the type of the command.
	 *
	 * This function returns the type of the command encapsulated in the object.
	 *
	 * @returns em_cmd_type_t The type of the command.
	 */
	em_cmd_type_t get_type() { return m_type; }
    
	/**!
	 * @brief Retrieves the command name.
	 *
	 * This function returns the name of the command associated with the current object.
	 *
	 * @returns A constant character pointer to the command name.
	 *
	 * @note The returned string is managed internally and should not be freed by the caller.
	 */
	const char *get_cmd_name() { return m_name; }
    
	/**!
	 * @brief Retrieves a constant character pointer to the fixed arguments.
	 *
	 * @returns A constant character pointer to the fixed arguments.
	 */
	const char *get_arg() { return m_param.u.args.fixed_args; }
    
	/**!
	 * @brief Retrieves the service type.
	 *
	 * This function returns the current service type stored in the object.
	 *
	 * @returns The current service type.
	 */
	em_service_type_t get_svc() { return m_svc; }
    
	/**!
	 * @brief Retrieves the current event.
	 *
	 * @returns A pointer to the current event.
	 */
	em_event_t *get_event() { return m_evt; }
    
	/**!
	 * @brief Retrieves the total length of an event.
	 *
	 * This function calculates the total length of an event by adding the size of the event structure to the length of the event data.
	 *
	 * @returns The total length of the event in bytes.
	 */
	unsigned int get_event_length() { return (sizeof(em_event_t) + get_event_data_length()); }
    
	/**!
	 * @brief Retrieves the length of the event data.
	 *
	 * This function returns the size of the event data in bytes.
	 *
	 * @returns The length of the event data as an unsigned integer.
	 */
	unsigned int get_event_data_length();
	
	/**!
	 * @brief Sets the event data length.
	 *
	 * This function sets the length of the event data to the specified value.
	 *
	 * @param[in] len The length of the event data to be set.
	 *
	 * @note Ensure that the length is within the acceptable range.
	 */
	void set_event_data_length(unsigned int len);
    
	/**!
	 * @brief Retrieves the command parameters.
	 *
	 * This function returns a pointer to the command parameters structure.
	 *
	 * @returns A pointer to the em_cmd_params_t structure containing the command parameters.
	 */
	em_cmd_params_t *get_param() { return &m_param; }
    
	/**!
	 * @brief Retrieves the bus event.
	 *
	 * @returns A pointer to the bus event.
	 */
	em_bus_event_t *get_bus_event() { return &m_evt->u.bevt; }
    
	/**!
	 * @brief Retrieves the data model instance.
	 *
	 * @returns Pointer to the data model instance.
	 */
	dm_easy_mesh_t *get_data_model() { return &m_data_model; }

    
	/**!
	 * @brief Copies a bus event.
	 *
	 * This function takes an em_bus_event_t structure and performs a copy operation.
	 *
	 * @param[in] evt Pointer to the em_bus_event_t structure to be copied.
	 *
	 * @note Ensure that the evt pointer is valid and points to a properly initialized structure.
	 */
	void copy_bus_event(em_bus_event_t *evt);
    
	/**!
	 * @brief Copies a frame event to the specified event structure.
	 *
	 * This function takes a pointer to an em_frame_event_t structure and copies
	 * the frame event data into it.
	 *
	 * @param[out] evt Pointer to the em_frame_event_t structure where the frame
	 * event will be copied.
	 *
	 * @note Ensure that the evt pointer is valid and points to a properly
	 * allocated em_frame_event_t structure before calling this function.
	 */
	void copy_frame_event(em_frame_event_t *evt);

    
	/**!
	 * @brief Retrieves the current orchestration descriptor.
	 *
	 * This function returns a pointer to the orchestration descriptor
	 * corresponding to the current orchestration operation index.
	 *
	 * @returns A pointer to the current orchestration descriptor.
	 *
	 * @note Ensure that the orchestration operation index is valid
	 * before calling this function.
	 */
	em_orch_desc_t *get_orch_desc() { return &m_orch_desc[m_orch_op_idx]; }
    
	/**!
	 * @brief Retrieves the current orchestration operation type.
	 *
	 * This function returns the operation type of the current orchestration
	 * descriptor indexed by `m_orch_op_idx`.
	 *
	 * @returns The orchestration operation type as `dm_orch_type_t`.
	 */
	dm_orch_type_t get_orch_op()  { return m_orch_desc[m_orch_op_idx].op; }
    
	/**!
	 * @brief Retrieves the submission status of the current orchestration operation.
	 *
	 * @returns The submission status as a boolean value.
	 */
	bool get_orch_submit() { return m_orch_desc[m_orch_op_idx].submit; }
    
	/**!
	 * @brief Clones the current command for the next operation.
	 *
	 * This function creates a duplicate of the current command object,
	 * allowing it to be used for subsequent operations without altering
	 * the original command.
	 *
	 * @returns A pointer to the newly cloned command object.
	 * @note Ensure that the cloned object is properly managed to avoid
	 * memory leaks.
	 */
	virtual em_cmd_t *clone_for_next();
    
	/**!
	 * @brief Clones the current em_cmd object.
	 *
	 * This function creates a new instance of the em_cmd object that is a copy of the current object.
	 *
	 * @returns A pointer to the newly cloned em_cmd object.
	 * @retval nullptr If the cloning process fails.
	 *
	 * @note The caller is responsible for managing the memory of the cloned object.
	 */
	virtual em_cmd_t *clone();
    
	/**!
	 * @brief Sets the orchestration operation index.
	 *
	 * This function assigns the provided index to the member variable `m_orch_op_idx`.
	 *
	 * @param[in] idx The index to be set for the orchestration operation.
	 */
	virtual void set_orch_op_index(unsigned int idx) { m_orch_op_idx = idx; }
    
	/**!
	 * @brief Retrieves the orchestration operation index.
	 *
	 * This function returns the current index used for orchestration operations.
	 *
	 * @returns The orchestration operation index.
	 */
	virtual unsigned int get_orch_op_index() { return m_orch_op_idx; }
    
	/**!
	 * @brief Override operation for a given index with a specified orchestrator descriptor.
	 *
	 * This function allows overriding the operation at the specified index using the provided orchestrator descriptor.
	 *
	 * @param[in] index The index of the operation to override.
	 * @param[in] desc Pointer to the orchestrator descriptor to be used for overriding.
	 *
	 * @note Ensure that the index is within the valid range and the descriptor is properly initialized before calling this function.
	 */
	virtual void override_op(unsigned int index, em_orch_desc_t *desc);
    

    
	/**!
	 * @brief Retrieves the control AL interface.
	 *
	 * This function returns a pointer to the control AL interface from the data model.
	 *
	 * @returns A pointer to the control AL interface.
	 *
	 * @note Ensure that the returned pointer is valid before using it.
	 */
	em_interface_t *get_ctrl_al_interface() { return m_data_model.get_ctrl_al_interface(); }
    
	/**!
	 * @brief Retrieves the agent AL interface.
	 *
	 * This function returns a pointer to the agent AL interface from the data model.
	 *
	 * @returns A pointer to the `em_interface_t` representing the agent AL interface.
	 *
	 * @note Ensure that the returned pointer is valid before using it.
	 */
	em_interface_t *get_agent_al_interface() { return m_data_model.get_agent_al_interface(); }
    
	/**!
	 * @brief Retrieves the radio interface for the specified index.
	 *
	 * This function returns a pointer to the radio interface corresponding to the given index.
	 *
	 * @param[in] index The index of the radio interface to retrieve.
	 *
	 * @returns A pointer to the `em_interface_t` representing the radio interface.
	 * @retval nullptr If the index is out of range or the interface is not available.
	 *
	 * @note Ensure that the index is within the valid range of available radio interfaces.
	 */
	em_interface_t *get_radio_interface(unsigned int index) { return m_data_model.get_radio_interface(index); }
        
    
	/**!
	 * @brief Retrieves the MAC address of the AL interface.
	 *
	 * This function returns the MAC address associated with the AL interface.
	 *
	 * @returns A pointer to an unsigned char array containing the MAC address.
	 *
	 * @note Ensure that the returned pointer is handled appropriately to avoid memory issues.
	 */
	unsigned char *get_al_interface_mac() { return m_data_model.get_agent_al_interface_mac(); }
    
	/**!
	 * @brief Retrieves the manufacturer name.
	 *
	 * This function returns the manufacturer name from the data model.
	 *
	 * @returns A pointer to a character string containing the manufacturer name.
	 *
	 * @note Ensure that the returned string is properly managed to avoid memory leaks.
	 */
	char *get_manufacturer() { return m_data_model.get_manufacturer(); }
    
	/**!
	 * @brief Retrieves the manufacturer model.
	 *
	 * @returns A pointer to a character string containing the manufacturer model.
	 */
	char *get_manufacturer_model() { return m_data_model.get_manufacturer_model(); }
    
	/**!
	 * @brief Retrieves the serial number.
	 *
	 * This function returns the serial number from the data model.
	 *
	 * @returns A pointer to a character string containing the serial number.
	 *
	 * @note Ensure that the returned pointer is not null before using it.
	 */
	char *get_serial_number() { return m_data_model.get_serial_number(); }
    
	/**!
	 * @brief Retrieves the IEEE 1905 security capabilities.
	 *
	 * This function returns a pointer to the IEEE 1905 security capabilities
	 * structure from the data model.
	 *
	 * @returns A pointer to the `em_ieee_1905_security_cap_t` structure.
	 * @retval nullptr if the security capabilities are not available.
	 *
	 * @note Ensure that the returned pointer is not null before accessing
	 * the security capabilities.
	 */
	em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() { return m_data_model.get_ieee_1905_security_cap(); }
    
	/**!
	 * @brief Retrieves the primary device type.
	 *
	 * This function returns the primary device type from the data model.
	 *
	 * @returns A pointer to a character string representing the primary device type.
	 *
	 * @note Ensure that the returned string is not modified or freed by the caller.
	 */
	char *get_primary_device_type() { return m_data_model.get_primary_device_type(); }

    
	/**!
	 * @brief Retrieves the number of network SSIDs.
	 *
	 * This function returns the total count of network SSIDs available.
	 *
	 * @returns The number of network SSIDs.
	 */
	unsigned int get_num_network_ssid() { return m_data_model.get_num_network_ssid(); }

    
	/**!
	 * @brief Retrieves the network SSID for the given index.
	 *
	 * This function accesses the data model to fetch the SSID associated with the specified index.
	 *
	 * @param[in] index The index of the network SSID to retrieve.
	 *
	 * @returns A pointer to the dm_network_ssid_t structure containing the network SSID.
	 *
	 * @note Ensure the index is within the valid range of available network SSIDs.
	 */
	dm_network_ssid_t *get_network_ssid(unsigned int index) { return m_data_model.get_network_ssid(index); }
    
	/**!
	 * @brief Retrieves the DPP (Data Processing Pointer) from the data model.
	 *
	 * This function returns a pointer to the DPP, which is used for data processing
	 * within the application.
	 *
	 * @returns A pointer to the dm_dpp_t structure.
	 * @note Ensure that the returned pointer is not null before using it.
	 */
	dm_dpp_t *get_dpp() { return m_data_model.get_dpp(); }
    
	/**!
	 * @brief Retrieves a radio object from the data model.
	 *
	 * This function returns a pointer to a radio object at the specified index
	 * from the data model.
	 *
	 * @param[in] index The index of the radio object to retrieve.
	 *
	 * @returns A pointer to the radio object at the specified index.
	 * @retval nullptr If the index is out of range or the radio object is not found.
	 *
	 * @note Ensure that the index is within the valid range of available radios.
	 */
	dm_radio_t *get_radio(unsigned int index) { return m_data_model.get_radio(index); }
    
	/**!
	 * @brief Retrieves the current operation class for a given index.
	 *
	 * This function accesses the data model to fetch the current operation class
	 * associated with the specified index.
	 *
	 * @param[in] index The index for which the current operation class is requested.
	 *
	 * @returns A pointer to the dm_op_class_t representing the current operation class.
	 * @retval nullptr If the index is out of range or invalid.
	 *
	 * @note Ensure that the index is within the valid range before calling this function.
	 */
	dm_op_class_t *get_curr_op_class(unsigned int index) { return m_data_model.get_curr_op_class(index); }
    
	/**!
	 * @brief Retrieves the radio data for a given interface.
	 *
	 * This function returns the radio data associated with the specified
	 * interface, allowing access to various radio parameters.
	 *
	 * @param[in] radio The interface for which the radio data is requested.
	 *
	 * @returns A pointer to the radio data structure associated with the
	 *          specified interface.
	 *
	 * @note Ensure that the interface provided is valid and initialized
	 *       before calling this function.
	 */
	rdk_wifi_radio_t *get_radio_data(em_interface_t *radio) { return m_data_model.get_radio_data(radio); };
    
	/**!
	 * @brief Retrieves the current read operation class.
	 *
	 * This function returns the value of the member variable `m_rd_op_class`,
	 * which represents the current read operation class.
	 *
	 * @returns The current read operation class as an unsigned integer.
	 */
	unsigned int get_rd_op_class() { return m_rd_op_class; }
    
	/**!
	 * @brief Retrieves the current read channel value.
	 *
	 * This function returns the value of the member variable `m_rd_channel`,
	 * which represents the current read channel.
	 *
	 * @returns The current read channel value.
	 */
	unsigned int get_rd_channel() { return m_rd_channel; }

    
	/**!
	 * @brief Sets the start time using the current time of day.
	 *
	 * This function initializes the start time by retrieving the current time
	 * of day and storing it in the member variable `m_start_time`.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void set_start_time() { gettimeofday(&m_start_time, NULL);}

    
	/**!
	 * @brief Resets the event and command parameters to zero.
	 *
	 * This function initializes the event and command parameters by setting all
	 * bytes to zero, effectively resetting their state.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void reset() { memset(m_evt, 0, sizeof(em_event_t)); memset(&m_param, 0, sizeof(em_cmd_params_t));; }
    
	/**!
	 * @brief Initializes the easy mesh with the given configuration.
	 *
	 * This function sets up the easy mesh network using the provided configuration
	 * parameters. It must be called before any other mesh operations.
	 *
	 * @param[in] dm Pointer to the easy mesh configuration structure.
	 *
	 * @note Ensure that the configuration structure is properly initialized
	 * before passing it to this function.
	 */
	void init(dm_easy_mesh_t *dm);
    
	/**!
	 * @brief Initializes the system or component.
	 *
	 * This function sets up necessary configurations and prepares the system for operation.
	 *
	 * @note Ensure that all preconditions are met before calling this function.
	 */
	void init();
    
	/**!
	 * @brief Deinitializes the module or component.
	 *
	 * This function is responsible for cleaning up resources and
	 * performing any necessary shutdown procedures.
	 *
	 * @note Ensure that all operations using the module are complete
	 * before calling this function.
	 */
	void deinit();
    
	/**!
	 * @brief Resets the command context.
	 *
	 * This function resets the command context by invoking the reset_cmd_ctx method
	 * on the m_data_model object.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void reset_cmd_ctx() { m_data_model.reset_cmd_ctx(); }

    
	/**!
	 * @brief Retrieves the database configuration type.
	 *
	 * This function returns the current database configuration type.
	 *
	 * @returns The database configuration type as an unsigned integer.
	 */
	unsigned int get_db_cfg_type() { return m_db_cfg_type; }
    
	/**!
	 * @brief Sets the database configuration type.
	 *
	 * This function assigns the provided type to the member variable m_db_cfg_type.
	 *
	 * @param[in] type The configuration type to be set.
	 */
	void set_db_cfg_type(unsigned int type) { m_db_cfg_type = type; }

    
	/**!
	 * @brief Converts a bus event type to a command type.
	 *
	 * This function takes a bus event type as input and returns the corresponding
	 * command type. It is used to map bus events to command types for further processing.
	 *
	 * @param[in] type The bus event type that needs to be converted.
	 *
	 * @returns The corresponding command type for the given bus event type.
	 *
	 * @note Ensure that the input type is valid and supported by the conversion logic.
	 */
	static em_cmd_type_t bus_2_cmd_type(em_bus_event_type_t type);
    
	/**!
	 * @brief Converts a command type to a bus event type.
	 *
	 * This function takes a command type and converts it to the corresponding bus event type.
	 *
	 * @param[in] type The command type to be converted.
	 *
	 * @returns The corresponding bus event type.
	 */
	static em_bus_event_type_t cmd_2_bus_event_type(em_cmd_type_t type);
    
	/**!
	 * @brief Retrieves the string representation of the orchestration operation type.
	 *
	 * This function takes an orchestration type and returns its corresponding string.
	 *
	 * @param[in] type The orchestration type for which the string representation is needed.
	 *
	 * @returns A constant character pointer to the string representation of the given orchestration type.
	 *
	 * @note Ensure that the type provided is valid and corresponds to a defined orchestration operation.
	 */
	static const char *get_orch_op_str(dm_orch_type_t type);
    
	/**!
	 * @brief Retrieves the string representation of a bus event type.
	 *
	 * This function takes an em_bus_event_type_t enumeration value and returns
	 * a constant character pointer to its string representation.
	 *
	 * @param[in] type The bus event type to be converted to a string.
	 *
	 * @returns A constant character pointer to the string representation of the bus event type.
	 *
	 * @note Ensure that the input type is a valid em_bus_event_type_t value to avoid undefined behavior.
	 */
	static const char *get_bus_event_type_str(em_bus_event_type_t type);
    
	/**!
	 * @brief Retrieves the command type as a string.
	 *
	 * This function takes a command type and returns its corresponding string representation.
	 *
	 * @param[in] type The command type to be converted to a string.
	 *
	 * @returns A constant character pointer to the string representation of the command type.
	 *
	 * @note Ensure that the command type provided is valid to avoid unexpected results.
	 */
	static const char *get_cmd_type_str(em_cmd_type_t type);    
    
	/**!
	 * @brief Dumps the bus event details.
	 *
	 * This function processes the bus event and outputs the relevant information.
	 *
	 * @param[in] evt Pointer to the bus event structure to be dumped.
	 *
	 * @returns int Status code of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	static int dump_bus_event(em_bus_event_t *evt);
    
    
	/**!
	 * @brief Executes a command based on the specified type and parameters.
	 *
	 * This function processes the command of the given type using the provided parameters
	 * and updates the EasyMesh instance accordingly.
	 *
	 * @param[in] type The type of command to execute.
	 * @param[in] param The parameters associated with the command.
	 * @param[out] dm The EasyMesh instance to be updated.
	 *
	 * @returns The result of the command execution.
	 * @retval EM_CMD_SUCCESS if the command was executed successfully.
	 * @retval EM_CMD_FAILURE if the command execution failed.
	 *
	 * @note Ensure that the EasyMesh instance is properly initialized before calling this function.
	 */
	em_cmd_t(em_cmd_type_t type, em_cmd_params_t param, dm_easy_mesh_t& dm);
    
	/**!
	 * @brief Executes a command based on the specified type and parameters.
	 *
	 * @param[in] type The type of command to execute.
	 * @param[in] param The parameters associated with the command.
	 *
	 * @returns em_cmd_t The result of the command execution.
	 *
	 * @note Ensure that the command type and parameters are valid before calling this function.
	 */
	em_cmd_t(em_cmd_type_t type, em_cmd_params_t param);
    
	/**!
	 * @brief Constructor for the em_cmd_t class.
	 *
	 * This constructor initializes an instance of the em_cmd_t class.
	 *
	 * @note This is a default constructor and does not take any parameters.
	 */
	em_cmd_t();
    
	/**!
	 * @brief Destructor for em_cmd_t class.
	 *
	 * This destructor cleans up any resources allocated by the em_cmd_t instance.
	 *
	 * @note Ensure that all operations using em_cmd_t are completed before destruction.
	 */
	virtual ~em_cmd_t();
};

#endif

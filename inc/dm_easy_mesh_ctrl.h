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

#ifndef DM_EM_CTRL_H
#define DM_EM_CTRL_H

#include "em_base.h"
#include "dm_network_list.h"
#include "dm_device_list.h"
#include "dm_network_ssid_list.h"
#include "dm_ieee_1905_security_list.h"
#include "dm_radio_list.h"
#include "dm_radio_cap_list.h"
#include "dm_op_class_list.h"
#include "dm_bss_list.h"
#include "dm_sta_list.h"
#include "dm_policy_list.h"
#include "dm_scan_result_list.h"
#include "dm_dpp.h"
#include "db_client.h"
#include "dm_easy_mesh_list.h"
#include "em_network_topo.h"

class em_cmd_t;
class dm_easy_mesh_t;
class em_mgr_t;
class em_ctrl_t;
class dm_easy_mesh_ctrl_t :
    public dm_network_list_t, public dm_device_list_t, public dm_network_ssid_list_t,
    public dm_ieee_1905_security_list_t, public dm_radio_list_t, public dm_radio_cap_list_t,
    public dm_op_class_list_t, public dm_bss_list_t, public dm_sta_list_t, public dm_policy_list_t,
	public dm_scan_result_list_t {

public:
    int m_nb_pipe_rd;
    int m_nb_pipe_wr;
    uint32_t m_nb_evt_id;

    int get_nb_pipe_rd() { return m_nb_pipe_rd; }
    int get_nb_pipe_wr() { return m_nb_pipe_wr; }
    uint32_t get_next_nb_evt_id() { return m_nb_evt_id++; }

    bus_error_t bus_get_cb_fwd(char *event_name, raw_data_t *p_data, bus_get_handler_t cb);
    dm_easy_mesh_t *get_dm_easy_mesh(char *instance, bool is_num);
    dm_device_t *get_dm_dev(mac_address_t dev_mac, mac_address_t bmac);
    dm_radio_t *get_dm_radio(dm_easy_mesh_t *dm, char *instance, bool is_num);
    dm_sta_t *get_dm_bh_sta(dm_easy_mesh_t *dm, dm_radio_t *radio);
    const char* get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num);

    bus_error_t network_get(char *event_name, raw_data_t *p_data);
    static bus_error_t network_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);

    bus_error_t device_get(char* event_name, raw_data_t* p_data);
    static bus_error_t device_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    bus_error_t device_tget(char *event_name, raw_data_t *p_data);
    static bus_error_t device_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);

    bus_error_t policy_get(char* event_name, raw_data_t* p_data);
    static bus_error_t policy_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);

    bus_error_t radio_get(char* event_name, raw_data_t* p_data);
    static bus_error_t radio_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    bus_error_t radio_tget(char* event_name, raw_data_t* p_data);
    static bus_error_t radio_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t radio_tget_params(dm_easy_mesh_t *dm, const char *root, bus_data_prop_t **property);
    bus_error_t rbhsta_get(char *event_name, raw_data_t *p_data);
    static bus_error_t rbhsta_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    bus_error_t curops_tget(char *event_name, raw_data_t *p_data);
    static bus_error_t curops_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t curops_tget_params(dm_easy_mesh_t *dm, const char *root, em_radio_info_t *ri, bus_data_prop_t **property);

    void fill_comma_sep(em_short_string_t str[], size_t max, char *buf);
    bus_error_t bss_get(char* event_name, raw_data_t* p_data);
    static bus_error_t bss_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    bus_error_t bss_tget(char* event_name, raw_data_t* p_data);
    static bus_error_t bss_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t bss_tget_params(dm_easy_mesh_t *dm, const char *root, em_radio_info_t *ri, bus_data_prop_t **property);

    bus_error_t ssid_get(char* event_name, raw_data_t* p_data);
    static bus_error_t ssid_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    bus_error_t ssid_tget(char* event_name, raw_data_t* p_data);
    static bus_error_t ssid_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t ssid_tget_params(dm_easy_mesh_t *dm, const char *root, bus_data_prop_t **property);

    char* get_ht_caps_str(em_ap_ht_cap_t *ht, char *buf, size_t buf_len);
    char* get_vht_caps_str(em_ap_vht_cap_t *vht, char *buf, size_t buf_len);
    bus_error_t rcaps_get(char* event_name, raw_data_t* p_data);
    static bus_error_t rcaps_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t rcaps_tget_inner(dm_easy_mesh_t *dm, const char *root, bus_data_prop_t **property);
    bus_error_t wf6ap_get(char* event_name, raw_data_t* p_data);
    bus_error_t wf6ap_tget(char* event_name, raw_data_t* p_data);
    static bus_error_t wf6ap_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t wf6ap_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t wf6ap_tget_params(dm_easy_mesh_t *dm, const char *root, em_radio_info_t *ri, bus_data_prop_t **property, int idx);

    bus_error_t wf7ap_get(char* event_name, raw_data_t* p_data);
    bus_error_t wf7ap_tget(char* event_name, raw_data_t* p_data);
    static bus_error_t wf7ap_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t wf7ap_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t wf7ap_tget_params(dm_easy_mesh_t *dm, const char *root, em_radio_info_t *ri, bus_data_prop_t **property, int idx);

    dm_op_class_t* get_dm_curop(dm_easy_mesh_t *dm, dm_radio_t *radio, int instance);
    bus_error_t curops_get(char* event_name, raw_data_t* p_data);
    static bus_error_t curops_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);

    dm_sta_t* get_dm_sta(dm_easy_mesh_t *dm, em_bss_info_t *bi, int instance);
    void fill_haul_type(em_haul_type_t hauls[], size_t max, char *buf);
    bus_error_t sta_get(char* event_name, raw_data_t* p_data);
    bus_error_t sta_tget(char *event_name, raw_data_t *p_data);
    static bus_error_t sta_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t sta_tget_params(dm_easy_mesh_t *dm, const char *root, em_bss_info_t *bi, bus_data_prop_t **property);
    static bus_error_t sta_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);

    dm_ap_mld_t *get_dm_ap_mld(dm_easy_mesh_t *dm, char *instance, bool is_num);
    bus_error_t apmld_get(char *event_name, raw_data_t *p_data);
    bus_error_t apmld_tget(char *event_name, raw_data_t *p_data);
    bus_error_t apmldcfg_get(char *event_name, raw_data_t *p_data);
    static bus_error_t apmld_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t apmld_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t apmld_tget_params(dm_easy_mesh_t *dm, const char *root, bus_data_prop_t **property);
    static bus_error_t apmldcfg_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);

    bus_error_t affap_get(char *event_name, raw_data_t *p_data);
    bus_error_t affap_tget(char *event_name, raw_data_t *p_data);
    static bus_error_t affap_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t affap_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t affap_tget_params(dm_easy_mesh_t *dm, const char *root, em_ap_mld_info_t *ami, bus_data_prop_t **property);

private:
    db_client_t m_db_client;
    bool	m_initialized;
    bool	m_network_initialized;

    dm_easy_mesh_list_t	m_data_model_list;
	em_network_topo_t   *m_topology;

	/**!
	 * @brief Sets the device list.
	 *
	 * This function updates the device list with the provided JSON object.
	 *
	 * @param[in] dev_list_obj A pointer to a cJSON object representing the device list.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the JSON object is properly formatted before passing it to this function.
	 */
	int set_device_list(cJSON *dev_list_obj);
    
	/**!
	 * @brief Sets the radio list for a given device.
	 *
	 * This function updates the radio list object with the specified device MAC address.
	 *
	 * @param[in] radio_list_obj Pointer to the cJSON object representing the radio list.
	 * @param[in] dev_mac Pointer to the MAC address of the device.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the radio_list_obj is properly initialized before calling this function.
	 */
	int set_radio_list(cJSON *radio_list_obj, mac_address_t *dev_mac);
    
	/**!
	 * @brief Sets the BSS list for a given radio MAC address.
	 *
	 * This function updates the BSS list associated with the specified radio MAC address.
	 *
	 * @param[in] bss_list_obj A pointer to a cJSON object representing the BSS list.
	 * @param[out] radio_mac A pointer to the MAC address of the radio for which the BSS list is being set.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the bss_list_obj is properly formatted and radio_mac is valid before calling this function.
	 */
	int set_bss_list(cJSON *bss_list_obj, mac_address_t *radio_mac);
    
	/**!
	 * @brief Sets the operational class list for a given radio MAC address.
	 *
	 * This function updates the operational class list based on the provided JSON object
	 * and associates it with the specified radio MAC address.
	 *
	 * @param[in] op_class_list_obj A pointer to a cJSON object containing the operational class list.
	 * @param[out] radio_mac A pointer to a mac_address_t structure representing the radio MAC address.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the cJSON object and MAC address are valid before calling this function.
	 */
	int set_op_class_list(cJSON *op_class_list_obj, mac_address_t *radio_mac);
    
	/**!
	 * @brief Sets the radio capability list.
	 *
	 * This function updates the radio capability list with the provided JSON object and associates it with the specified radio MAC address.
	 *
	 * @param[in] radio_cap_list_obj A pointer to a cJSON object representing the radio capability list.
	 * @param[out] radio_mac A pointer to a mac_address_t structure where the radio MAC address will be stored.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the radio_cap_list_obj is properly formatted and that radio_mac is a valid pointer.
	 */
	int set_radio_cap_list(cJSON *radio_cap_list_obj, mac_address_t *radio_mac);

public:
    
	/**!
	 * @brief Initializes the Easy Mesh Controller with the specified data model path.
	 *
	 * This function sets up the Easy Mesh Controller by loading the data model from the given path
	 * and initializing the manager structure.
	 *
	 * @param[in] data_model_path The file path to the data model configuration.
	 * @param[out] mgr Pointer to the Easy Mesh manager structure to be initialized.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the data model path is valid and accessible before calling this function.
	 */
	int init(const char *data_model_path, em_mgr_t *mgr);

    
	/**!
	 * @brief Checks if the mesh control is initialized.
	 *
	 * This function returns the initialization status of the mesh control.
	 *
	 * @returns True if the mesh control is initialized, false otherwise.
	 */
	bool is_initialized() { return m_initialized; }
    
	/**!
	 * @brief Sets the initialized flag to true.
	 *
	 * This function sets the member variable `m_initialized` to true, indicating that the initialization process is complete.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void set_initialized() { m_initialized = true; }
    
	/**!
	 * @brief Checks if the network is initialized.
	 *
	 * @returns True if the network is initialized, false otherwise.
	 */
	bool is_network_initialized() { return m_network_initialized; }
    
	/**!
	 * @brief Sets the network initialization status to true.
	 *
	 * This function sets the internal flag `m_network_initialized` to true, indicating that the network has been initialized.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void set_network_initialized() { m_network_initialized = true; }

    //int analyze_network_ssid_list(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the link metrics for a station.
	 *
	 * This function processes the link metrics for a given station command.
	 *
	 * @param[in] pcmd Array of pointers to station command structures.
	 *
	 * @returns int Status code indicating success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the command array is properly initialized before calling this function.
	 */
	int analyze_sta_link_metrics(em_cmd_t *pcmd[]);
    
	/**!
	 * @brief Analyzes and sets the SSID based on the provided event and command.
	 *
	 * This function processes the event and command to configure the SSID settings.
	 *
	 * @param[in] evt Pointer to the event structure containing the SSID information.
	 * @param[in] cmd Array of command structures to be processed.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_set_ssid(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes and sets the radio configuration based on the provided event and command.
	 *
	 * This function processes the given event and command array to configure the radio settings.
	 *
	 * @param[in] evt Pointer to the event structure containing radio configuration details.
	 * @param[in] cmd Array of command structures to be processed for setting the radio.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_set_radio(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes and sets the channel based on the provided event and command.
	 *
	 * This function processes the event and command to determine the appropriate channel settings.
	 *
	 * @param[in] evt Pointer to the event structure containing event details.
	 * @param[in] cmd Array of command pointers to be processed.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_set_channel(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the scan channel based on the provided event and command.
	 *
	 * This function processes the scan channel information from the event and command
	 * structures to perform necessary analysis.
	 *
	 * @param[in] evt Pointer to the event structure containing scan channel data.
	 * @param[in] cmd Array of pointers to command structures for processing.
	 *
	 * @returns int Status code indicating success or failure of the analysis.
	 * @retval 0 Success
	 * @retval -1 Failure due to invalid parameters
	 *
	 * @note Ensure that the event and command structures are properly initialized
	 * before calling this function.
	 */
	int analyze_scan_channel(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes and sets the policy based on the given event and command.
	 *
	 * This function processes the event and command to determine the appropriate policy settings.
	 *
	 * @param[in] evt Pointer to the event structure containing event details.
	 * @param[in] cmd Array of pointers to command structures to be processed.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_set_policy(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the DPP start event and command.
	 *
	 * This function processes the DPP start event and the associated command array.
	 *
	 * @param[in] evt Pointer to the DPP start event structure.
	 * @param[in] cmd Array of pointers to command structures.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command pointers are valid before calling this function.
	 */
	int analyze_dpp_start(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the station steering parameters and updates the command list.
	 *
	 * This function processes the given steering parameters and modifies the command
	 * list accordingly to steer the station to the appropriate access point.
	 *
	 * @param[in] params The steering parameters to be analyzed.
	 * @param[out] cmd The list of commands to be updated based on the analysis.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the command list is properly initialized before calling this function.
	 */
	int analyze_sta_steer(em_cmd_steer_params_t &params, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the disassociation of a station.
	 *
	 * This function processes the disassociation parameters and updates the command array accordingly.
	 *
	 * @param[in] params The disassociation parameters to be analyzed.
	 * @param[out] cmd The command array to be updated based on the analysis.
	 *
	 * @returns int Status code indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the command array is properly initialized before calling this function.
	 */
	int analyze_sta_disassoc(em_cmd_disassoc_params_t &params, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the disassociation of a station.
	 *
	 * This function processes the event related to a station's disassociation and updates the command list accordingly.
	 *
	 * @param[in] evt Pointer to the event structure containing disassociation details.
	 * @param[out] cmd Array of command structures to be updated based on the event.
	 *
	 * @returns Integer status code indicating success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_sta_disassoc(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the STA BTM event and command.
	 *
	 * This function processes the STA BTM event and executes the associated command.
	 *
	 * @param[in] evt Pointer to the STA BTM event structure.
	 * @param[out] cmd Array of pointers to the command structures to be executed.
	 *
	 * @returns int Status code indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_sta_btm(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the command steer event.
	 *
	 * This function processes the given event and command array to determine the appropriate steering action.
	 *
	 * @param[in] evt Pointer to the event structure containing the bus event details.
	 * @param[in] cmd Array of command structures to be analyzed.
	 *
	 * @returns int Status code indicating the result of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command array are properly initialized before calling this function.
	 */
	int analyze_command_steer(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the disassociation command.
	 *
	 * This function processes the disassociation command received in the event.
	 *
	 * @param[in] evt Pointer to the event structure containing the disassociation command.
	 * @param[in] cmd Array of command structures to be analyzed.
	 *
	 * @returns int Status code indicating the result of the analysis.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_command_disassoc(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the BTM command from the event bus.
	 *
	 * This function processes the BTM command received through the event bus and populates the command array.
	 *
	 * @param[in] evt Pointer to the event bus event structure containing the BTM command.
	 * @param[out] cmd Array of command structures to be populated based on the event data.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_command_btm(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the reset event and command.
	 *
	 * This function processes the reset event and associated command array.
	 *
	 * @param[in] evt Pointer to the event structure containing reset information.
	 * @param[out] cmd Array of command structures to be processed.
	 *
	 * @returns int Status code indicating success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_reset(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes and removes a device from the mesh network.
	 *
	 * This function processes the event and command to remove a device from the mesh network.
	 *
	 * @param[in] evt Pointer to the event structure containing the device information.
	 * @param[out] cmd Array of command structures to be executed for device removal.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_remove_device(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the M2 transmission event and command.
	 *
	 * This function processes the M2 transmission event and updates the command array accordingly.
	 *
	 * @param[in] evt Pointer to the event structure containing the M2 transmission details.
	 * @param[in] evt_status Indicates if the same event for this command type is already executing.
	 * @param[out] cmd Array of command pointers to be updated based on the event analysis.
	 *
	 * @returns int Status code indicating success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the event and command pointers are valid before calling this function.
	 */
	int analyze_m2_tx(em_bus_event_t *evt, em_cmd_t *cmd[], bool evt_status);
    
	/**!
	 * @brief Analyzes the station association event.
	 *
	 * This function processes the event related to station association and updates the command list accordingly.
	 *
	 * @param[in] evt Pointer to the event structure containing association details.
	 * @param[out] cmd Array of command structures to be updated based on the event analysis.
	 *
	 * @returns int Status code indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the event structure is properly initialized before calling this function.
	 */
	int analyze_sta_assoc_event(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the client association event and command.
	 *
	 * This function processes the client association event and updates the command array accordingly.
	 *
	 * @param[in] evt Pointer to the event structure containing client association details.
	 * @param[out] cmd Array of command structures to be updated based on the event analysis.
	 *
	 * @returns int Status code indicating success or failure of the analysis.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the event and command pointers are valid before calling this function.
	 */
	int analyze_client_assoc(em_bus_event_t *evt, em_cmd_t *cmd[]);
	
	/**!
	 * @brief Analyzes the configuration renewal event and command.
	 *
	 * This function processes the configuration renewal event and updates the command array accordingly.
	 *
	 * @param[in] evt Pointer to the event structure containing the configuration renewal details.
	 * @param[out] cmd Array of command structures to be updated based on the event analysis.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the event and command pointers are valid before calling this function.
	 */
	int analyze_config_renew(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the device test based on the provided event and command.
	 *
	 * This function processes the event and command to perform a device test analysis.
	 *
	 * @param[in] evt Pointer to the event structure containing event details.
	 * @param[in] cmd Array of command structures to be analyzed.
	 *
	 * @returns int Status code indicating the result of the analysis.
	 * @retval 0 Success.
	 * @retval -1 Failure due to invalid parameters.
	 *
	 * @note Ensure that the event and command structures are properly initialized before calling this function.
	 */
	int analyze_dev_test(em_bus_event_t *evt, em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes radio metrics request.
	 *
	 * This function processes the radio metrics request encapsulated in the command array.
	 *
	 * @param[in] cmd Array of pointers to em_cmd_t structures containing the command data.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the command array is properly initialized before calling this function.
	 */
	int analyze_radio_metrics_req(em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the access point metrics request.
	 *
	 * This function processes the metrics request for access points.
	 *
	 * @param[in] cmd Array of pointers to em_cmd_t structures containing the command data.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the cmd array is properly initialized before calling this function.
	 */
	int analyze_ap_metrics_req(em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes client metrics request.
	 *
	 * This function processes the client metrics request encapsulated in the command array.
	 *
	 * @param[in] cmd Array of pointers to em_cmd_t structures representing the client metrics request.
	 *
	 * @returns int Status code indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the command array is properly initialized before calling this function.
	 */
	int analyze_client_metrics_req(em_cmd_t *cmd[]);
    
	/**!
	 * @brief Analyzes the MLD reconfiguration command.
	 *
	 * This function processes the MLD reconfiguration command provided in the
	 * em_cmd_t structure array.
	 *
	 * @param[in] pcmd Array of pointers to em_cmd_t structures containing the
	 * MLD reconfiguration commands to be analyzed.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note Ensure that the pcmd array is properly initialized before calling
	 * this function.
	 */
	int analyze_mld_reconfig(em_cmd_t *pcmd[]);

	/**!
	 * @brief Analyzes the Backhaul STA capability query command.
	 *
	 * This function processes the Backhaul STA capability query command provided in the
	 * em_cmd_t structure array.
	 *
	 * @param[in] evt Pointer to the event structure containing event details.
	 * @param[in] pcmd Array of command structures to be analyzed.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note Ensure that the pcmd array is properly initialized before calling
	 * this function.
	 */
	int analyze_bsta_cap_req(em_bus_event_t *evt, em_cmd_t *pcmd[]);

	/**!
	 * @brief Resets the configuration to its default state.
	 *
	 * This function is responsible for resetting all configuration settings
	 * to their default values, ensuring a clean state for the mesh control.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that all necessary preconditions are met before calling
	 * this function to avoid unexpected behavior.
	 */
	int reset_config();

    using dm_scan_result_list_t::set_config;
    using dm_scan_result_list_t::get_config;

    
	/**!
	 * @brief Retrieves the station configuration based on the provided key and reason.
	 *
	 * This function searches for the station configuration within the given JSON parent object
	 * using the specified key and reason. It returns an integer status code indicating the
	 * success or failure of the operation.
	 *
	 * @param[in] parent The JSON object containing the station configurations.
	 * @param[in] key The key used to identify the specific station configuration.
	 * @param[in] reason The reason for retrieving the station list, default is none.
	 * @param[in] subdoc buffer pointer to the structure where the sub-document information
	 * will be stored.
	 *
	 * @returns int Status code of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object and key are valid before calling this function.
	 */
	int get_sta_config(cJSON *parent, char *key, em_get_sta_list_reason_t reason = em_get_sta_list_reason_none, char *data = NULL);
    
	/**!
	 * @brief Retrieves the BSS configuration from a JSON object.
	 *
	 * This function searches for a specific key within a JSON object and retrieves
	 * the corresponding BSS configuration.
	 *
	 * @param[in] parent The JSON object containing the BSS configurations.
	 * @param[in] key The key to search for within the JSON object.
	 *
	 * @returns An integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 if the key is not found or an error occurs.
	 *
	 * @note Ensure that the JSON object and key are valid before calling this function.
	 */
	int get_bss_config(cJSON *parent, char *key);
    
	/**!
	 * @brief Retrieves the network configuration based on the provided key.
	 *
	 * This function searches within the given JSON object to find the network configuration
	 * associated with the specified key.
	 *
	 * @param[in] parent The JSON object containing network configurations.
	 * @param[in] key The key used to identify the specific network configuration.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object and key are valid before calling this function.
	 */
	int get_network_config(cJSON *parent, char *key);
    
	/**!
	 * @brief Retrieves the device configuration based on the specified key.
	 *
	 * This function searches for the configuration data within the provided JSON object
	 * and returns the corresponding value associated with the given key.
	 *
	 * @param[in] parent The JSON object containing the device configuration data.
	 * @param[in] key The key for which the configuration value is to be retrieved.
	 * @param[in] summary Optional parameter to specify if a summary of the configuration is required.
	 *
	 * @returns int Status code indicating the success or failure of the operation.
	 *
	 * @retval 0 on success.
	 * @retval -1 if the key is not found or an error occurs.
	 *
	 * @note Ensure that the JSON object is properly initialized before calling this function.
	 */
	int get_device_config(cJSON *parent, char *key, bool summary = false);
    
	/**!
	 * @brief Retrieves the radio configuration based on the specified reason.
	 *
	 * This function fetches the radio configuration details and populates the provided JSON object.
	 *
	 * @param[out] parent A pointer to a cJSON object where the radio configuration will be stored.
	 * @param[in] key A string representing the key for the radio configuration.
	 * @param[in] reason An optional parameter specifying the reason for fetching the radio list. Defaults to em_get_radio_list_reason_none.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the parent cJSON object is initialized before calling this function.
	 */
	int get_radio_config(cJSON *parent, char *key, em_get_radio_list_reason_t reason = em_get_radio_list_reason_none);
    
	/**!
	 * @brief Retrieves the network SSID configuration from the given JSON object.
	 *
	 * This function searches for the specified key within the JSON object and
	 * returns the corresponding SSID configuration.
	 *
	 * @param[in] parent The JSON object containing network configurations.
	 * @param[in] key The key associated with the SSID configuration to retrieve.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 if the key is not found or an error occurs.
	 *
	 * @note Ensure that the JSON object and key are valid before calling this function.
	 */
	int get_network_ssid_config(cJSON *parent, char *key);
    
	/**!
	 * @brief Retrieves the channel configuration based on the provided parameters.
	 *
	 * This function accesses the JSON object to extract channel configuration
	 * using the specified key and reason.
	 *
	 * @param[in] parent The JSON object containing channel configurations.
	 * @param[in] key The key used to identify the specific channel configuration.
	 * @param[in] reason The reason for getting the channel list, default is none.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object and key are valid before calling this function.
	 */
	int get_channel_config(cJSON *parent, char *key, em_get_channel_list_reason_t reason = em_get_channel_list_reason_none);
    
	/**!
	 * @brief Retrieves the policy configuration based on the provided key.
	 *
	 * This function searches for the specified key within the given JSON object and returns the associated policy configuration.
	 *
	 * @param[in] parent A pointer to the cJSON object representing the parent JSON structure.
	 * @param[in] key A character pointer to the key whose policy configuration is to be retrieved.
	 *
	 * @returns An integer indicating the success or failure of the operation.
	 * @retval 0 on success.
	 * @retval -1 if the key is not found or an error occurs.
	 *
	 * @note Ensure that the cJSON object and key are valid before calling this function.
	 */
	int get_policy_config(cJSON *parent, char *key);
    
	/**!
	 * @brief Retrieves the scan result from the specified JSON object.
	 *
	 * This function searches for the scan result associated with the given key
	 * within the provided JSON parent object.
	 *
	 * @param[in] parent The JSON object containing the scan results.
	 * @param[in] key The key associated with the desired scan result.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 if the key is not found or an error occurs.
	 *
	 * @note Ensure that the JSON object and key are valid before calling this function.
	 */
	int get_scan_result(cJSON *parent, char *key);
    
	/**!
	 * @brief Retrieves the MLD configuration from the given JSON object.
	 *
	 * This function searches for the specified key within the JSON object
	 * and returns the associated MLD configuration.
	 *
	 * @param[in] parent The JSON object containing the configuration data.
	 * @param[in] key The key to search for within the JSON object.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 if the key is not found or an error occurs.
	 *
	 * @note Ensure that the JSON object is properly initialized before calling this function.
	 */
	int get_mld_config(cJSON *parent, char *key);
    
    /**!
	 * @brief Retrieves the wifi reset configuration from the given JSON object.
	 *
	 * This function searches for the specified key within the JSON object
	 * and returns the associated wifi reset configuration.
	 *
	 * @param[in] parent The JSON object containing the configuration data.
	 * @param[in] key The key to search for within the JSON object.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 if the key is not found or an error occurs.
	 *
	 * @note Ensure that the JSON object is properly initialized before calling this function.
	 */
	int get_wifi_reset_config(cJSON *parent, char *key);

	/**!
	 * @brief Retrieves the wifi channel capability from the given JSON object.
	 *
	 * This function searches for the specified key within the JSON object
	 * and returns the associated wifi channel capability.
	 *
	 * @param[in] parent The JSON object containing the configuration data.
	 * @param[in] key The key to search for within the JSON object.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 if the key is not found or an error occurs.
	 *
	 * @note Ensure that the JSON object is properly initialized before calling this function.
	 */
	int get_channel_capabilities (cJSON *parent, char *key);

	/**!
	 * @brief Retrieves the reference configuration based on the provided key.
	 *
	 * This function searches within the given JSON object to find the configuration
	 * associated with the specified key.
	 *
	 * @param[in] parent The JSON object where the search is performed.
	 * @param[in] key The key used to locate the reference configuration within the JSON object.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 if the key is not found or an error occurs.
	 *
	 * @note Ensure that the JSON object and key are valid before calling this function.
	 */
	int get_reference_config(cJSON *parent, char *key);
    
	/**!
	 * @brief Retrieves the configuration for a given network identifier.
	 *
	 * This function fetches the configuration details associated with the specified
	 * network identifier and populates the provided sub-document information structure.
	 *
	 * @param[in] net_id The network identifier for which the configuration is requested.
	 * @param[out] subdoc Pointer to the structure where the sub-document information
	 * will be stored.
	 *
	 * @note Ensure that the subdoc pointer is valid and points to a properly allocated
	 * em_subdoc_info_t structure before calling this function.
	 */
	void get_config(em_long_string_t net_id, em_subdoc_info_t *subdoc);
    
	/**!
	* @brief Sets the configuration for the Easy Mesh.
	*
	* This function configures the Easy Mesh settings using the provided
	* dm_easy_mesh_t structure.
	*
	* @param[in] dm Pointer to the dm_easy_mesh_t structure containing
	* the configuration settings.
	*
	* @returns int
	* @retval 0 on success
	* @retval -1 on failure
	*
	* @note Ensure that the dm pointer is valid and properly initialized
	* before calling this function.
	*/
	int set_config(dm_easy_mesh_t *dm);
    
	/**!
	 * @brief Copies the configuration from the given network ID to the easy mesh structure.
	 *
	 * This function takes a network ID and copies the corresponding configuration
	 * into the provided easy mesh structure.
	 *
	 * @param[out] dm Pointer to the easy mesh structure where the configuration will be copied.
	 * @param[in] net_id The network ID from which the configuration is to be copied.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the `dm` pointer is valid and properly initialized before calling this function.
	 */
	int copy_config(dm_easy_mesh_t *dm, em_long_string_t net_id);

    
	/**!
	 * @brief Retrieves the control AL interface for a given network ID.
	 *
	 * This function returns a pointer to the control AL interface associated with the specified network ID.
	 *
	 * @param[in] net_id The network ID for which the control AL interface is requested.
	 *
	 * @returns A pointer to the em_interface_t structure representing the control AL interface.
	 * @retval nullptr If the network ID is not found or an error occurs.
	 *
	 * @note Ensure that the network ID provided is valid and exists in the network list.
	 */
	em_interface_t *get_ctrl_al_interface(em_long_string_t net_id) { return dm_network_list_t::get_ctrl_al_interface(net_id); }

    
	/**!
	 * @brief Retrieves the data model for a given network ID and AL MAC address.
	 *
	 * This function searches for and returns a pointer to the data model associated
	 * with the specified network identifier and AL MAC address.
	 *
	 * @param[in] net_id The network identifier for which the data model is requested.
	 * @param[in] al_mac The AL MAC address associated with the data model.
	 *
	 * @returns A pointer to the `dm_easy_mesh_t` structure representing the data model.
	 * @retval NULL if the data model is not found or an error occurs.
	 *
	 * @note Ensure that the `net_id` and `al_mac` are valid and correspond to an existing
	 * data model in the system.
	 */
	dm_easy_mesh_t	*get_data_model(const char *net_id, const unsigned char *al_mac);   
    
	/**!
	 * @brief Creates a data model for the EasyMesh network.
	 *
	 * This function initializes and returns a pointer to a new EasyMesh data model
	 * based on the provided network identifier, interface, and profile type.
	 *
	 * @param[in] net_id A constant character pointer representing the network identifier.
	 * @param[in] al_intf A pointer to the em_interface_t structure representing the interface.
	 * @param[in] profile An em_profile_type_t value indicating the profile type.
	 *
	 * @returns A pointer to the newly created dm_easy_mesh_t structure.
	 * @retval NULL if the creation fails due to invalid parameters or memory allocation issues.
	 *
	 * @note Ensure that the network identifier and interface are valid before calling this function.
	 */
	dm_easy_mesh_t	*create_data_model(const char *net_id, const em_interface_t *al_intf, em_profile_type_t profile);    

	
	/**!
	 * @brief Retrieves the first data model from the list.
	 *
	 * @returns A pointer to the first data model in the list.
	 */
	dm_easy_mesh_t *get_first_dm() { return m_data_model_list.get_first_dm(); }
	
	/**!
	 * @brief Retrieves the next data model in the list.
	 *
	 * This function returns the next data model object from the list of data models.
	 *
	 * @param[in] dm A pointer to the current data model object.
	 *
	 * @returns A pointer to the next data model object in the list.
	 * @retval nullptr If there is no next data model.
	 *
	 * @note Ensure that the input data model pointer is valid before calling this function.
	 */
	dm_easy_mesh_t *get_next_dm(dm_easy_mesh_t *dm) { return m_data_model_list.get_next_dm(dm); }

    
	/**!
	 * @brief Retrieves the first network from the data model list.
	 *
	 * This function returns a pointer to the first network object in the data model list.
	 *
	 * @returns A pointer to the first network object of type dm_network_t.
	 * @retval nullptr If the data model list is empty.
	 *
	 * @note Ensure that the data model list is initialized before calling this function.
	 */
	dm_network_t *get_first_network() { return m_data_model_list.get_first_network(); }
    
	/**!
	 * @brief Retrieves the next network in the data model list.
	 *
	 * This function returns the next network object following the provided network
	 * in the data model list. If the provided network is the last in the list,
	 * the function may return a null pointer or handle it as per implementation.
	 *
	 * @param[in] net A pointer to the current network object from which the next
	 * network is to be retrieved.
	 *
	 * @returns A pointer to the next network object in the list.
	 * @retval nullptr If the provided network is the last in the list or if the
	 * list is empty.
	 *
	 * @note Ensure that the provided network pointer is valid and part of the
	 * data model list to avoid undefined behavior.
	 */
	dm_network_t *get_next_network(dm_network_t *net) { return m_data_model_list.get_next_network(net); }
    
	/**!
	 * @brief Retrieves the network associated with the given key.
	 *
	 * This function searches for and returns the network object that corresponds
	 * to the specified key from the data model list.
	 *
	 * @param[in] key A constant character pointer representing the key used to
	 * identify the network.
	 *
	 * @returns A pointer to the dm_network_t object associated with the given key.
	 * @retval nullptr If no network is found for the specified key.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing
	 * network in the data model list.
	 */
	dm_network_t *get_network(const char *key) { return m_data_model_list.get_network(key); }
    
	/**!
	 * @brief Removes a network from the data model list.
	 *
	 * This function removes the network identified by the given key from the data model list.
	 *
	 * @param[in] key A pointer to a character string representing the key of the network to be removed.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing network in the list.
	 */
	void remove_network(const char *key) { m_data_model_list.remove_network(key); }
    
	/**!
	 * @brief Puts a network into the data model list.
	 *
	 * This function adds a network to the data model list using the provided key.
	 *
	 * @param[in] key A constant character pointer representing the key associated with the network.
	 * @param[in] net A pointer to a dm_network_t structure representing the network to be added.
	 *
	 * @note Ensure that the key and network are valid before calling this function.
	 */
	void put_network(const char *key, const dm_network_t *net) { m_data_model_list.put_network(key, net); }
    
    
	/**!
	 * @brief Retrieves the first device from the data model list.
	 *
	 * This function returns a pointer to the first device in the data model list.
	 *
	 * @returns A pointer to the first device in the data model list.
	 * @retval nullptr if the list is empty.
	 *
	 * @note Ensure that the data model list is initialized before calling this function.
	 */
	dm_device_t *get_first_device() { return m_data_model_list.get_first_device(); }
    
	/**!
	 * @brief Retrieves the next device in the data model list.
	 *
	 * This function takes a device pointer and returns the next device in the list.
	 *
	 * @param[in] dev Pointer to the current device.
	 *
	 * @returns Pointer to the next device in the list.
	 * @retval NULL if there is no next device.
	 *
	 * @note Ensure that the device pointer is valid before calling this function.
	 */
	dm_device_t *get_next_device(dm_device_t *dev) { return m_data_model_list.get_next_device(dev); }
    
	/**!
	 * @brief Retrieves a device from the data model list using a specified key.
	 *
	 * This function searches for a device in the data model list that matches the given key and returns a pointer to the device if found.
	 *
	 * @param[in] key A constant character pointer representing the key used to search for the device.
	 *
	 * @returns A pointer to the dm_device_t structure representing the device if found, otherwise NULL.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing device in the data model list.
	 */
	dm_device_t *get_device(const char *key) { return m_data_model_list.get_device(key); }
    
	/**!
	 * @brief Removes a device from the data model list.
	 *
	 * This function removes a device identified by the given key from the data model list.
	 *
	 * @param[in] key A constant character pointer representing the key of the device to be removed.
	 *
	 * @note Ensure that the key provided is valid and exists in the data model list to avoid unexpected behavior.
	 */
	void remove_device(const char *key) { m_data_model_list.remove_device(key); }
    
	/**!
	 * @brief Adds a device to the data model list.
	 *
	 * This function inserts a device into the data model list using the specified key.
	 *
	 * @param[in] key The key associated with the device.
	 * @param[in] dev Pointer to the device structure to be added.
	 *
	 * @note Ensure that the key and device are valid before calling this function.
	 */
	void put_device(const char *key, const dm_device_t *dev) { m_data_model_list.put_device(key, dev); }

	void update_device(const char *key, const dm_device_t *dev) { m_data_model_list.update_device(key, dev); }
    
	/**!
	 * @brief Retrieves the first radio from the data model list.
	 *
	 * This function returns a pointer to the first radio object available in the data model list.
	 *
	 * @returns A pointer to the first `dm_radio_t` object.
	 * @retval nullptr If the data model list is empty.
	 *
	 * @note Ensure that the data model list is initialized before calling this function.
	 */
	dm_radio_t *get_first_radio() { return m_data_model_list.get_first_radio(); }
    
	/**!
	 * @brief Retrieves the next radio in the data model list.
	 *
	 * This function returns the next radio object in the sequence from the given radio object.
	 *
	 * @param[in] radio A pointer to the current radio object from which the next radio is to be retrieved.
	 *
	 * @returns A pointer to the next radio object in the data model list.
	 * @retval NULL if there is no next radio in the list.
	 *
	 * @note Ensure that the radio object passed is valid and part of the data model list.
	 */
	dm_radio_t *get_next_radio(dm_radio_t *radio) { return m_data_model_list.get_next_radio(radio); }
    
	/**!
	 * @brief Retrieves a radio object based on the provided key.
	 *
	 * This function searches for a radio object in the data model list using the specified key.
	 *
	 * @param[in] key A constant character pointer representing the key used to find the radio.
	 *
	 * @returns A pointer to the dm_radio_t object if found, otherwise NULL.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing radio object.
	 */
	dm_radio_t *get_radio(const char *key) { return m_data_model_list.get_radio(key); }
    
	/**!
	 * @brief Removes a radio from the data model list.
	 *
	 * This function removes a radio identified by the given key from the data model list.
	 *
	 * @param[in] key A constant character pointer representing the key of the radio to be removed.
	 *
	 * @note Ensure that the key provided is valid and exists in the data model list.
	 */
	void remove_radio(const char *key) { m_data_model_list.remove_radio(key); }
    
	/**!
	 * @brief Puts a radio configuration into the data model list.
	 *
	 * This function inserts a radio configuration identified by a key into the data model list.
	 *
	 * @param[in] key A string representing the key associated with the radio configuration.
	 * @param[in] radio A pointer to a dm_radio_t structure containing the radio configuration.
	 *
	 * @note Ensure that the key and radio parameters are valid and properly initialized before calling this function.
	 */
	void put_radio(const char *key, const dm_radio_t *radio) { m_data_model_list.put_radio(key, radio); }

    
	/**!
	 * @brief Retrieves the first BSS (Basic Service Set) from the data model list.
	 *
	 * @returns A pointer to the first `dm_bss_t` object in the data model list.
	 * @retval nullptr if the data model list is empty.
	 */
	dm_bss_t *get_first_bss() { return m_data_model_list.get_first_bss(); }
    
	/**!
	 * @brief Retrieves the next BSS (Basic Service Set) from the data model list.
	 *
	 * This function is used to iterate over the BSS entries in the data model list.
	 *
	 * @param[in] bss A pointer to the current BSS entry. If NULL, the function returns the first BSS entry.
	 *
	 * @returns A pointer to the next BSS entry in the list. Returns NULL if there are no more entries.
	 *
	 * @note Ensure that the BSS list is not modified while iterating through it.
	 */
	dm_bss_t *get_next_bss(dm_bss_t *bss) { return m_data_model_list.get_next_bss(bss); }
    
	/**!
	 * @brief Retrieves the BSS object associated with the given key.
	 *
	 * This function searches for the BSS object in the data model list using the provided key.
	 *
	 * @param[in] key The key used to identify the BSS object.
	 *
	 * @returns A pointer to the dm_bss_t object if found, otherwise NULL.
	 *
	 * @note Ensure that the key is valid and corresponds to an existing BSS object.
	 */
	dm_bss_t *get_bss(const char *key) { return m_data_model_list.get_bss(key); }
    
	/**!
	 * @brief Removes a BSS entry from the data model list.
	 *
	 * This function removes a BSS (Basic Service Set) entry identified by the given key from the data model list.
	 *
	 * @param[in] key A constant character pointer representing the key of the BSS entry to be removed.
	 *
	 * @note Ensure that the key provided is valid and exists in the data model list to avoid undefined behavior.
	 */
	void remove_bss(const char *key) { m_data_model_list.remove_bss(key); }
    
	/**!
	 * @brief Puts a BSS entry into the data model list.
	 *
	 * This function inserts a BSS (Basic Service Set) entry into the data model list using the provided key.
	 *
	 * @param[in] key A pointer to a character string representing the key associated with the BSS entry.
	 * @param[in] bss A pointer to a dm_bss_t structure containing the BSS information to be inserted.
	 *
	 * @note Ensure that the key and bss pointers are valid before calling this function.
	 */
	void put_bss(const char *key, const dm_bss_t *bss) { m_data_model_list.put_bss(key, bss); }

    
	/**!
	 * @brief Retrieves the first station object from the data model list.
	 *
	 * This function accesses the data model list and returns the first station object available.
	 *
	 * @returns A pointer to the first `dm_sta_t` object in the data model list.
	 * @retval nullptr If the data model list is empty or no station object is found.
	 *
	 * @note Ensure that the data model list is properly initialized before calling this function.
	 */
	dm_sta_t *get_first_sta() { return m_data_model_list.get_first_sta(); }
    
	/**!
	 * @brief Retrieves the next station in the data model list.
	 *
	 * This function takes a pointer to a station and returns a pointer to the next station in the list.
	 *
	 * @param[in] sta Pointer to the current station.
	 *
	 * @returns Pointer to the next station in the list.
	 *
	 * @note If the current station is the last in the list, the function may return a null pointer.
	 */
	dm_sta_t *get_next_sta(dm_sta_t *sta) { return m_data_model_list.get_next_sta(sta); }
    
	/**!
	 * @brief Retrieves a station object based on the provided key.
	 *
	 * This function searches for a station object in the data model list using the specified key.
	 *
	 * @param[in] key A constant character pointer representing the key used to search for the station.
	 *
	 * @returns A pointer to the `dm_sta_t` object if found, otherwise returns `nullptr`.
	 *
	 * @note Ensure that the key provided is valid and corresponds to an existing station in the data model list.
	 */
	dm_sta_t *get_sta(const char *key) { return m_data_model_list.get_sta(key); }
    
	/**!
	 * @brief Removes a station from the data model list.
	 *
	 * This function removes a station identified by the given key from the data model list.
	 *
	 * @param[in] key A constant character pointer representing the key of the station to be removed.
	 *
	 * @note Ensure that the key provided is valid and exists in the data model list.
	 */
	void remove_sta(const char *key) { m_data_model_list.remove_sta(key); }
    
	/**!
	 * @brief Puts a station entry into the data model list.
	 *
	 * This function adds a station entry identified by a key into the data model list.
	 *
	 * @param[in] key A constant character pointer representing the key for the station entry.
	 * @param[in] sta A pointer to a `dm_sta_t` structure containing the station data to be added.
	 *
	 * @note Ensure that the `key` and `sta` are valid and properly initialized before calling this function.
	 */
	void put_sta(const char *key, const dm_sta_t *sta) { m_data_model_list.put_sta(key, sta); }

    
	/**!
	 * @brief Retrieves the first operational class from the data model list.
	 *
	 * @returns A pointer to the first operational class.
	 *
	 * @note This function assumes that the data model list is properly initialized and contains at least one operational class.
	 */
	dm_op_class_t *get_first_op_class() { return m_data_model_list.get_first_op_class(); }
    
	/**!
	 * @brief Retrieves the next operational class from the data model list.
	 *
	 * This function takes a pointer to a current operational class and returns a pointer to the next operational class in the list.
	 *
	 * @param[in] op_class Pointer to the current operational class.
	 *
	 * @returns Pointer to the next operational class in the list.
	 * @retval nullptr if there is no next operational class.
	 *
	 * @note Ensure that the provided op_class is valid and part of the data model list.
	 */
	dm_op_class_t *get_next_op_class(dm_op_class_t *op_class) { return m_data_model_list.get_next_op_class(op_class); }
    
	/**!
	 * @brief Retrieves the operational class associated with the given key.
	 *
	 * This function searches for the operational class in the data model list using the specified key.
	 *
	 * @param[in] key The key used to identify the operational class.
	 *
	 * @returns A pointer to the dm_op_class_t associated with the key.
	 * @retval nullptr If the key does not correspond to any operational class.
	 *
	 * @note Ensure that the key is valid and corresponds to an existing operational class.
	 */
	dm_op_class_t *get_op_class(const char *key) { return m_data_model_list.get_op_class(key); }
    
	/**!
	 * @brief Removes an operational class from the data model list.
	 *
	 * This function removes the specified operational class identified by the key from the data model list.
	 *
	 * @param[in] key A constant character pointer representing the key of the operational class to be removed.
	 *
	 * @note Ensure that the key provided is valid and exists in the data model list to avoid unexpected behavior.
	 */
	void remove_op_class(const char *key) { m_data_model_list.remove_op_class(key); }
    
	/**!
	 * @brief Puts an operation class into the data model list.
	 *
	 * This function inserts the specified operation class into the data model list using the provided key.
	 *
	 * @param[in] key The key associated with the operation class.
	 * @param[in] op_class Pointer to the operation class to be inserted.
	 *
	 * @note Ensure that the key and op_class are valid and properly initialized before calling this function.
	 */
	void put_op_class(const char *key, const dm_op_class_t *op_class) { m_data_model_list.put_op_class(key, op_class); }
	
	/**!
	 * @brief Retrieves the first pre-set operational class by type.
	 *
	 * This function searches for and returns the first pre-set operational class
	 * that matches the specified type from the data model list.
	 *
	 * @param[in] type The type of operational class to search for.
	 *
	 * @returns A pointer to the first pre-set operational class of the specified type.
	 * @retval nullptr If no matching operational class is found.
	 *
	 * @note Ensure that the data model list is initialized before calling this function.
	 */
	dm_op_class_t *get_first_pre_set_op_class_by_type(em_op_class_type_t type) { return m_data_model_list.get_first_pre_set_op_class_by_type(type); }
    
	/**!
	 * @brief Retrieves the next pre-set operational class based on the specified type.
	 *
	 * This function searches for the next operational class in the list that matches the given type.
	 *
	 * @param[in] type The type of operational class to search for.
	 * @param[in] op_class A pointer to the current operational class from which to start the search.
	 *
	 * @returns A pointer to the next pre-set operational class of the specified type.
	 * @retval NULL if no matching operational class is found.
	 *
	 * @note Ensure that the op_class pointer is valid before calling this function.
	 */
	dm_op_class_t *get_next_pre_set_op_class_by_type(em_op_class_type_t type, dm_op_class_t *op_class) { return m_data_model_list.get_next_pre_set_op_class_by_type(type, op_class); }

    
	/**!
	 * @brief Retrieves the first network SSID from the data model list.
	 *
	 * @returns A pointer to the first network SSID.
	 *
	 * @note This function accesses the data model list to obtain the SSID.
	 */
	dm_network_ssid_t *get_first_network_ssid() { return m_data_model_list.get_first_network_ssid(); }
    
	/**!
	 * @brief Retrieves the next network SSID from the data model list.
	 *
	 * This function takes a pointer to a network SSID and returns the next network SSID in the list.
	 *
	 * @param[in] network_ssid Pointer to the current network SSID.
	 *
	 * @returns Pointer to the next network SSID in the list.
	 *
	 * @note If the current network SSID is the last in the list, the function may return a null pointer.
	 */
	dm_network_ssid_t *get_next_network_ssid(dm_network_ssid_t *network_ssid) { return m_data_model_list.get_next_network_ssid(network_ssid); }
    
	/**!
	 * @brief Retrieves the network SSID associated with the given key.
	 *
	 * This function searches for the network SSID using the provided key and returns it.
	 *
	 * @param[in] key A constant character pointer representing the key to search for the network SSID.
	 *
	 * @returns A pointer to a dm_network_ssid_t structure containing the network SSID if found, otherwise NULL.
	 *
	 * @note Ensure that the key provided is valid and exists in the data model list.
	 */
	dm_network_ssid_t *get_network_ssid(const char *key) { return m_data_model_list.get_network_ssid(key); }
    
	/**!
	 * @brief Removes a network SSID from the data model list.
	 *
	 * This function removes the specified network SSID from the internal data model list.
	 *
	 * @param[in] key The SSID key to be removed from the list.
	 *
	 * @note Ensure that the key provided is valid and exists in the list to avoid unexpected behavior.
	 */
	void remove_network_ssid(const char *key) { m_data_model_list.remove_network_ssid(key); }
    
	/**!
	 * @brief Puts the network SSID into the data model list.
	 *
	 * This function stores the provided network SSID associated with the given key into the data model list.
	 *
	 * @param[in] key The key associated with the network SSID.
	 * @param[in] network_ssid Pointer to the network SSID structure to be stored.
	 *
	 * @note Ensure that the key and network_ssid are valid and properly initialized before calling this function.
	 */
	void put_network_ssid(const char *key, const dm_network_ssid_t *network_ssid) { m_data_model_list.put_network_ssid(key, network_ssid); }

	
	/**!
	 * @brief Retrieves the first policy from the data model list.
	 *
	 * @returns A pointer to the first policy in the data model list.
	 */
	dm_policy_t *get_first_policy() { return m_data_model_list.get_first_policy(); }
    
	/**!
	 * @brief Retrieves the next policy in the data model list.
	 *
	 * This function returns the next policy object following the given policy in the data model list.
	 *
	 * @param[in] policy A pointer to the current policy object.
	 *
	 * @returns A pointer to the next policy object in the list.
	 * @retval NULL if there is no subsequent policy.
	 *
	 * @note Ensure that the policy parameter is not NULL before calling this function.
	 */
	dm_policy_t *get_next_policy(dm_policy_t *policy) { return m_data_model_list.get_next_policy(policy); }
    
	/**!
	 * @brief Retrieves the policy associated with the specified key.
	 *
	 * This function searches for the policy corresponding to the given key
	 * in the data model list and returns it.
	 *
	 * @param[in] key The key for which the policy is to be retrieved.
	 *
	 * @returns A pointer to the dm_policy_t associated with the key.
	 * @retval NULL if the key is not found or an error occurs.
	 *
	 * @note Ensure that the key is valid and exists in the data model list.
	 */
	dm_policy_t *get_policy(const char *key) { return m_data_model_list.get_policy(key); }
    
	/**!
	 * @brief Removes a policy from the data model list.
	 *
	 * This function removes a policy identified by the given key from the data model list.
	 *
	 * @param[in] key The key identifying the policy to be removed.
	 *
	 * @note Ensure that the key exists in the data model list before calling this function.
	 */
	void remove_policy(const char *key) { m_data_model_list.remove_policy(key); }
    
	/**!
	 * @brief Puts a policy into the data model list.
	 *
	 * This function adds or updates a policy in the data model list using the specified key.
	 *
	 * @param[in] key The key associated with the policy to be added or updated.
	 * @param[in] policy A pointer to the policy data to be added or updated.
	 *
	 * @note Ensure that the key and policy are valid and properly initialized before calling this function.
	 */
	void put_policy(const char *key, const dm_policy_t *policy) { m_data_model_list.put_policy(key, policy); }

	
	/**!
	 * @brief Retrieves the first scan result from the data model list.
	 *
	 * @returns A pointer to the first scan result of type dm_scan_result_t.
	 * @retval nullptr if the list is empty or no result is available.
	 *
	 * @note Ensure that the data model list is initialized before calling this function.
	 */
	dm_scan_result_t *get_first_scan_result() { return m_data_model_list.get_first_scan_result(); }
    
	/**!
	 * @brief Retrieves the next scan result from the data model list.
	 *
	 * This function takes a pointer to a scan result and returns the next scan result in the list.
	 *
	 * @param[in] scan_result Pointer to the current scan result.
	 *
	 * @returns Pointer to the next scan result in the list.
	 *
	 * @note If the current scan result is the last in the list, the function may return NULL.
	 */
	dm_scan_result_t *get_next_scan_result(dm_scan_result_t *scan_result) { return m_data_model_list.get_next_scan_result(scan_result); }
    
	/**!
	 * @brief Retrieves the scan result associated with the given key.
	 *
	 * This function searches for the scan result in the data model list using the specified key.
	 *
	 * @param[in] key The key used to identify the scan result.
	 *
	 * @returns A pointer to the dm_scan_result_t structure containing the scan result.
	 * @retval NULL if no scan result is found for the given key.
	 *
	 * @note Ensure that the key is valid and corresponds to an existing scan result.
	 */
	dm_scan_result_t *get_scan_result(const char *key) { return m_data_model_list.get_scan_result(key); }
    
	/**!
	 * @brief Removes a scan result from the data model list.
	 *
	 * This function removes a scan result identified by the given key from the data model list.
	 *
	 * @param[in] key A constant character pointer representing the key of the scan result to be removed.
	 *
	 * @note Ensure that the key provided is valid and exists in the data model list to avoid unexpected behavior.
	 */
	void remove_scan_result(const char *key) { m_data_model_list.remove_scan_result(key); }
    
	/**!
	 * @brief Puts a scan result into the data model list.
	 *
	 * This function inserts a scan result associated with a specific key into the data model list.
	 *
	 * @param[in] key A constant character pointer representing the key associated with the scan result.
	 * @param[in] scan_result A pointer to a dm_scan_result_t structure containing the scan result data to be inserted.
   * @param[in] index An unsigned integer where the scan result data is to be inserted.
	 *
	 * @note Ensure that the key and scan_result are valid and properly initialized before calling this function.
	 */
	void put_scan_result(const char *key, const dm_scan_result_t *scan_result, unsigned int index) { m_data_model_list.put_scan_result(key, scan_result, index); }

	
	/**!
	 * @brief Initializes the network topology.
	 *
	 * This function sets up the initial configuration for the network topology,
	 * preparing it for further operations.
	 *
	 * @note Ensure that all necessary configurations are set before calling this function.
	 */
	void init_network_topology();
    
	/**!
	 * @brief Updates the network topology.
	 *
	 * This function is responsible for updating the current network topology
	 * based on the latest configuration and status of the mesh network.
	 *
	 * @note Ensure that the network configuration is properly initialized
	 * before calling this function.
	 */
	void update_network_topology();

	/**!
	 * @brief Publish the network topology.
	 *
	 * This function is responsible for publishing the current network topology
	 * over the bus.
	 *
	 * @note Ensure that the network topology is properly updated
	 * before calling this function.
	 */
	void publish_network_topology();
    
	/**!
	 * @brief Handles the dirty data management process.
	 *
	 * This function is responsible for managing and processing any dirty data
	 * that needs to be handled within the system.
	 *
	 * @note Ensure that the data is properly initialized before calling this function.
	 */
	void handle_dirty_dm();
    
	/**!
	* @brief Initializes the tables used in the mesh control module.
	*
	* This function sets up the necessary data structures and state for the mesh control operations.
	*
	* @note This function should be called before any other mesh control operations are performed.
	*/
	void init_tables();
    
	/**!
	 * @brief Loads the necessary tables for the mesh control.
	 *
	 * This function initializes and loads the tables required for the easy mesh control operations.
	 *
	 * @returns int
	 * @retval  0 on success
	 * @retval -1 on empty data base
	 * @retval >0 on failure
	 *
	 * @note Ensure that the system is properly initialized before calling this function.
	 */
	int load_tables();
    
	/**!
	 * @brief Loads the network SSID table.
	 *
	 * This function is responsible for loading the SSID table for the network.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the network configuration is initialized before calling this function.
	 */
	int load_net_ssid_table();
    
	/**!
	 * @brief Updates the tables associated with the Easy Mesh instance.
	 *
	 * This function is responsible for updating the internal tables
	 * of the Easy Mesh instance provided.
	 *
	 * @param[in] dm Pointer to the Easy Mesh instance to be updated.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the Easy Mesh instance is properly initialized
	 * before calling this function.
	 */
	int update_tables(dm_easy_mesh_t *dm);
    
	/**!
	 * @brief Deletes a data model associated with the given network ID and AL MAC address.
	 *
	 * This function removes the data model from the list based on the provided identifiers.
	 *
	 * @param[in] net_id The network ID associated with the data model to be deleted.
	 * @param[in] al_mac The AL MAC address associated with the data model to be deleted.
	 *
	 * @note Ensure that the identifiers provided are valid and exist in the data model list.
	 */
	void delete_data_model(const char *net_id, const unsigned char *al_mac) { m_data_model_list.delete_data_model(net_id, al_mac); }
    
	/**!
	 * @brief Deletes all data models from the list.
	 *
	 * This function calls the delete_all_data_models method on the m_data_model_list object,
	 * effectively removing all data models contained within it.
	 *
	 * @note Ensure that any necessary data is backed up before calling this function,
	 * as it will permanently remove all data models.
	 */
	void delete_all_data_models() { m_data_model_list.delete_all_data_models(); }
    
	/**!
	 * @brief Debugs the probe for the data model list.
	 *
	 * This function calls the debug_probe method on the m_data_model_list object.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void debug_probe() { m_data_model_list.debug_probe(); }

    
	/**!
	* @brief Constructor for the dm_easy_mesh_ctrl_t class.
	*
	* Initializes a new instance of the dm_easy_mesh_ctrl_t class.
	*
	* @note This constructor does not take any parameters and does not return any values.
	*/
	dm_easy_mesh_ctrl_t();
    
	/**!
	 * @brief Destructor for the dm_easy_mesh_ctrl_t class.
	 *
	 * This function cleans up resources allocated by the dm_easy_mesh_ctrl_t instance.
	 *
	 * @note Ensure that all operations using the dm_easy_mesh_ctrl_t instance are completed before calling the destructor.
	 */
	~dm_easy_mesh_ctrl_t(); 
};

#endif

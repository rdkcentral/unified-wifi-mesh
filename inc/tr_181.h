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

#ifndef TR_181_H
#define TR_181_H

#include "em_ctrl.h"
#include "bus.h"
#include <string>
#include <memory>

// TR-181 specific definitions
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_COLOCATEDAGENTID    "Device.WiFi.DataElements.Network.ColocatedAgentID"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_CONTROLLERID        "Device.WiFi.DataElements.Network.ControllerID"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD        "Device.WiFi.DataElements.Network.SetSSID"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_TOPOLOGY           "Device.WiFi.DataElements.Network.Topology"

// Data model helper macros
#define DM_CHECK_NULL_WITH_RC(ptr, rc) \
    do { \
        if ((ptr) == NULL) { \
            em_printfout("Parameter '%s' is NULL\n", \
                   __func__, __LINE__, #ptr); \
            return (rc); \
        } \
    } while (0)

// Structure definitions
typedef struct scratch_data_buff {
    void     *buff;
    uint32_t buff_len;
} scratch_data_buff_t;

typedef struct wifi_dml_data_model {
    uint32_t table_radio_index;
    uint32_t table_ap_index;
    uint32_t table_ssid_index;
    uint32_t table_macfilter_index[16];
    uint32_t table_sta_assoc_index[16];
    uint32_t table_neig_diag_result_index;
    char     str_wifi_region_update_source[16];
} wfa_dml_data_model_t;

typedef struct {
    em_short_string_t ssid;
    bool enable;
    em_short_string_t add_remove_change;
    em_short_string_t passphrase;
    em_short_string_t band;
    em_short_string_t akms_allowed;
    bool advertisement_enabled;
    em_short_string_t mfp_config;
    em_short_string_t mobility_domain;
    em_short_string_t haul_type;
} tr_cmd_setssid;

// Callback function typedefs
typedef bool (*dml_get_bool_cb_t)    (void *obj_ins_context, char *param_name, bool *value);
typedef bool (*dml_set_bool_cb_t)    (void *obj_ins_context, char *param_name, bool value);
typedef bool (*dml_get_int_cb_t)     (void *obj_ins_context, char *param_name, int *value);
typedef bool (*dml_set_int_cb_t)     (void *obj_ins_context, char *param_name, int value);
typedef bool (*dml_get_uint_cb_t)    (void *obj_ins_context, char *param_name, uint32_t *value);
typedef bool (*dml_set_uint_cb_t)    (void *obj_ins_context, char *param_name, uint32_t value);
typedef bool (*dml_get_string_cb_t)  (void *obj_ins_context, char *param_name, scratch_data_buff_t *value);
typedef bool (*dml_set_string_cb_t)  (void *obj_ins_context, char *param_name, scratch_data_buff_t *value);

typedef struct dml_callback_table {
    dml_get_bool_cb_t    get_bool_value;
    dml_get_int_cb_t     get_int_value;
    dml_get_uint_cb_t    get_uint_value;
    dml_get_string_cb_t  get_string_value;
    dml_set_bool_cb_t    set_bool_value;
    dml_set_int_cb_t     set_int_value;
    dml_set_uint_cb_t    set_uint_value;
    dml_set_string_cb_t  set_string_value;
} dml_callback_table_t;

class tr_181_t {
private:
    static tr_181_t* tr181_data_model_instance;
    bus_handle_t* bus_handle;
    //dm_easy_mesh_t* data_model;
    wfa_dml_data_model_t dml_model;
    
    // Private constructor for singleton
    tr_181_t();
    
    // Helper methods
    std::string trim(const std::string& str);
    
public:
    static tr_181_t* getInstance();
    
    // Delete copy constructor and assignment
    tr_181_t(const tr_181_t&) = delete;
    tr_181_t& operator=(const tr_181_t&) = delete;
    
    // Initialization
    void initialize(bus_handle_t* handle, dm_easy_mesh_ctrl_t& dm_ctrl);
    
    // WFA DML interface
    int register_wfa_dml(bus_handle_t* handle);
    int wfa_set_bus_callbackfunc_pointers(const char* full_namespace, bus_callback_table_t* cb_table);
    int wfa_bus_register_namespace(bus_handle_t* handle, char* full_namespace, 
                                 bus_element_type_t element_type,
                                 bus_callback_table_t cb_table, 
                                 data_model_properties_t data_model_value, 
                                 int num_of_rows);
                                 
    // Bus callback handlers
    static bus_error_t default_get_param_value(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data);
    static bus_error_t default_set_param_value(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data);
    static bus_error_t default_table_add_row_handler(const char* tableName, const char* aliasName, uint32_t* instNum);
    static bus_error_t default_table_remove_row_handler(const char* rowName);
    static bus_error_t default_event_sub_handler(char* eventName, bus_event_sub_action_t action, int32_t interval, bool* autoPublish);
    
    // Data model access
    wfa_dml_data_model_t* get_dml_data_model_param();
    bus_error_t wifi_elem_num_of_table_row(char* event_name, uint32_t* table_row_size);
    
    // File operations
    void generate_namespaces_without_lib_refined(bus_handle_t* handle, const std::string& filename);
    void register_cjson_namespace(bus_handle_t *handle, cJSON *node, const std::string &prefix);
};

#endif // TR_181_H

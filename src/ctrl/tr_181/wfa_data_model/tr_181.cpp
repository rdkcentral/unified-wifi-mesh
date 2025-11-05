/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2025 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <map>
#include "tr_181.h"
#include "wfa_data_model_parser.h"
#include "wfa_data_model.h"
#include "util.h"


// Initialize static member
tr_181_t* tr_181_t::tr181_data_model_instance = nullptr;

tr_181_t::tr_181_t() : bus_handle(nullptr){//, data_model(nullptr) {
    // Initialize dml_model
    memset(&dml_model, 0, sizeof(wfa_dml_data_model_t));
}

tr_181_t* tr_181_t::getInstance() {
    if (!tr181_data_model_instance) {
        tr181_data_model_instance = new tr_181_t();
    }
    return tr181_data_model_instance;
}

void tr_181_t::initialize(bus_handle_t* handle, dm_easy_mesh_ctrl_t& dm_ctrl)
{
    bus_handle = handle;
    // data_model = &dm_ctrl;

    register_wfa_dml(bus_handle);
}

// Function to trim leading/trailing whitespace from a string
std::string tr_181_t::trim(const std::string& str)
{
    size_t first = str.find_first_not_of(" \t\n\r");
    if (std::string::npos == first) {
        return str;
    }
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}

int tr_181_t::wfa_set_bus_callbackfunc_pointers(const char *full_namespace, bus_callback_table_t *cb_table)
{
    bus_data_cb_func_t bus_default_data_cb = { " ",
        { default_get_param_value, default_set_param_value, default_table_add_row_handler,
          default_table_remove_row_handler, default_event_sub_handler, NULL }
    };

    uint32_t index = 0;

    memcpy(cb_table, &bus_default_data_cb.cb_func, sizeof(bus_callback_table_t));

    return RETURN_OK;
}

int tr_181_t::wfa_bus_register_namespace(bus_handle_t *handle, char *full_namespace, bus_element_type_t element_type,
                            bus_callback_table_t cb_table, data_model_properties_t  data_model_value, int num_of_rows)
{   
    bus_data_element_t dataElements = { 0 };

    dataElements.full_name       = full_namespace;
    dataElements.type            = element_type;
    dataElements.cb_table        = cb_table;
    dataElements.bus_speed       = slow_speed;
    dataElements.data_model_prop = data_model_value;

    if (element_type == bus_element_type_table) {
        uint32_t num_of_table_rows;
        if (wifi_elem_num_of_table_row(full_namespace, &num_of_table_rows) == bus_error_success) {
            dataElements.num_of_table_row = num_of_table_rows;
        } else {
            dataElements.num_of_table_row = num_of_rows;
        }
        em_printfout("Add number of row:%d input value:%d\n", dataElements.num_of_table_row, num_of_rows);
    }

    uint32_t num_elements = 1;
    bus_error_t rc = get_bus_descriptor()->bus_reg_data_element_fn(handle, &dataElements, num_elements);
    if (rc != bus_error_success) {
        em_printfout("bus: bus_regDataElements failed:%s\n", full_namespace);
    }

    return RETURN_OK;
}

bus_error_t tr_181_t::default_get_param_value(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data) {
    // Default implementation for get parameter value
   // (void)p_data;
        p_data->data_type = bus_data_type_boolean;
    p_data->raw_data.b = 0;
    p_data->raw_data_len = sizeof(bool);

    (void)user_data;
    em_printfout("enter:%s\\r\\n", event_name);
    return bus_error_success;
}

bus_error_t tr_181_t::default_set_param_value(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data) {
    //(void)p_data;
    p_data->data_type = bus_data_type_boolean;
    p_data->raw_data.b = 0;
    p_data->raw_data_len = sizeof(bool);

    (void)user_data;
    em_printfout("enter:%s\\r\\n", event_name);
    return bus_error_success;
}

bus_error_t tr_181_t::default_table_add_row_handler(const char* tableName, const char* aliasName, uint32_t* instNum) {
    (void)aliasName;
    // Set a dummy instance number for testing
    if (instNum != NULL) {
        *instNum = 1; 
    }
    em_printfout("Added table:%s\\r\\n", tableName);
    return bus_error_success;
}

bus_error_t tr_181_t::default_table_remove_row_handler(const char* rowName) {
    em_printfout("Removed row:%s\\r\\n",  rowName);
    return bus_error_success;
}

bus_error_t tr_181_t::default_event_sub_handler(char* eventName, bus_event_sub_action_t action, 
                                               int32_t interval, bool* autoPublish) {
    (void)autoPublish;
    em_printfout("enter:%s: action:%d interval:%d\r\n", eventName, action, interval);
    return bus_error_success;
}

wfa_dml_data_model_t* tr_181_t::get_dml_data_model_param() {
    return &dml_model;
}

bus_error_t tr_181_t::wifi_elem_num_of_table_row(char* event_name, uint32_t* table_row_size)
{
    // Return 0 rows for all tables for now
    if (table_row_size != NULL) {
        *table_row_size = 1;
    }
    em_printfout("enter:%s\\r\\n", event_name);
    return bus_error_success;
}

/**
 * @brief Parses JSON keys from the file and generates DML namespaces (refined).
 * 
 * This version properly handles indexed arrays to generate paths like:
 * Network.DeviceList.{i}.APMLD.STAMLD
 *
 * @param handle The bus handle
 * @param filename The path to the JSON file
 */
void tr_181_t::generate_namespaces_without_lib_refined(bus_handle_t *handle, const std::string& filename)
{
    bus_name_string_t      name_prefix;
    bus_element_type_t     element_type     = bus_element_type_property;
    bus_callback_table_t   cb_table         = { 0 };
    data_model_properties_t   data_model_value;

    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << ". Please ensure it exists." << std::endl;
        return;
    }

    // Map to track the path segments by indentation level
    std::map<int, std::string> hierarchy;
    
    std::cout << "--- WARNING: Using string parsing (Still Fragile!) ---" << std::endl;
    std::cout << "Generated Namespaces (full_namespace):" << std::endl;
    std::cout << "---------------------------------------" << std::endl;

    // Initialize with the root path 'Network' at level 1
    int root_level = 1;
    hierarchy[root_level] = "Network";

    std::string line;
    while (std::getline(file, line)) {
        // 1. Calculate Indentation Level (Assuming 4 spaces per level for pretty-printed JSON)
        int indent_count = 0;
        for (char c : line) {
            if (c == ' ') indent_count++;
            else if (c == '\t') indent_count += 4;
            else break;
        }
        int current_level = (indent_count / 4) + root_level;
        
        std::string trimmed_line = trim(line);

        if (trimmed_line.empty() || trimmed_line.find('{') == 0 || trimmed_line.find('}') == 0 || 
            trimmed_line.find(']') == 0 || trimmed_line.find('[') == 0) {
            continue; // Ignore pure structural lines
        }

        // 2. Extract Key
        size_t quote_start = trimmed_line.find('"');
        size_t quote_end = (quote_start != std::string::npos) ? trimmed_line.find('"', quote_start + 1) : std::string::npos;
        size_t colon_pos = (quote_end != std::string::npos) ? trimmed_line.find(':', quote_end + 1) : std::string::npos;
        
        std::string key;
        if (quote_start != std::string::npos && quote_end != std::string::npos && colon_pos != std::string::npos) {
            key = trimmed_line.substr(quote_start + 1, quote_end - quote_start - 1);
        } else {
            continue; // Not a standard key-value line
        }

        // Handle the root tag 'wfa-dataelements:Network' exclusion
        if (key == "wfa-dataelements:Network") {
            continue;
        }

        // 3. Update Hierarchy and Track Array Context
        bool has_indexed_parent = false;
        std::string parent_path;
        
        // Check if we have a parent and if it's an indexed array
        if (current_level > root_level && hierarchy.count(current_level - 1)) {
            parent_path = hierarchy[current_level - 1];
            has_indexed_parent = (parent_path.find(".{i}") != std::string::npos);
        }

        // Clear deeper hierarchy paths
        for (auto it = hierarchy.begin(); it != hierarchy.end();) {
            if (it->first > current_level) {
                it = hierarchy.erase(it);
            } else {
                ++it;
            }
        }

        // Store the current key in hierarchy
        hierarchy[current_level] = key;
        
        // 4. Construct Full Namespace
        std::string full_path = "";
        for (int i = root_level; i <= current_level; ++i) {
            if (hierarchy.count(i)) {
                if (!full_path.empty()) full_path += ".";
                full_path += hierarchy[i];
            }
        }

        // If we're under an indexed parent, reconstruct the path to include {i}
        std::string indexed_full_path = full_path;
        if (has_indexed_parent) {
            // Find the last segment of the parent path (before our key)
            size_t last_dot = full_path.find_last_of('.');
            if (last_dot != std::string::npos) {
                // Replace the last segment to include .{i}
                indexed_full_path = full_path.substr(0, last_dot) + ".{i}." + key;
            }
        }
        
        // 5. Apply DML Rules
        
        // Check for Array/Object Table Opener
        if (trimmed_line.find(":{") != std::string::npos || trimmed_line.find(": [") != std::string::npos) {
            // If the structure starts with an array, register the indexed path
            if (trimmed_line.find(": [") != std::string::npos) {
                std::string table_path = has_indexed_parent ? indexed_full_path : full_path;
                std::string array_path = table_path + ".{i}";
                
                // Print and register the array path
                em_printfout("%s", array_path.c_str());
                
                wfa_set_bus_callbackfunc_pointers(array_path.c_str(), &cb_table);
                memset(&data_model_value, 0, sizeof(data_model_value));
                wfa_bus_register_namespace(handle, const_cast<char*>(array_path.c_str()), 
                                         bus_element_type_table, cb_table, data_model_value, 1);

                // Update hierarchy to include {i} for children of this array
                hierarchy[current_level] = key + ".{i}";
            }
        }
        // Handle Leaf Parameters
        else if (trimmed_line.find(':') != std::string::npos && trimmed_line.back() != '{' && trimmed_line.back() != '[') {
            // Use the indexed path if we're under an array parent, otherwise use normal path
            std::string leaf_path = has_indexed_parent ? indexed_full_path : full_path;
            
            em_printfout("%s", leaf_path.c_str());
            wfa_set_bus_callbackfunc_pointers(leaf_path.c_str(), &cb_table);
            memset(&data_model_value, 0, sizeof(data_model_value));
            wfa_bus_register_namespace(handle, const_cast<char*>(leaf_path.c_str()), 
                                     bus_element_type_method, cb_table, data_model_value, 1);
        }
    }
    printf("\n\n==========================\n\n");
}

int tr_181_t::register_wfa_dml(bus_handle_t *handle)
{
    const std::string filename = "Data_Elements_MultiAP_Example_JSON_v3.0.json";
    generate_namespaces_without_lib_refined(handle, filename);
    return RETURN_OK;
}
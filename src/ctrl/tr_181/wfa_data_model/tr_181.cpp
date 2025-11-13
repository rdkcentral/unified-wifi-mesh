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
        *table_row_size = 0;
    }
    em_printfout("enter:%s\\r\\n", event_name);
    return bus_error_success;
}

void tr_181_t::register_cjson_namespace(bus_handle_t *handle, cJSON *node, const std::string &prefix)
{
    if (!node)
        return;

    bus_callback_table_t cb_table = {0};
    data_model_properties_t data_model_value;

    for (cJSON *child = node->child; child; child = child->next)
    {
        std::string key = child->string ? child->string : "";
        std::string full_path;
        if(prefix.empty()) {
            full_path = key;
        } else if(prefix.back() == '.') {
            full_path = prefix + key;
        } else {
            full_path = prefix + "." + key;
        }

        if (cJSON_IsObject(child))
        {
            em_printfout("%s", full_path.c_str());
            wfa_set_bus_callbackfunc_pointers(full_path.c_str(), &cb_table);
            memset(&data_model_value, 0, sizeof(data_model_value));
            wfa_bus_register_namespace(handle, (char *)full_path.c_str(),
                                       bus_element_type_property, cb_table, data_model_value, 1);

            // Recurse into the object's children
            register_cjson_namespace(handle, child, full_path);
        }
        else if (cJSON_IsArray(child))
        {
            std::string array_path;
            if(prefix.empty()) {
                array_path = key + ".{i}.";
            } else if(prefix.back() == '.') {
                array_path = prefix + key + ".{i}.";
            } else {
                array_path = prefix + "." + key + ".{i}.";
            }

            em_printfout("%s", array_path.c_str());
            wfa_set_bus_callbackfunc_pointers(array_path.c_str(), &cb_table);
            memset(&data_model_value, 0, sizeof(data_model_value));

            // Now inspect the first element of the array
            cJSON *first_item = cJSON_GetArrayItem(child, 0);
            if (first_item && cJSON_IsObject(first_item))
            {
                //set the get and set handlers NULL for table entries
                cb_table.get_handler = NULL;
                cb_table.set_handler = NULL;
                wfa_bus_register_namespace(handle, (char *)array_path.c_str(),
                                       bus_element_type_table, cb_table, data_model_value, 0);
                register_cjson_namespace(handle, first_item, array_path);
            }
            else if (first_item && (cJSON_IsString(first_item) || cJSON_IsNumber(first_item)))
            {
                std::string prop_path;
                if(prefix.empty())
                    prop_path = key;
                else if(prefix.back() == '.')
                    prop_path = prefix + key;
                else
                    prop_path = prefix + "." + key;

                em_printfout("%s Primitive array as property", prop_path.c_str());
                wfa_set_bus_callbackfunc_pointers(prop_path.c_str(), &cb_table);
                memset(&data_model_value, 0, sizeof(data_model_value));
                wfa_bus_register_namespace(handle, (char *)prop_path.c_str(),
                                       bus_element_type_property, cb_table, data_model_value, 1);
            }
        }
        else if (cJSON_IsString(child) || cJSON_IsNumber(child) || cJSON_IsBool(child))
        {
            em_printfout("%s", full_path.c_str());
            wfa_set_bus_callbackfunc_pointers(full_path.c_str(), &cb_table);
            memset(&data_model_value, 0, sizeof(data_model_value));
            wfa_bus_register_namespace(handle, (char *)full_path.c_str(),
                                       bus_element_type_property, cb_table, data_model_value, 1);
        }
        else
        {
            em_printfout("Ignoring unsupported node: %s", full_path.c_str());
        }
    }
}

/**
 * Main entry: Parse JSON file and register Network hierarchy into RBUS.
 * Root key: "wfa-dataelements:Network"
 */
void tr_181_t::generate_namespaces_without_lib_refined(bus_handle_t *handle, const std::string &filename)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        std::cerr << "Error: Could not open " << filename << std::endl;
        return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string json_str = buffer.str();

    cJSON *root = cJSON_Parse(json_str.c_str());
    if (!root)
    {
        std::cerr << "Error parsing JSON" << std::endl;
        return;
    }

    // Root node of interest: wfa-dataelements:Network
    cJSON *network_node = cJSON_GetObjectItem(root, "wfa-dataelements:Network");
    if (!network_node)
    {
        std::cerr << "Root key 'wfa-dataelements:Network' not found." << std::endl;
        cJSON_Delete(root);
        return;
    }

    bus_callback_table_t cb_table = {0};
    data_model_properties_t data_model_value;
    std::string root_path = "Network";

    // Register the root property node
    em_printfout("%s", root_path.c_str());
    wfa_set_bus_callbackfunc_pointers(root_path.c_str(), &cb_table);
    memset(&data_model_value, 0, sizeof(data_model_value));
    wfa_bus_register_namespace(handle, (char *)root_path.c_str(),
                               bus_element_type_property, cb_table, data_model_value, 1);

    // Recurse through the full JSON hierarchy
    register_cjson_namespace(handle, network_node, root_path);

    //print_registered_elems(get_bus_mux_reg_cb_map(), 0);
    cJSON_Delete(root);
    std::cout << "\nJSON namespace registration complete.\n";
}

int tr_181_t::register_wfa_dml(bus_handle_t *handle)
{
    const std::string filename = "Data_Elements_MultiAP_Example_JSON_v3.0.json";
    generate_namespaces_without_lib_refined(handle, filename);
    return RETURN_OK;
}

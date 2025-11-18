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
#include <unistd.h>
#include <fcntl.h>
#include "tr_181.h"
// #include "wfa_data_model_parser.h"
// #include "wfa_data_model.h"
#include "util.h"
#include "dm_easy_mesh_ctrl.h"

// class dm_easy_mesh_ctrl_t;
bus_handle_t tr_181_t::m_bus_handle;
dm_easy_mesh_ctrl_t* tr_181_t::m_ctrl = nullptr;

void tr_181_t::init(void* ptr)
{
    wifi_bus_desc_t *desc;
    char service_name[] = "EasyMesh_Ctrl_Service";
    int pipefd[2];
	int rcp;
	rcp = pipe2(pipefd, O_DIRECT);
	if (rcp == -1) {
		return;
	}

	m_nb_pipe_rd = pipefd[0];
	m_nb_pipe_wr = pipefd[1];


    bus_init(&tr_181_t::m_bus_handle);

    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
    }
    
    if (desc->bus_open_fn(&tr_181_t::m_bus_handle, service_name) != 0) {
        printf("%s:%d bus open failed\n",__func__, __LINE__);
        return;
    }

    m_ctrl = static_cast<dm_easy_mesh_ctrl_t*> (ptr);

    register_wfa_dml();
}

int tr_181_t::wfa_set_bus_callbackfunc_pointers(const char *full_namespace, bus_callback_table_t *cb_table)
{
    em_printfout(" namespace:[%s]\n", full_namespace);
    bus_data_cb_func_t bus_data_cb[] = {
        ELEMENT(DE_NETWORK_ID, CB(.get_handler = network_get)),
        ELEMENT(DE_NETWORK_CTRLID, CB(.get_handler = network_get)),
        ELEMENT(DE_NETWORK_COLAGTID, CB(.get_handler = network_get)),
        ELEMENT(DE_NETWORK_DEVNOE, CB(.get_handler = network_get)),
        //ELEMENT_TABLE_ROW(DE_SSID_TABLE, CB(.get_handler = ssid_tget, .table_add_row_handler = ssid_table_add_row_handler)),
        ELEMENT_TABLE_ROW(DE_SSID_TABLE, CB(.table_add_row_handler = ssid_table_add_row_handler)),
        ELEMENT(DE_SSID_SSID, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_BAND, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_ENABLE, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_AKMALLOWE, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_SUITESEL, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_ADVENABLED, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_MFPCONFIG, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_MOBDOMAIN, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_HAULTYPE, CB(.get_handler = ssid_get)),
        // ELEMENT_TABLE_ROW(DE_DEVICE_TABLE, CB(.get_handler = device_tget, .table_add_row_handler = device_table_add_row_handler)),
        // ELEMENT_TABLE_ROW(DE_RADIO_TABLE, CB(.get_handler = radio_tget, .table_add_row_handler = radio_table_add_row_handler)),
        // ELEMENT_TABLE_ROW(DE_BSS_TABLE, CB(.get_handler = bss_tget, .table_add_row_handler = bss_table_add_row_handler)),
        // ELEMENT(DE_STA_TABLE, CB(.get_handler = sta_tget, .table_add_row_handler = sta_table_add_row_handler)),
        ELEMENT_TABLE_ROW(DE_DEVICE_TABLE, CB(.table_add_row_handler = device_table_add_row_handler)),
        ELEMENT_TABLE_ROW(DE_RADIO_TABLE, CB(.table_add_row_handler = radio_table_add_row_handler)),
        ELEMENT_TABLE_ROW(DE_BSS_TABLE, CB(.table_add_row_handler = bss_table_add_row_handler)),
        ELEMENT(DE_STA_TABLE, CB(.table_add_row_handler = sta_table_add_row_handler)), 
    };

    bus_data_cb_func_t bus_default_data_cb = { " ",
        { default_get_param_value, default_set_param_value, default_table_add_row_handler,
          default_table_remove_row_handler, default_event_sub_handler, NULL }
    };

    uint32_t index = 0;
    bool     table_found = false;

    for (index = 0; index < (uint32_t)ARRAY_SIZE(bus_data_cb); index++) {
        if (strcmp(full_namespace, bus_data_cb[index].cb_table_name)) {
            memcpy(cb_table, &bus_data_cb[index].cb_func, sizeof(bus_callback_table_t));
            table_found = true;
             em_printfout("strcmp namespace:[%s]\n", full_namespace);
            break;
        }
    }

    if (table_found == false) {
        em_printfout("default cb set for namespace:[%s]\n", full_namespace);
        memcpy(cb_table, &bus_default_data_cb.cb_func, sizeof(bus_callback_table_t));
    }

    return RETURN_OK;
}

int tr_181_t::wfa_bus_register_namespace(char *full_namespace, bus_element_type_t element_type,
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
    bus_error_t rc = get_bus_descriptor()->bus_reg_data_element_fn(&tr_181_t::m_bus_handle, &dataElements, num_elements);
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


bus_error_t tr_181_t::network_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_printfout("event name: %s\n", event_name);
    if (tr_181_t::m_ctrl != NULL)
    {
        //tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data, device_tget_inner);
        tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::ssid_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_printfout("event name: %s\n", event_name);
    if (tr_181_t::m_ctrl != NULL)
    {
        //tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data, device_tget_inner);
        tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::ssid_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_printfout("event name: %s\n", event_name);
    if (tr_181_t::m_ctrl != NULL)
    {
        //tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data, device_tget_inner);
        tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::device_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_printfout("event name: %s\n", event_name);
    if (tr_181_t::m_ctrl != NULL)
    {
        //tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data, device_tget_inner);
        tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::radio_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_printfout("event name: %s\n", event_name);
    if (tr_181_t::m_ctrl != NULL)
    {
        //tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data, device_tget_inner);
        tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::bss_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_printfout("event name: %s\n", event_name);
    if (tr_181_t::m_ctrl != NULL)
    {
        //tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data, device_tget_inner);
        tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::sta_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_printfout("event name: %s\n", event_name);
    if (tr_181_t::m_ctrl != NULL)
    {
        //tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data, device_tget_inner);
        tr_181_t::m_ctrl->device_tget_impl(event_name, p_data, user_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::device_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number)
{
    em_printfout("table name: %s\n", table_name);
    return bus_error_success;
}

bus_error_t tr_181_t::radio_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number)
{
    em_printfout("table name: %s\n", table_name);
    return bus_error_success;
}

bus_error_t tr_181_t::bss_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number)
{
    em_printfout("table name: %s\n", table_name);
    return bus_error_success;
}

bus_error_t tr_181_t::ssid_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number)
{
    em_printfout("table name: %s\n", table_name);
    return bus_error_success;
}

bus_error_t tr_181_t::sta_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number)
{
    em_printfout("table name: %s\n", table_name);
    return bus_error_success;
}

bus_error_t tr_181_t::add_table_row(char const *name)
{
    wifi_bus_desc_t *desc;
    int index = 0;
    bus_error_t rc = bus_error_invalid_input;

    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
    }

    //TODO: find a way to map this against the corresponding handler from the table
    rc = desc->bus_add_table_row_fn(&tr_181_t::m_bus_handle, name, NULL, (uint32_t*)&index);

    return rc;
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

void tr_181_t::register_cjson_namespace(cJSON *node, const std::string &prefix)
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
            wfa_bus_register_namespace((char *)full_path.c_str(),
                                       bus_element_type_property, cb_table, data_model_value, 1);

            // Recurse into the object's children
            register_cjson_namespace(child, full_path);
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
                wfa_bus_register_namespace((char *)array_path.c_str(),
                                       bus_element_type_table, cb_table, data_model_value, 0);
                register_cjson_namespace(first_item, array_path);
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
                wfa_bus_register_namespace((char *)prop_path.c_str(),
                                       bus_element_type_property, cb_table, data_model_value, 1);
            }
        }
        else if (cJSON_IsString(child) || cJSON_IsNumber(child) || cJSON_IsBool(child))
        {
            em_printfout("%s", full_path.c_str());
            wfa_set_bus_callbackfunc_pointers(full_path.c_str(), &cb_table);
            memset(&data_model_value, 0, sizeof(data_model_value));
            wfa_bus_register_namespace((char *)full_path.c_str(),
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
void tr_181_t::generate_namespaces_without_lib_refined(const std::string &filename)
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
    wfa_bus_register_namespace((char *)root_path.c_str(),
                               bus_element_type_property, cb_table, data_model_value, 1);

    // Recurse through the full JSON hierarchy
    register_cjson_namespace(network_node, root_path);

    //print_registered_elems(get_bus_mux_reg_cb_map(), 0);
    cJSON_Delete(root);
    std::cout << "\nJSON namespace registration complete.\n";
}

int tr_181_t::register_wfa_dml()
{
    const std::string filename = "Data_Elements_MultiAP_Example_JSON_v3.0.json";
    generate_namespaces_without_lib_refined(filename);
    return RETURN_OK;
}

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
#if 0
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bus.h"
#include "wfa_data_model_parser.h"
#include "wfa_data_model.h"
#include "util.h"

// Global DML structure (keep existing definition)
wfa_dml_data_model_t g_dml_data_model;

wfa_dml_data_model_t *get_dml_data_model_param(void)
{
    return &g_dml_data_model;
}

// ==========================================================
// EMPTY CALLBACK IMPLEMENTATIONS
// ==========================================================

bus_error_t wifi_elem_num_of_table_row(char *event_name, uint32_t *table_row_size)
{
    // Return 0 rows for all tables for now
    if (table_row_size != NULL) {
        *table_row_size = 1;
    }
    em_printfout("enter:%s\\r\\n", event_name);
    return bus_error_success;
}

// --- DML Callback Functions for wifi Object (e.g., Device.WiFi.) ---
// bus_error_t wifi_get_param_value(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data )
// {
//     (void)p_data;
//     (void)user_data;
//     wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter:%s\\r\\n", __func__, __LINE__, event_name);
//     return bus_error_success;
// }

// bus_error_t wifi_set_param_value(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data)
// {
//     (void)p_data;
//     (void)user_data;
//     wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter:%s\\r\\n", __func__, __LINE__, event_name);
//     return bus_error_success;
// }

// bus_error_t wifi_event_sub_handler(char *eventName, bus_event_sub_action_t action, int32_t interval, bool* autoPublish)
// {
//     (void)action;
//     (void)interval;
//     (void)autoPublish;
//     wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter:%s\\r\\n", __func__, __LINE__, eventName);
//     return bus_error_success;
// }

// // --- DML Callback Functions for radio Object (e.g., Device.WiFi.Radio.{i}.) ---
// bus_error_t radio_get_param_value(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data )
// {
//     (void)p_data;
//     (void)user_data;
//     wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter:%s\\r\\n", __func__, __LINE__, event_name);
//     return bus_error_success;
// }

// bus_error_t radio_set_param_value(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data)
// {
//     (void)p_data;
//     (void)user_data;
//     wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter:%s\\r\\n", __func__, __LINE__, event_name);
//     return bus_error_success;
// }

// // --- DML Callback Functions for ssid Object (e.g., Device.WiFi.SSID.{i}.) ---
// bus_error_t ssid_get_param_value(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data )
// {
//     (void)p_data;
//     (void)user_data;
//     wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter:%s\\r\\n", __func__, __LINE__, event_name);
//     return bus_error_success;
// }

// bus_error_t ssid_set_param_value(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data)
// {
//     (void)p_data;
//     (void)user_data;
//     wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter:%s\\r\\n", __func__, __LINE__, event_name);
//     return bus_error_success;
// }

// // --- DML Callback Functions for ap Object (e.g., Device.WiFi.AccessPoint.{i}.) ---
// bus_error_t ap_get_param_value(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data )
// {
//     (void)p_data;
//     (void)user_data;
//     wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter:%s\\r\\n", __func__, __LINE__, event_name);
//     return bus_error_success;
// }

// bus_error_t ap_set_param_value(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data)
// {
//     (void)p_data;
//     (void)user_data;
//     wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter:%s\\r\\n", __func__, __LINE__, event_name);
//     return bus_error_success;
// }

// // --- DML Callback Functions for associated device table ---
// bus_error_t sta_assoc_table_get_param_value(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data)
// {
//     (void)p_data;
//     (void)user_data;
//     wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter:%s\\r\\n", __func__, __LINE__, event_name);
//     return bus_error_success;
// }

// --- DML Callback Functions for default and general methods ---

// Default Get, Set, Add, and Remove handlers for all other objects
bus_error_t default_get_param_value(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data )
{
    // (void)p_data;
        p_data->data_type = bus_data_type_boolean;
    p_data->raw_data.b = 0;
    p_data->raw_data_len = sizeof(bool);

    (void)user_data;
    em_printfout("enter:%s\\r\\n", event_name);
    return bus_error_success;
}

bus_error_t default_set_param_value(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data)
{
    //(void)p_data;
    p_data->data_type = bus_data_type_boolean;
    p_data->raw_data.b = 0;
    p_data->raw_data_len = sizeof(bool);

    (void)user_data;
    em_printfout("enter:%s\\r\\n", event_name);
    return bus_error_success;
}

bus_error_t default_table_add_row_handler(char const* tableName, char const* aliasName, uint32_t* instNum)
{
    (void)aliasName;
    // Set a dummy instance number for testing
    if (instNum != NULL) {
        *instNum = 1; 
    }
    em_printfout("Added table:%s\\r\\n", tableName);
    return bus_error_success;
}

bus_error_t default_table_remove_row_handler(char const* rowName)
{
    em_printfout("Removed row:%s\\r\\n",  rowName);
    return bus_error_success;
}

bus_error_t default_event_sub_handler(char *eventName, bus_event_sub_action_t action, int32_t interval, bool* autoPublish)
{
    (void)autoPublish;
    em_printfout("enter:%s: action:%d interval:%d\r\n", eventName, action, interval);
    return bus_error_success;
}
// ==========================================================

#endif
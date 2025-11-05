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
#ifndef WFA_DATA_MODEL_H
#define WFA_DATA_MODEL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bus.h"

#define DM_CHECK_NULL_WITH_RC(ptr, rc) \
    do { \
        if ((ptr) == NULL) { \
            em_printfout("Parameter '%s' is NULL\n", \
                   __func__, __LINE__, #ptr); \
            return (rc); \
        } \
    } while (0)

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

bus_error_t wifi_elem_num_of_table_row(char *event_name, uint32_t *table_row_size);

bus_error_t default_get_param_value(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data);
bus_error_t default_set_param_value(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data);
bus_error_t default_table_add_row_handler(char const* tableName, char const* aliasName, uint32_t* instNum);
bus_error_t default_table_remove_row_handler(char const* rowName);
bus_error_t default_event_sub_handler(char *eventName, bus_event_sub_action_t action, int32_t interval, bool* autoPublish);

wfa_dml_data_model_t *get_dml_data_model_param(void);
#endif//WFA_DATA_MODEL_H
#endif
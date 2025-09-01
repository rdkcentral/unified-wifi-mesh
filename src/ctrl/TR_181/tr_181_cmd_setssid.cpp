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
#include "em_ctrl.h"
#include "tr_181.h"

extern em_ctrl_t g_ctrl;
extern char *global_netid;

bus_error_t em_ctrl_t::cmd_setssid(const char *event_name, bus_data_prop_t *input_data, bus_data_prop_t *output_data, void *user_data)
{
    em_subdoc_info_t *subdoc = NULL;
    unsigned char buff[EM_IO_BUFF_SZ];
    cJSON *json = NULL, *root = NULL;
    char *jsonbuff = NULL;
    bus_data_prop_t *prop = NULL;
    char *ssid = NULL, *passphrase = NULL, *band = NULL, *akms = NULL, *addremove = NULL;
    cJSON *ssid_list = NULL, *target = NULL, *item = NULL, *ssid_item = NULL;
    char *updated_json = NULL;
    int idx = 0;
    size_t json_len = 0;
    
    printf("Received parameters in cmd_setssid:\n");
    
    prop = input_data;
    while (prop) {
        printf("Param %d: name='%s', value='%s', len=%u\n", idx, prop->name, (char*)prop->value.raw_data.bytes, prop->value.raw_data_len);
        prop = prop->next_data;
        idx++;
    }

    // Extract parameters from input_data
    prop = input_data;
    while (prop) {
        if (strcmp(prop->name, "SSID") == 0) {
            ssid = strndup((char*)prop->value.raw_data.bytes, prop->value.raw_data_len);
        } else if (strcmp(prop->name, "PassPhrase") == 0) {
            passphrase = strndup((char*)prop->value.raw_data.bytes, prop->value.raw_data_len);
        } else if (strcmp(prop->name, "Band") == 0) {
            band = strndup((char*)prop->value.raw_data.bytes, prop->value.raw_data_len);
        } else if (strcmp(prop->name, "AKMsAllowed") == 0) {
            akms = strndup((char*)prop->value.raw_data.bytes, prop->value.raw_data_len);
        } else if (strcmp(prop->name, "AddRemoveChange") == 0) {
            addremove = strndup((char*)prop->value.raw_data.bytes, prop->value.raw_data_len);
        }
        prop = prop->next_data;
    }
    
    if (ssid == NULL || passphrase == NULL || band == NULL || akms == NULL || addremove == NULL) {
        printf("ERROR: Missing required parameters in cmd_setssid\n");
        return bus_error_invalid_input;
    }

    subdoc = (em_subdoc_info_t *)buff;
    strncpy(subdoc->name, "NetworkSSIDList", strlen("NetworkSSIDList"));
    g_ctrl.m_data_model.get_config("OneWifiMesh", subdoc);
    printf("%s:%d: buff=%s \n", __func__, __LINE__, subdoc->buff );
    json = cJSON_Parse(subdoc->buff);
    if (json == NULL) {
        printf("ERROR: Failed to parse JSON from subdoc\n");
        return bus_error_invalid_input;
    }

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "ID", "OneWifiMesh");
    cJSON_AddItemToObject(root, "wfa-dataelements:SetSSID", json);
    jsonbuff = cJSON_Print(root);
    printf("%s:%d root: %s\n", __func__, __LINE__,root);

    // Find or add the SSID entry
    ssid_list = cJSON_GetObjectItem(json, "NetworkSSIDList");
    if (ssid_list == NULL || !cJSON_IsArray(ssid_list)) {
        printf("ERROR: NetworkSSIDList not found or is not an array\n");
        cJSON_Delete(json);
        return bus_error_invalid_input;
    }
    cJSON_ArrayForEach(item, ssid_list) {
        ssid_item = cJSON_GetObjectItem(item, "SSID");
        if (ssid_item && ssid && strcmp(ssid_item->valuestring, ssid) == 0) {
            target = item;
            break;
        }
    }
    if (target) {
        // Replace all fields for the existing SSID entry
        if (ssid) {
            cJSON_ReplaceItemInObject(target, "SSID", cJSON_CreateString(ssid));
        }
        if (passphrase) {
            cJSON_ReplaceItemInObject(target, "PassPhrase", cJSON_CreateString(passphrase));
        }
        if (band) {
            cJSON *band_arr = cJSON_CreateArray();
            cJSON_AddItemToArray(band_arr, cJSON_CreateString(band));
            cJSON_ReplaceItemInObject(target, "Band", band_arr);
        }
        if (akms) {
            cJSON *akm_arr = cJSON_CreateArray();
            cJSON_AddItemToArray(akm_arr, cJSON_CreateString(akms));
            cJSON_ReplaceItemInObject(target, "AKMsAllowed", akm_arr);
        }
    } else if (addremove && strcmp(addremove, "Add") == 0) {
        // Add new entry if SSID does not exist
        target = cJSON_CreateObject();
        cJSON_AddItemToArray(ssid_list, target);
        if (ssid) {
            cJSON_AddStringToObject(target, "SSID", ssid);
        }
        if (passphrase) {
            cJSON_AddStringToObject(target, "PassPhrase", passphrase);
        }
        if (band) {
            cJSON *band_arr = cJSON_CreateArray();
            cJSON_AddItemToArray(band_arr, cJSON_CreateString(band));
            cJSON_AddItemToObject(target, "Band", band_arr);
        }
        if (akms) {
            cJSON *akm_arr = cJSON_CreateArray();
            cJSON_AddItemToArray(akm_arr, cJSON_CreateString(akms));
            cJSON_AddItemToObject(target, "AKMsAllowed", akm_arr);
        }
    }

    updated_json = cJSON_PrintUnformatted(root);
    json_len = strlen(updated_json);
    if (json_len >= EM_IO_BUFF_SZ) {
        printf("ERROR: JSON too large for buffer! Truncating.\n");
        json_len = EM_IO_BUFF_SZ - 1;
    }
    
    memcpy(subdoc->buff, updated_json, json_len);
    subdoc->buff[json_len] = '\0';
    cJSON *json_obj = cJSON_Parse(subdoc->buff);
    if (json_obj) {
        char *new_json = cJSON_Print(json_obj);
        printf("updated and formatted JSON:\n%s\n", new_json);
        free(new_json);
        cJSON_Delete(json_obj);
    } else {
        printf("Invalid JSON in subdoc->buff\n");
    }

    g_ctrl.io_process(em_bus_event_type_set_ssid, subdoc->buff, strlen(subdoc->buff));
    free(updated_json);
    cJSON_Delete(json);

    return bus_error_success;
}


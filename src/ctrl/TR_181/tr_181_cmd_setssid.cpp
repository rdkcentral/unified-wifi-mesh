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

#define MAX_PARAM_LEN 128

#if 0
//TODO: Rbus abstraction needed for this async method call, it will be enabled once its ready
bus_error_t em_ctrl_t::cmd_setssid(const char *event_name, bus_data_prop_t const *input_data, bus_data_prop_t *output_data, void *user_data)
{
    em_subdoc_info_t *subdoc = NULL;
    unsigned char buff[EM_IO_BUFF_SZ];
    cJSON *json = NULL, *root = NULL, *new_json = NULL, *ssid_list = NULL, *target = NULL, *item = NULL, *ssid_item = NULL, *child = NULL, *next = NULL, *band_arr = NULL, *akm_arr = NULL, *json_obj = NULL;
    char *jsonbuff = NULL, *updated_json = NULL, *new_json_str = NULL;
    bus_data_prop_t const *prop = NULL;
    char ssid[MAX_PARAM_LEN] = {0};
    char passphrase[MAX_PARAM_LEN] = {0};
    char band[MAX_PARAM_LEN] = {0};
    char akms[MAX_PARAM_LEN] = {0};
    char addremove[MAX_PARAM_LEN] = {0};
    int idx = 0;
    size_t json_len = 0;
    
    em_printfout("Received parameters in cmd_setssid");
    
    prop = input_data;
    while (prop) {
        em_printfout("Param %d: name='%s', value='%s', len=%u", idx, prop->name, (char*)prop->value.raw_data.bytes, prop->value.raw_data_len);
        prop = prop->next_data;
        idx++;
    }

    // Extract parameters from input_data
    prop = input_data;
    while (prop) {
        em_printfout("name='%s', value='%.*s', len=%u", prop->name, (int)prop->value.raw_data_len, (char*)prop->value.raw_data.bytes, prop->value.raw_data_len);
        if (strcmp(prop->name, "SSID") == 0) {
            strncpy(ssid, (char*)prop->value.raw_data.bytes, MAX_PARAM_LEN - 1);
            ssid[MAX_PARAM_LEN - 1] = '\0';
        } else if (strcmp(prop->name, "PassPhrase") == 0) {
            strncpy(passphrase, (char*)prop->value.raw_data.bytes, MAX_PARAM_LEN - 1);
            passphrase[MAX_PARAM_LEN - 1] = '\0';
        } else if (strcmp(prop->name, "Band") == 0) {
            strncpy(band, (char*)prop->value.raw_data.bytes, MAX_PARAM_LEN - 1);
            band[MAX_PARAM_LEN - 1] = '\0';
        } else if (strcmp(prop->name, "AKMsAllowed") == 0) {
            strncpy(akms, (char*)prop->value.raw_data.bytes, MAX_PARAM_LEN - 1);
            akms[MAX_PARAM_LEN - 1] = '\0';
        } else if (strcmp(prop->name, "AddRemoveChange") == 0) {
            strncpy(addremove, (char*)prop->value.raw_data.bytes, MAX_PARAM_LEN - 1);
            addremove[MAX_PARAM_LEN - 1] = '\0';
        }
        prop = prop->next_data;
    }
    
    if (ssid[0] == '\0' || passphrase[0] == '\0' || band[0] == '\0' || akms[0] == '\0' || addremove[0] == '\0') {
        em_printfout("ERROR: Missing required parameters in cmd_setssid");
        return bus_error_invalid_input;
    }

    subdoc = (em_subdoc_info_t *)buff;
    strncpy(subdoc->name, "NetworkSSIDList", strlen("NetworkSSIDList"));
    g_ctrl.m_data_model.get_config("OneWifiMesh", subdoc);
    em_printfout("%s:%d: buff=%s \n", __func__, __LINE__, subdoc->buff );
    json = cJSON_Parse(subdoc->buff);
    if (json == NULL) {
        em_printfout("ERROR: Failed to parse JSON from subdoc");
        return bus_error_invalid_input;
    }

    root = cJSON_CreateObject();
    // Add "ID" to the beginning of the JSON object
    new_json = cJSON_CreateObject();
    cJSON_AddStringToObject(new_json, "ID", "OneWifiMesh");

    // Move all items from the original json to new_json
    child = json->child;
    while (child) {
        next = child->next;
        cJSON_DetachItemViaPointer(json, child);
        cJSON_AddItemToObject(new_json, child->string, child);
        child = next;
    }
    cJSON_Delete(json);
    json = new_json;

    cJSON_AddItemToObject(root, "wfa-dataelements:SetSSID", json);
    jsonbuff = cJSON_Print(root);
    em_printfout("%s:%d root: %s\n", __func__, __LINE__, jsonbuff);
    free(jsonbuff);

    // Find or add the SSID entry
    ssid_list = cJSON_GetObjectItem(json, "NetworkSSIDList");
    if (ssid_list == NULL || !cJSON_IsArray(ssid_list)) {
        em_printfout("ERROR: NetworkSSIDList not found or is not an array");
        cJSON_Delete(json);
        return bus_error_invalid_input;
    }
    cJSON_ArrayForEach(item, ssid_list) {
        ssid_item = cJSON_GetObjectItem(item, "SSID");
        if (ssid_item && ssid && strcmp(ssid_item->valuestring, ssid) == 0) {
            target = item;
            em_printfout("Matching SSID found: %s", ssid_item->valuestring);
            break;
        }
        //TBD: If not found, update fronthaul for now
        //check if ssid named private_ssdid exists
        ssid_item = cJSON_GetObjectItem(item, "SSID");
        if (ssid_item && ssid && strcmp(ssid_item->valuestring, "private_ssid") == 0) {
            target = item;
            em_printfout("private_ssid found: %s\n", ssid_item->valuestring);
            break;
        }
    }
    em_printfout("Target SSID entry: %s", target ? "Found" : "Not Found");
    if (target) {
        em_printfout("Replace existing SSID");
        // Replace all fields for the existing SSID entry
        if (ssid[0]) {
            cJSON_ReplaceItemInObject(target, "SSID", cJSON_CreateString(ssid));
        }
        if (passphrase[0]) {
            cJSON_ReplaceItemInObject(target, "PassPhrase", cJSON_CreateString(passphrase));
        }
        if (band[0]) {
            band_arr = cJSON_CreateArray();
            cJSON_AddItemToArray(band_arr, cJSON_CreateString(band));
            cJSON_ReplaceItemInObject(target, "Band", band_arr);
        }
        if (akms[0]) {
            akm_arr = cJSON_CreateArray();
            cJSON_AddItemToArray(akm_arr, cJSON_CreateString(akms));
            cJSON_ReplaceItemInObject(target, "AKMsAllowed", akm_arr);
        }
    } else if (addremove[0] && strcmp(addremove, "Add") == 0) {
        em_printfout("ADD (new SSID)");
        // Add new entry if SSID does not exist
        target = cJSON_CreateObject();
        cJSON_AddItemToArray(ssid_list, target);
        if (ssid[0]) {
            cJSON_AddStringToObject(target, "SSID", ssid);
        }
        if (passphrase[0]) {
            cJSON_AddStringToObject(target, "PassPhrase", passphrase);
        }
        if (band[0]) {
            band_arr = cJSON_CreateArray();
            cJSON_AddItemToArray(band_arr, cJSON_CreateString(band));
            cJSON_AddItemToObject(target, "Band", band_arr);
        }
        if (akms[0]) {
            akm_arr = cJSON_CreateArray();
            cJSON_AddItemToArray(akm_arr, cJSON_CreateString(akms));
            cJSON_AddItemToObject(target, "AKMsAllowed", akm_arr);
        }
    }

    updated_json = cJSON_PrintUnformatted(root);
    json_len = strlen(updated_json);
    if (json_len >= EM_IO_BUFF_SZ) {
        em_printfout("ERROR: JSON too large for buffer!");
        free(updated_json);
        cJSON_Delete(json);
        return bus_error_invalid_input;
    }
    
    memcpy(subdoc->buff, updated_json, json_len);
    subdoc->buff[json_len] = '\0';
    json_obj = cJSON_Parse(subdoc->buff);
    if (json_obj) {
        char *new_json = cJSON_Print(json_obj);
        em_printfout("Updated and formatted JSON:\n%s", new_json);
        free(new_json);
        cJSON_Delete(json_obj);
    } else {
        em_printfout("Invalid JSON in subdoc->buff");
    }

    g_ctrl.io_process(em_bus_event_type_set_ssid, subdoc->buff, strlen(subdoc->buff));
    free(updated_json);
    cJSON_Delete(json);

    return bus_error_success;
}
#endif

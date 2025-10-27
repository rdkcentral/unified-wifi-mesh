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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include "bus.h"
#include "bus_common.h"
#include "tr_181.h"

typedef enum{
    CONTROLLERID,
    COLOCATEDAGENTID,
    SETSSID
}test_tr;

void print_options()
{
    printf("\n ---------------------------------------------------");
    printf("\n Test TR-Param");
    printf("\nDEVICE_WIFI_DATAELEMENTS_NETWORK_CONTROLLERID:%d",CONTROLLERID);
    printf("\nDEVICE_WIFI_DATAELEMENTS_NETWORK_COLOCATEDAGENTID:%d",COLOCATEDAGENTID);
    printf("\nDEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD:%d",SETSSID);
    printf("\n ---------------------------------------------------");
    printf("\n");
}

void output_cb(char const* methodName, bus_error_t error, bus_data_prop_t *params, void *userData)
{
    printf("	OUTPUT Callback status: %d, params:%s, userData: %s\n", error, params, userData);
    //check wheter config is successfully applied to all agents or not
    //wait all devices are online and check ssid details of all devices
}


int main()
{
    wifi_bus_desc_t *desc;
    bus_handle_t m_bus_hdl;
    memset(&m_bus_hdl, 0, sizeof(bus_handle_t));
    raw_data_t data;

    int num_retry = 0;
    bus_error_t bus_error_val;
    int rc = bus_error_success;
    char service_name[] = "Test_TR181";
    int input = 0;
    //cmdsetssid add_ssid;
    bus_data_prop_t *prop_data;


    bus_init(&m_bus_hdl);
    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
    }
    if (desc->bus_open_fn(&m_bus_hdl, service_name) != 0) {
        printf("%s:%d bus open failed\n",__func__, __LINE__);
        return 0;
    }
    printf("%s:%d he_bus open success\n", __func__, __LINE__);
    memset(&data, 0, sizeof(raw_data_t));

    while(1) {
        print_options();
        printf("\n Enter number to test: \n");
        scanf("%d", &input);
        memset(&data, 0, sizeof(raw_data_t));
        printf("%s:%d input=%d\n",__func__, __LINE__, input);
        
        if (input == CONTROLLERID) {
            if((bus_error_val = desc->bus_data_get_fn(&m_bus_hdl, DEVICE_WIFI_DATAELEMENTS_NETWORK_CONTROLLERID, &data)) != bus_error_success ) {
                printf("%s:%d bus_data_get_fn failed with error: %d\n", __func__, __LINE__, bus_error_val);
            }
            if (data.raw_data.bytes != NULL) {
                printf("\n%s:%d recv data: CONTROLLERID=%s\n", __func__, __LINE__, (char *)data.raw_data.bytes);
                get_bus_descriptor()->bus_data_free_fn(&data);
            } else
                printf("\n%s:%d recv data: CONTROLLERID is NULL: %s\n", __func__, __LINE__, (char *)data.raw_data.bytes);
        } else if (input == COLOCATEDAGENTID) { 
            if((bus_error_val = desc->bus_data_get_fn(&m_bus_hdl, DEVICE_WIFI_DATAELEMENTS_NETWORK_COLOCATEDAGENTID, &data)) != bus_error_success ) {
                printf("%s:%d bus_data_get_fn failed with error: %d\n", __func__, __LINE__, bus_error_val);
            }
            printf("\n%s:%d recv data:COLOCATEDAGENTID=%s\n", __func__, __LINE__, (char *)data.raw_data.bytes);
            get_bus_descriptor()->bus_data_free_fn(&data);
        } else if (input == SETSSID) {
            printf("\n%s:%d SET SSID start\n", __func__, __LINE__);
            bus_data_obj_t *input_data = (bus_data_obj_t*)calloc(1, sizeof(bus_data_obj_t));
            // Allocate on heap
            bus_data_prop_t *add_prop  = (bus_data_prop_t*)calloc(1, sizeof(bus_data_prop_t));
            bus_data_prop_t *band_prop = (bus_data_prop_t*)calloc(1, sizeof(bus_data_prop_t));
            bus_data_prop_t *pass_prop = (bus_data_prop_t*)calloc(1, sizeof(bus_data_prop_t));
            bus_data_prop_t *akm_prop  = (bus_data_prop_t*)calloc(1, sizeof(bus_data_prop_t));

            raw_data_t *p_raw_data = (raw_data_t*)calloc(1, sizeof(raw_data_t));
            input_data->data_prop.value.data_type = bus_data_type_string;
            input_data->data_prop.value.raw_data.bytes = strdup("private_ssid"); // strdup allocates and copies string
            input_data->data_prop.value.raw_data_len = strlen("private_ssid") + 1;

            //1st prop
            memset(&input_data->data_prop, 0, sizeof(bus_data_prop_t));
            strncpy(input_data->data_prop.name, "SSID", BUS_MAX_NAME_LENGTH);
            input_data->data_prop.name_len = strlen("SSID") + 1;
            input_data->data_prop.value.data_type = bus_data_type_string;
            input_data->data_prop.value.raw_data.bytes = strdup("atest");
            input_data->data_prop.value.raw_data_len = strlen("atest") + 1;
            input_data->data_prop.next_data = add_prop;

            //2nd prop
            // AddRemoveChange
            add_prop->value.data_type = bus_data_type_string;
            strncpy(add_prop->name, "AddRemoveChange", BUS_MAX_NAME_LENGTH);
            add_prop->name_len = strlen("AddRemoveChange") + 1;
            add_prop->value.raw_data.bytes = strdup("Add");
            add_prop->value.raw_data_len = strlen("Add") + 1;
            add_prop->next_data = band_prop;

            //3rd prop
            // Band
            band_prop->value.data_type = bus_data_type_string;
            strncpy(band_prop->name, "Band", BUS_MAX_NAME_LENGTH);
            band_prop->name_len = strlen("Band") + 1;
            band_prop->value.raw_data.bytes = strdup("2.4");
            band_prop->value.raw_data_len = strlen("2.4") + 1;
            band_prop->next_data = pass_prop;

            // PassPhrase
            pass_prop->value.data_type = bus_data_type_string;
            strncpy(pass_prop->name, "PassPhrase", BUS_MAX_NAME_LENGTH);
            pass_prop->name_len = strlen("PassPhrase") + 1;
            pass_prop->value.raw_data.bytes = strdup("rdk@1234");
            pass_prop->value.raw_data_len = strlen("rdk@1234") + 1;
            pass_prop->next_data = akm_prop;

            // AKMsAllowed
            akm_prop->value.data_type = bus_data_type_string;
                strncpy(akm_prop->name, "AKMsAllowed", BUS_MAX_NAME_LENGTH);
            akm_prop->name_len = strlen("AKMsAllowed") + 1;
            akm_prop->value.raw_data.bytes = strdup("psk");
            akm_prop->value.raw_data_len = strlen("psk") + 1;
            akm_prop->next_data = NULL;

            // Fill input_data
            input_data->num_prop = 5;

            bus_data_prop_t *prop = &input_data->data_prop;
            bus_data_prop_t *next;
            int idx = 0;
            printf("Total params: %d\n", idx);
            while (prop) {
                printf("  Param %d: name='%s', value='%s', len=%u\n", idx, prop->name, (char*)prop->value.raw_data.bytes, prop->value.raw_data_len);
                prop = prop->next_data;
                idx++;
            }
            if((bus_error_val = desc->bus_method_async_invoke_fn(&m_bus_hdl, \
                (char const *) DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD, \
                ( char const *)DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD, \
                input_data, output_cb, BUS_METHOD_SET)) != bus_error_success ) {
                printf("%s:%d bus_set_fn failed with error: %d\n", __func__, __LINE__, bus_error_val);
            }

            printf("%s:%d bus_set_fn SUCCESS: %d\n", __func__, __LINE__, bus_error_val);
        }
    }
    return 0;
}

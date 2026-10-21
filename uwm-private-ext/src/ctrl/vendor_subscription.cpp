/**
 * Copyright 2026 Comcast Cable Communications Management, LLC
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
#include "em_ctrl_hooks.h"
#include "util.h"
#include "bus.h"
#include "em_ctrl.h"
#include <cjson/cJSON.h>


/*static bus_error_t rcv_wei_data_set_cb(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    if (!p_data || !p_data->raw_data.bytes || p_data->raw_data_len == 0) {
        em_printfout("rcv_wei_data_set_cb: empty payload on %s", event_name);
        return bus_error_invalid_input;
    }

    cJSON *parsed = cJSON_ParseWithLength(
        reinterpret_cast<const char *>(p_data->raw_data.bytes), p_data->raw_data_len);
    if (parsed == NULL) {
        em_printfout("rcv_wei_data_set_cb: payload is not valid JSON, dropping");
        return bus_error_invalid_input;
    }

    char *json_str = cJSON_PrintUnformatted(parsed);
    cJSON_Delete(parsed);
    if (json_str == NULL) return bus_error_general;

    //em_topo_stream_send_topology(json_str);

    free(json_str);
    return bus_error_success;
}

static void subscription_init(bus_handle_t *bus_hdl, wifi_bus_desc_t *desc)
{
    if (!desc || !bus_hdl) {
        em_printfout("subscription_init: null desc/bus_hdl, skipping");
        return;
    }

    bus_data_element_t elem = {
        const_cast<char *>(DEVICE_WIFI_DATAELEMENTS_RCV_WEI_DATA), bus_element_type_property,
        { NULL, rcv_wei_data_set_cb, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
        { bus_data_type_string, false, 0, 0, 0, NULL }
    };

    if (desc->bus_reg_data_element_fn(bus_hdl, &elem, 1) != bus_error_success) {
        em_printfout("subscription_init: failed to register %s", DEVICE_WIFI_DATAELEMENTS_RCV_WEI_DATA);
        return;
    }

    em_printfout("subscription_init: registered %s as controller-owned property",
                 DEVICE_WIFI_DATAELEMENTS_RCV_WEI_DATA);
}

namespace {
struct auto_register_t {
    auto_register_t() { em_register_bus_ready_hook(subscription_init); }
} g_auto_register;// <-- constructor runs at static-init time, calls the register fn
}*/

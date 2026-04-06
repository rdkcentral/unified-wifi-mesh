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

bus_error_t tr_181_t::setssid_handler(const char *method_name, bus_data_prop_t *input_data,
    bus_data_prop_t *output_data, void *async_handle)
{
    // Standardize input pointer checks
    if (!input_data || (!input_data->is_data_set && input_data->next_data == NULL)) {
        em_printfout("Invalid input_data or missing input_props");
        if (output_data) {
            tr_181_t::tr181_set_status_output(output_data, "Failure: missing input_props");
        }
        return bus_error_invalid_input;
    }

    bus_data_prop_t *input_props = input_data;
    bus_data_prop_t *output_props = NULL;

    uint32_t input_count = 0;
    for (bus_data_prop_t *p = input_props; p; p = p->next_data) {
        if (p->is_data_set) {
            input_count++;
        }
    }
    em_printfout("Method='%s' input_len=%u", method_name ? method_name : "(null)", input_count);
    // Log all chained input properties
    for (bus_data_prop_t *p = input_props; p; p = p->next_data) {
        em_printfout("Prop='%s' type=%d len=%u", p->name, p->value.data_type, p->value.raw_data_len);
    }

    em_ctrl_t *ctrl = em_ctrl_t::get_em_ctrl_instance();
    if (!ctrl) {
        em_printfout("Controller unavailable");
        if (output_data) {
            tr_181_t::tr181_set_status_output(output_data, "Failure: controller unavailable");
        }
        return bus_error_invalid_input;
    }

    const char *event = method_name ? method_name : DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD;
    bus_error_t rc = ctrl->cmd_setssid(event, input_props, output_data ? &output_props : NULL, async_handle);

    if (output_data && output_props) {
        *output_data = *output_props;
        output_data->ref_count = 1;

        for (bus_data_prop_t *p = output_data->next_data; p; p = p->next_data) {
            p->ref_count = 1;
        }

        free(output_props);
    }

    return rc;
}

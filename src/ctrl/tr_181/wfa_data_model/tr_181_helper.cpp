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

#include "tr_181_helper.h"
#include <stdlib.h>

bus_data_prop_t *tr181_alloc_string_prop(const char *name, const char *value)
{
    if (!name || !value) return nullptr;

    bus_data_prop_t *prop = static_cast<bus_data_prop_t *>(calloc(1, sizeof(bus_data_prop_t)));
    if (!prop) return nullptr;

    size_t name_len = strnlen(name, sizeof(prop->name) - 1U);
    memcpy(prop->name, name, name_len);
    prop->name[name_len] = '\0';
    prop->name_len = static_cast<uint32_t>(name_len);
    prop->is_data_set = true;
    prop->status = bus_error_success;

    size_t value_len = strlen(value);
    prop->value.data_type = bus_data_type_string;
    prop->value.raw_data.bytes = malloc(value_len + 1U);
    if (!prop->value.raw_data.bytes) {
        free(prop);
        return nullptr;
    }
    memcpy(prop->value.raw_data.bytes, value, value_len + 1U);
    prop->value.raw_data_len = static_cast<unsigned int>(value_len + 1U);
    return prop;
}

bus_data_prop_t *tr181_set_status_output_prop(const char *status)
{
    return status ? tr181_alloc_string_prop("Status", status) : nullptr;
}

void tr181_set_status_output(raw_data_t *output_data, const char *status)
{
    if (!output_data) return;
    bus_data_prop_t *prop = tr181_set_status_output_prop(status);
    if (!prop) return;
    output_data->data_type = bus_data_type_property;
    output_data->raw_data.bytes = prop;
    output_data->raw_data_len = sizeof(bus_data_prop_t);
}

bool tr181_copy_prop_string(const bus_data_prop_t *prop, char *dst, size_t dst_len)
{
    if ((prop == NULL) || (dst == NULL) || (dst_len == 0U)) {
        return false;
    }
    if ((prop->value.data_type != bus_data_type_string) || (prop->value.raw_data.bytes == NULL)) {
        return false;
    }

    size_t len = prop->value.raw_data_len;
    if (len == 0U) {
        len = strnlen(static_cast<const char *>(prop->value.raw_data.bytes), dst_len - 1U);
    }
    if (len >= dst_len) {
        len = dst_len - 1U;
    }

    memcpy(dst, prop->value.raw_data.bytes, len);
    dst[len] = '\0';
    return true;
}

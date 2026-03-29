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

#include "tr_181.h"
#include "util.h"
#include <cjson/cJSON.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Utility: Trim leading/trailing whitespace from a string (in-place)
void tr_181_t::tr181_trim_whitespace(char *str)
{
    if (!str) {
        return;
    }
    char *start = str;
    while (isspace(static_cast<unsigned char>(*start))) {
        start++;
    }
    if (*start == '\0') {
        str[0] = '\0';
        return;
    }
    char *end = start + strlen(start) - 1;
    while (end > start && isspace(static_cast<unsigned char>(*end))) {
        end--;
    }
    size_t len = static_cast<size_t>(end - start + 1);
    if (start != str) {
        memmove(str, start, len);
    }
    str[len] = '\0';
}

// Create a HaulType array from a single value (Fronthaul/Backhaul only)
cJSON *tr_181_t::create_haultype_array(const char *haul_val)
{
    if (!haul_val || *haul_val == '\0') return NULL;
    if (strchr(haul_val, ',')) {
        em_printfout("ERROR: HaulType must be a single value (no commas): '%s'", haul_val);
        return NULL;
    }
    char tok_buf[TR181_HAULTYPE_MAX_LEN + 1];
    size_t val_len = strnlen(haul_val, sizeof(tok_buf));
    if (val_len >= sizeof(tok_buf)) {
        em_printfout("ERROR: HaulType too long");
        return NULL;
    }
    memcpy(tok_buf, haul_val, val_len + 1);
    tr181_trim_whitespace(tok_buf);
    if (*tok_buf == '\0') {
        em_printfout("ERROR: HaulType empty after trimming");
        return NULL;
    }
    if (strcmp(tok_buf, "Fronthaul") != 0 && strcmp(tok_buf, "Backhaul") != 0) {
        em_printfout("ERROR: Invalid HaulType value '%s' (expected Fronthaul/Backhaul)", tok_buf);
        return NULL;
    }
    cJSON *arr = cJSON_CreateArray();
    if (!arr) {
        return NULL;
    }
    cJSON *val = cJSON_CreateString(tok_buf);
    if (!val) {
        cJSON_Delete(arr);
        return NULL;
    }
    cJSON_AddItemToArray(arr, val);
    return arr;
}

// Return true if item's HaulType array contains the provided value
bool tr_181_t::item_matches_haultype(const cJSON *item, const char *haul_val)
{
    if (!item || !haul_val || *haul_val == '\0') return false;
    char tok_buf[TR181_HAULTYPE_MAX_LEN + 1];
    size_t val_len = strnlen(haul_val, sizeof(tok_buf));
    if (val_len >= sizeof(tok_buf)) {
        return false;
    }
    memcpy(tok_buf, haul_val, val_len + 1);
    tr181_trim_whitespace(tok_buf);
    if (*tok_buf == '\0') return false;
    const cJSON *haul_arr = cJSON_GetObjectItem(item, "HaulType");
    if (!haul_arr || !cJSON_IsArray(haul_arr)) return false;
    cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, haul_arr) {
        if (cJSON_IsString(entry) && entry->valuestring && strcmp(entry->valuestring, tok_buf) == 0) {
            return true;
        }
    }
    return false;
}

// Format HaulType array as comma-separated string
size_t tr_181_t::format_haultype_list(const cJSON *item, char *out, size_t out_len)
{
    if (!out || out_len == 0) return 0;
    out[0] = '\0';
    if (!item) return 0;
    const cJSON *haul_arr = cJSON_GetObjectItem(item, "HaulType");
    if (!haul_arr || !cJSON_IsArray(haul_arr)) return 0;
    bool first = true;
    cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, haul_arr) {
        if (!cJSON_IsString(entry) || !entry->valuestring) continue;
        size_t len = strlen(out);
        if (len >= out_len - 1) break;
        snprintf(out + len, out_len - len, "%s%s", first ? "" : ",", entry->valuestring);
        first = false;
    }
    return strlen(out);
}

// Create a string property with the given name and value.
bus_data_prop_t *tr_181_t::tr181_alloc_string_prop(const char *name, const char *value)
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

// Build a "Status" output property with the given status string.
bus_data_prop_t *tr_181_t::tr181_set_status_output_prop(const char *status)
{
    return status ? tr181_alloc_string_prop("Status", status) : nullptr;
}

// Populate output_data with a "Status" property containing the given status string.
void tr_181_t::tr181_set_status_output(bus_data_prop_t *output_data, const char *status)
{
    if (!output_data || !status) {
        return;
    }

    bus_data_prop_t *prop = output_data;
    memset(prop, 0, sizeof(*prop));

    size_t name_len = strnlen("Status", sizeof(prop->name) - 1U);
    memcpy(prop->name, "Status", name_len);
    prop->name[name_len] = '\0';
    prop->name_len = static_cast<uint32_t>(name_len);
    prop->is_data_set = true;
    prop->status = bus_error_success;
    prop->ref_count = 1;

    size_t value_len = strlen(status);
    prop->value.data_type = bus_data_type_string;
    prop->value.raw_data.bytes = malloc(value_len + 1U);
    if (!prop->value.raw_data.bytes) {
        prop->is_data_set = false;
        prop->ref_count = 0;
        return;
    }
    memcpy(prop->value.raw_data.bytes, status, value_len + 1U);
    prop->value.raw_data_len = static_cast<unsigned int>(value_len + 1U);
}

// Copy a string property value into a destination buffer, ensuring proper type and null-termination.
bool tr_181_t::tr181_copy_prop_string(const bus_data_prop_t *prop, char *dst, size_t dst_len)
{
    if (!prop || !dst || (dst_len == 0U)) {
        return false;
    }
    if ((prop->value.data_type != bus_data_type_string) || !prop->value.raw_data.bytes) {
        return false;
    }

    const char *src = static_cast<const char *>(prop->value.raw_data.bytes);
    size_t len = prop->value.raw_data_len;
    if (len == 0U) {
        len = strnlen(src, dst_len - 1U);
    } else if (src[len - 1U] == '\0') {
        len -= 1U;
    }
    if (len >= dst_len) {
        len = dst_len - 1U;
    }

    memcpy(dst, src, len);
    dst[len] = '\0';
    return true;
}

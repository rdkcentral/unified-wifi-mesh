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

#pragma once
#ifndef TR_181_HELPER_H
#define TR_181_HELPER_H

#include <stddef.h>
#include <stdlib.h>
#include <cstring>
#include "bus.h"
#include <string>

#define TR181_SETSSID_MAX_PARAM_LEN 128

/**
 * Initialize a bus_data_prop_t with the given string value.
 * @param name The name of the property.
 * @param value The string value to set.
 * @return A pointer to the allocated bus_data_prop_t, or NULL on failure.
 * 
 * The caller is responsible for freeing the returned bus_data_prop_t and its internal string buffer.
 */
bus_data_prop_t *tr181_alloc_string_prop(const char *name, const char *value);

/**
 * Set a standard "Status" output property in the provided output_data structure.
 * @param output_data The raw_data_t structure to populate with the status property.
 * @param status The status string to set (e.g., "Success", "Failure: reason").
 * 
 * This function allocates a bus_data_prop_t for the status and assigns it to output_data. 
 * The caller is responsible for freeing the allocated property and its internal string buffer when done.
 */
bus_data_prop_t *tr181_set_status_output_prop(const char *status);

/**
 * Helper function to set the output_data with a "Status" property based on the provided status string.
 * @param output_data The raw_data_t structure to populate with the status property.
 * @param status The status string to set (e.g., "Success", "Failure: reason").
 *  
 * This function internally calls tr181_set_status_output_prop to create the property and assigns it to output_data.
 * The caller is responsible for freeing the allocated property and its internal string buffer when done.
 */
void tr181_set_status_output(raw_data_t *output_data, const char *status);

/**
 * Copy a string value from a bus_data_prop_t to a destination buffer.
 * @param prop The bus_data_prop_t containing the string property to copy.
 * @param dst The destination buffer to copy the string into.
 * @param dst_len The length of the destination buffer.
 * @return true if the copy was successful, false otherwise (e.g., invalid input, type mismatch).
 * 
 * This function checks that the property is of type string and that the raw data is not NULL before copying.
 * It ensures that the copied string is null-terminated and does not exceed the destination buffer length
 */
bool tr181_copy_prop_string(const bus_data_prop_t *prop, char *dst, size_t dst_len);
#endif // TR_181_HELPER_H

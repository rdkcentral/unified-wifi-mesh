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

#ifndef EM_CLI_APIS_H
#define EM_CLI_APIS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "em_base.h"
	
em_network_node_t *exec(char *in, size_t in_len);
int init(em_editor_callback_t func);
const char *get_first_cmd_str();
const char *get_next_cmd_str(const char *cmd);
em_network_node_t *get_network_tree_by_file(const char *file_name);
em_network_node_t *get_network_tree(char *buff);
em_network_node_t *get_child_node_at_index(em_network_node_t *node, unsigned int idx);
char *get_formatted_node_scalar_value(em_network_node_t *node);
char *get_formatted_node_array_value(em_network_node_t *node);
void free_formatted_node_value(char *str);
em_network_node_data_type_t get_node_type(em_network_node_t *node);
void free_network_tree(em_network_node_t *node);
void *network_tree_to_json(em_network_node_t *node);
void print_network_tree(em_network_node_t *node);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // EM_CLI_APIS_H

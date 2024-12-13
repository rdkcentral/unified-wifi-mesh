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

#ifndef EM_CLI_H
#define EM_CLI_H

#include "em_base.h"
#include "em_cmd_exec.h"

class em_cli_t {
    em_cmd_t& get_command(char *in, size_t in_len);

public:
	em_editor_callback_t m_editor_cb;

	char *exec(char *in, size_t in_len, em_status_string_t out);
    em_network_node_t *exec(char *in, size_t in_len);
    int init(em_editor_callback_t func);
	const char *get_first_cmd_str();
	const char *get_next_cmd_str(const char *cmd);
	
	em_network_node_t *get_network_tree_by_file(const char *file_name);
	em_network_node_t *get_network_tree(char *buff);
	int get_network_tree_node(cJSON *obj, em_network_node_t *root);
	void free_network_tree(em_network_node_t *tree);
	void free_network_tree_node(em_network_node_t *node);
	void *network_tree_to_json(em_network_node_t *root);
	cJSON *network_tree_node_to_json(em_network_node_t *node, cJSON *parent);
	void print_network_tree(em_network_node_t *tree);
	void print_network_tree_node(em_network_node_t *node, unsigned int *pident);

    em_cli_t();
    ~em_cli_t();
};

em_cli_t *get_cli();

#endif

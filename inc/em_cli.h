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
    em_long_string_t	m_lib_dbg_file_name;

public:
	em_editor_callback_t m_editor_cb;
	void *m_user_data;

    em_network_node_t *exec(char *in, size_t in_len);
    int init(em_editor_callback_t func, void *user_data);
	const char *get_first_cmd_str();
	const char *get_next_cmd_str(const char *cmd);
	
    em_network_node_t *get_network_tree_by_file(const char *file_name);
    em_network_node_t *get_network_tree(char *buff);
    em_network_node_t *clone_network_tree(em_network_node_t *orig_node, em_network_node_t *dis_node, 
            unsigned int index, bool collapse, unsigned int *node_ctr = NULL);
    em_network_node_t *get_node_from_node_ctr(em_network_node_t *tree, unsigned int node_display_ctr);
    int get_network_tree_node(cJSON *obj, em_network_node_t *root, unsigned int *node_ctr);
    em_network_node_t *get_child_node_at_index(em_network_node_t *node, unsigned int idx);
    unsigned int get_node_display_position(em_network_node_t *node);
    char *get_formatted_node_scalar_value(em_network_node_t *node);
    char *get_formatted_node_array_value(em_network_node_t *node);
    em_network_node_data_type_t get_node_type(em_network_node_t *node);
    void free_formatted_node_value(char *str);
    void free_network_tree(em_network_node_t *tree);
    void free_network_tree_node(em_network_node_t *node);
    void *network_tree_to_json(em_network_node_t *root);
    cJSON *network_tree_node_to_json(em_network_node_t *node, cJSON *parent);
    char *get_network_tree_string(em_network_node_t *tree);
    void get_network_tree_node_string(char *str, em_network_node_t *node, unsigned int *pident);
    void init_lib_dbg(char *file_name);
    void dump_lib_dbg(char *str);

    em_cli_t();
    ~em_cli_t();
};

em_cli_t *get_cli();

#endif


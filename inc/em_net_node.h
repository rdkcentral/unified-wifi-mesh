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

#ifndef EM_NET_NODE_H
#define EM_NET_NODE_H

#include "em_base.h"

class em_net_node_t {

public:
    static em_network_node_t *get_network_tree_by_file(const char *file_name);
    static em_network_node_t *get_network_tree(char *buff);
    static em_network_node_t *clone_network_tree(em_network_node_t *node);
    static em_network_node_t *clone_network_tree_for_display(em_network_node_t *orig_node, em_network_node_t *dis_node, 
            unsigned int index, bool collapse, unsigned int *node_ctr = NULL);
    static em_network_node_t *get_node_from_node_ctr(em_network_node_t *tree, unsigned int node_display_ctr);
    static int get_network_tree_node(cJSON *obj, em_network_node_t *root, unsigned int *node_ctr);
    static em_network_node_t *get_child_node_at_index(em_network_node_t *node, unsigned int idx);
    static unsigned int get_node_display_position(em_network_node_t *node);
    static char *get_formatted_node_scalar_value(em_network_node_t *node);
    static char *get_formatted_node_array_value(em_network_node_t *node);
    static em_network_node_data_type_t get_node_type(em_network_node_t *node);
    static void free_formatted_node_value(char *str);
    static void free_network_tree(em_network_node_t *tree);
    static void free_network_tree_node(em_network_node_t *node);
    static void *network_tree_to_json(em_network_node_t *root);
    static cJSON *network_tree_node_to_json(em_network_node_t *node, cJSON *parent);
    static char *get_network_tree_string(em_network_node_t *tree);
    static void get_network_tree_node_string(char *str, em_network_node_t *node, unsigned int *pident);

    em_net_node_t();
    ~em_net_node_t();
};

#endif


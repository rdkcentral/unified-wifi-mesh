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
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "em_net_node.h"
#include "em_cmd_exec.h"

em_network_node_data_type_t em_net_node_t::get_node_type(em_network_node_t *node)
{
    return node->type;
}

void em_net_node_t::free_node_value(char *str)
{
    free(str);
}

char *em_net_node_t::get_node_array_value(em_network_node_t *node, em_network_node_data_type_t *type)
{
    char *str;
    em_2xlong_string_t tmp_str;
    unsigned int i;

    str = static_cast<char *> (malloc(sizeof(em_long_string_t)));
    memset(str, 0, sizeof(em_long_string_t));

    if (node->num_children == 0) {
		snprintf(str, sizeof(em_long_string_t), "[]");
		*type = em_network_node_data_type_array_str;
        return str;
    }

    snprintf(str, sizeof(em_long_string_t), "[");
    for (i = 0; i < node->num_children; i++) {
        if (node->child[0]->type == em_network_node_data_type_string) {
			*type = em_network_node_data_type_array_str;
            snprintf(tmp_str, sizeof(em_2xlong_string_t), "%s, ", node->child[i]->value_str);
        } else {
			*type = em_network_node_data_type_array_num;
            snprintf(tmp_str, sizeof(em_2xlong_string_t), "%d, ", node->child[i]->value_int);
        }
        strncat(str, tmp_str, strlen(tmp_str));	
    }

    str[strlen(str) - 2] = ']';


    return str;
}

void em_net_node_t::set_node_array_value(em_network_node_t *node, char *fmt)
{
	em_long_string_t value;
	char *tmp, *remain;
	em_network_node_data_type_t arrType = em_network_node_data_type_invalid;

	if (node->type == em_network_node_data_type_array_str) {
		arrType = em_network_node_data_type_string;
	} else if (node->type == em_network_node_data_type_array_num) {
		arrType = em_network_node_data_type_number;
	}

	node->type = em_network_node_data_type_array_obj;

	if (*fmt == 0) {
		return;		
	}

	if ((tmp = strchr(fmt, '[')) == NULL) {
		return;
	}
		
	tmp++;

	if (*tmp == ']') {
		node->num_children = 0;
		return;
	}
		
	snprintf(value, sizeof(em_long_string_t), "%s", tmp);

	tmp = value;
	remain = value;


	while ((tmp = strstr(remain, ", ")) != NULL) {
		*tmp = 0;
	
		node->child[node->num_children] = static_cast<em_network_node_t *>(malloc(sizeof(em_network_node_t)));
		memset(node->child[node->num_children], 0, sizeof(em_network_node_t));
		node->child[node->num_children]->type = arrType;
		if (arrType == em_network_node_data_type_string) {
			strncpy(node->child[node->num_children]->value_str, remain, sizeof(em_long_string_t));
		} else if (arrType == em_network_node_data_type_number) {
			node->child[node->num_children]->value_int = static_cast<unsigned int> (atoi(remain));
		}
	
		node->num_children++;
		
		remain = tmp + 2;	
	}

	if ((tmp = strchr(remain, ']')) != NULL) {
		*tmp = 0;
	}

	node->child[node->num_children] = static_cast<em_network_node_t *> (malloc(sizeof(em_network_node_t)));
	memset(node->child[node->num_children], 0, sizeof(em_network_node_t));
	node->child[node->num_children]->type = arrType;
	if (arrType == em_network_node_data_type_string) {
		strncpy(node->child[node->num_children]->value_str, remain, sizeof(em_long_string_t));
	} else if (arrType == em_network_node_data_type_number) {
		node->child[node->num_children]->value_int = static_cast<unsigned int> (atoi(remain));
	}
	
	node->num_children++;
	
}

char *em_net_node_t::get_node_scalar_value(em_network_node_t *node)
{
    char *str;

    str = static_cast<char *> (malloc(sizeof(em_long_string_t)));
    memset(str, 0, sizeof(em_long_string_t));

    switch (node->type) {
        case em_network_node_data_type_invalid:
            break;

        case em_network_node_data_type_false:
            snprintf(str, sizeof(em_long_string_t), "false");
            break;

        case em_network_node_data_type_true:
            snprintf(str, sizeof(em_long_string_t), "true");
            break;

        case em_network_node_data_type_null:
            break;

        case em_network_node_data_type_number:
            snprintf(str, sizeof(em_long_string_t), "%d", node->value_int);
            break;

        case em_network_node_data_type_string:
            snprintf(str, sizeof(em_long_string_t), "%s", node->value_str);
            break;

        case em_network_node_data_type_array_obj:
            break;

        case em_network_node_data_type_obj:
            snprintf(str, sizeof(em_long_string_t), "object");
            break;

        case em_network_node_data_type_raw:
            break;
    
        default:
            break;

    }

    return str;

}

void em_net_node_t::set_node_scalar_value(em_network_node_t *node, char *fmt)
{
	switch (node->type) {
		case em_network_node_data_type_false:
			node->value_int = 0;
			break;

		case em_network_node_data_type_true:
			node->value_int = 1;
			break;
		
		case em_network_node_data_type_number:
			node->value_int = static_cast<unsigned int> (atoi(fmt));
			break;

		case em_network_node_data_type_string:
			strncpy(node->value_str, fmt, strlen(fmt) + 1);
			break;

        default:
            break;
	}
}

void em_net_node_t::get_network_tree_node_string(char *str, em_network_node_t *node, unsigned int *pident)
{
    unsigned int i, ident = 0;
    em_long_string_t fmt = {0};
    em_3xlong_string_t string = {0};
    em_2xlong_string_t value_str = {0};
    em_2xlong_string_t tmp_str;

    ident = *pident;
    ident++;
    *pident = ident;

    for (i = 0; i < ident; i++) {
        strncat(fmt, "   ", (sizeof(fmt) - strlen(fmt) - 1));
    }

    switch (node->type) {
        case em_network_node_data_type_invalid:
            break;

        case em_network_node_data_type_false:
            snprintf(string, sizeof(em_3xlong_string_t), "%s%s:\tfalse\n", fmt, node->key);
            break;

        case em_network_node_data_type_true:
            snprintf(string, sizeof(em_3xlong_string_t), "%s%s:\ttrue\n", fmt, node->key);
            break;

        case em_network_node_data_type_null:
            break;

        case em_network_node_data_type_number:
            snprintf(string, sizeof(em_3xlong_string_t), "%s%s:\t%d\n", fmt, node->key, node->value_int);
            break;

        case em_network_node_data_type_string:
            snprintf(string, sizeof(em_3xlong_string_t), "%s%s:\t%s\n", fmt, node->key, node->value_str);
            break;

        case em_network_node_data_type_array_obj:
            snprintf(string, sizeof(em_3xlong_string_t), "%s%s:", fmt, node->key);
            if ((node->num_children > 0) && ((node->child[0]->type == em_network_node_data_type_array_obj) ||
                        (node->child[0]->type == em_network_node_data_type_obj))) {
                printf("\n");
            } else if (node->num_children == 0) {
                //printf("\n");
            }
            break;

        case em_network_node_data_type_obj:
            if (node->key[0] != 0) {
                snprintf(string, sizeof(em_3xlong_string_t), "%s%s\t\n", fmt, node->key);
            }
            break;

        case em_network_node_data_type_raw:
            break;

        default:
            break;

    }

    strncat(str, string, strlen(string));

    if ((node->type == em_network_node_data_type_array_obj) && (node->num_children > 0) &&
            ((node->child[0]->type == em_network_node_data_type_number) ||
             (node->child[0]->type == em_network_node_data_type_string))) {

        snprintf(value_str, sizeof(em_2xlong_string_t), "[");
        for (i = 0; i < node->num_children; i++) {
            if (node->child[0]->type == em_network_node_data_type_string) {
                snprintf(tmp_str, sizeof(em_2xlong_string_t), "%s, ", node->child[i]->value_str);
            } else {
                snprintf(tmp_str, sizeof(em_2xlong_string_t), "%d, ", node->child[i]->value_int);
            }
            size_t available_len = std::min(strlen(tmp_str), (sizeof(value_str) - strlen(value_str) - 1));
            strncat(value_str, tmp_str, available_len);
        }

        value_str[strlen(value_str) - 2] = ']';
        strncat(value_str, "\n", (sizeof(value_str) - strlen(value_str) - 1));
        strncat(str, value_str, strlen(value_str));
    } else {

        if (node->type == em_network_node_data_type_array_obj) {
            if (node->num_children == 0) {
                strncat(str, "[", (sizeof(str) - strlen(str) - 1));
            } else {
                snprintf(value_str, sizeof(value_str), "%s[\n", fmt);
                strncat(str, value_str, strlen(value_str));
            }
        } else if (node->type == em_network_node_data_type_obj) {
            if (node->num_children == 0) {
                strncat(str, "{", (sizeof(str) - strlen(str) - 1));
            } else {
                snprintf(value_str, sizeof(value_str), "%s{\n", fmt);
                strncat(str, value_str, strlen(value_str));
            }
        }

        for (i = 0; i < node->num_children; i++) {
            get_network_tree_node_string(str, node->child[i], pident);
        }
        if (node->type == em_network_node_data_type_array_obj) {
            if (node->num_children == 0) {
                strncat(str, "]\n", (sizeof(str) - strlen(str) - 1));
            } else {
                snprintf(value_str, sizeof(value_str), "%s]\n", fmt);
                strncat(str, value_str, strlen(value_str));
            }
        } else if (node->type == em_network_node_data_type_obj) {
            if (node->num_children == 0) {
                strncat(str, "}\n", (sizeof(str) - strlen(str) - 1));
            } else {
                snprintf(value_str, sizeof(value_str), "%s}\n", fmt);
                strncat(str, value_str, strlen(value_str));
            }

        }
    }

    ident = *pident;
    ident--;
    *pident = ident;
}

char *em_net_node_t::get_network_tree_string(em_network_node_t *node)
{
    unsigned int ident = 0;
    unsigned int size = EM_LONG_IO_BUFF_SZ;
    char *str;

    str = static_cast<char *> (malloc(size));
    memset(str, 0, size);

    get_network_tree_node_string(str, node, &ident);	

    return str;
}

cJSON *em_net_node_t::network_tree_node_to_json(em_network_node_t *node, cJSON *parent)
{
    unsigned int i;
    cJSON *obj = NULL;

    switch (node->type) {
        case em_network_node_data_type_invalid:
            break;

        case em_network_node_data_type_false:
            obj = cJSON_CreateFalse();
            break;

        case em_network_node_data_type_true:
            obj = cJSON_CreateTrue();
            break;

        case em_network_node_data_type_null:
            obj = cJSON_CreateNull();
            break;

        case em_network_node_data_type_number:
            obj = cJSON_CreateNumber(node->value_int);
            break;

        case em_network_node_data_type_string:
            obj = cJSON_CreateString(node->value_str);
            break;

        case em_network_node_data_type_array_obj:
            obj = cJSON_CreateArray();
            break;

        case em_network_node_data_type_obj:
            obj = cJSON_CreateObject();
            break;

        case em_network_node_data_type_raw:
            break;

        default:
            break;
    }

    if (obj == NULL) {
        printf("%s:%d: Failed to allocate JSON object\n",__func__,__LINE__);
        return NULL;
    }

    cJSON_AddItemToObject(parent, node->key, obj);

    for (i = 0; i < node->num_children; i++) {
        network_tree_node_to_json(node->child[i], obj);
    }

    return obj;

}

void *em_net_node_t::network_tree_to_json(em_network_node_t *root)
{
    cJSON *obj;
    unsigned int i;

    obj = cJSON_CreateObject();
    if (obj == NULL) {
        printf("%s:%d: Failed to allocate JSON object\n",__func__,__LINE__);
        return NULL;
    }

    for (i = 0; i < root->num_children; i++) {
        network_tree_node_to_json(root->child[i], obj);	
    }

    return obj;	
}

int em_net_node_t::get_network_tree_node(cJSON *obj, em_network_node_t *root, unsigned int *node_display_ctr)
{
    cJSON *child_obj, *tmp_obj;
    int sz = 0;

    if (obj->string != NULL) {
        strncpy(root->key, obj->string, strlen(obj->string) + 1);
    }

    if (cJSON_IsInvalid(obj) == true) {
        root->type = em_network_node_data_type_invalid;
    } else if (cJSON_IsString(obj) == true) {
        root->type = em_network_node_data_type_string;
        strncpy(root->value_str, obj->valuestring, strlen(obj->valuestring) + 1);
    } else if (cJSON_IsNumber(obj) == true) {
        root->type = em_network_node_data_type_number;
        root->value_int = static_cast<unsigned int> (obj->valueint);
    } else if (cJSON_IsArray(obj) == true) {
        root->type = em_network_node_data_type_array_obj;
    } else if (cJSON_IsFalse(obj) == true) {
        root->type = em_network_node_data_type_false;
    } else if (cJSON_IsTrue(obj) == true) {
        root->type = em_network_node_data_type_true;
    } else if (cJSON_IsNull(obj) == true) {
        root->type = em_network_node_data_type_null;
    } else if (cJSON_IsRaw(obj) == true) {
        root->type = em_network_node_data_type_raw;
    } else if (cJSON_IsObject(obj) == true) {
        root->type = em_network_node_data_type_obj;
    }

    if (obj->child == NULL) {
        root->num_children = 0;
        return 0;
    }

    child_obj = obj->child;
    tmp_obj = child_obj;

    while (tmp_obj != NULL) {

        //TBD with details as this needs to be revisited
        sz = sizeof(em_network_node_t) *  2;
        root->child[root->num_children] = (em_network_node_t *)malloc(sz);
        memset(root->child[root->num_children], 0, sz);

        if (cJSON_IsArray(obj) == true) {
            if ((cJSON_IsObject(tmp_obj) == true) || (cJSON_IsArray(tmp_obj) == true)) {
                (*node_display_ctr)++;
            }	
        } else {
            (*node_display_ctr)++;
        }
        root->child[root->num_children]->display_info.node_ctr = *node_display_ctr;
        root->child[root->num_children]->display_info.orig_node_ctr = *node_display_ctr;
        root->child[root->num_children]->display_info.node_pos = root->display_info.node_pos + 1;
        get_network_tree_node(tmp_obj, root->child[root->num_children], node_display_ctr);

        root->num_children++;

        tmp_obj = tmp_obj->next;	
    }

    return static_cast<int> (root->num_children);
}

em_network_node_t *em_net_node_t::get_network_tree(char *buff)
{
    cJSON *root_obj = NULL;
    em_network_node_t *root;
    unsigned int node_display_ctr = 0;

	if ((buff == NULL) || (*buff == 0)) {
		return NULL;
	}

    if ((root_obj = cJSON_Parse(buff)) == NULL) {
        return NULL;
    }

	//printf("%s:%d: %s\n", __func__, __LINE__, cJSON_Print(root_obj));

    root = static_cast<em_network_node_t *> (malloc(sizeof(em_network_node_t)));
    memset(root, 0, sizeof(em_network_node_t));

    get_network_tree_node(root_obj, root, &node_display_ctr);

    cJSON_Delete(root_obj);

    return root;

}

em_network_node_t *em_net_node_t::get_node_from_node_ctr(em_network_node_t *tree, unsigned int node_display_ctr)
{
    em_network_node_t *node = NULL;
    bool found_match = false;
    unsigned int i;

    if (tree == NULL) return NULL;

    if (tree->display_info.node_ctr == node_display_ctr) {
        return tree;
    } else {
        for (i = 0; i < tree->num_children; i++) {
            if ((node = get_node_from_node_ctr(tree->child[i], node_display_ctr)) != NULL) {
                found_match = true;
                break;
            }
        }

        if (found_match == true) {
            return node;
        }
    }

    return NULL;
}

em_network_node_t *em_net_node_t::clone_network_tree(em_network_node_t *node)
{
    em_network_node_t *cloned = NULL;
	unsigned int i;

    if (node == NULL) {
        return NULL;
    }

    cloned = static_cast<em_network_node_t *> (malloc(sizeof(em_network_node_t)));
    memset(cloned, 0, sizeof(em_network_node_t));

    strncpy(cloned->key, node->key, strlen(node->key) + 1);
    memcpy(&cloned->display_info, &node->display_info, sizeof(em_node_display_info_t));
    cloned->display_info.orig_node_ctr = node->display_info.orig_node_ctr;

    cloned->type = node->type;
    strncpy(cloned->value_str, node->value_str, sizeof(em_long_string_t));
    cloned->value_int = node->value_int;

	for (i = 0; i < node->num_children; i++) {
     	cloned->child[i] = clone_network_tree(node->child[i]);
    	cloned->num_children++;
    }

	return cloned;
}

em_network_node_t *em_net_node_t::clone_network_tree_for_display(em_network_node_t *orig_node, em_network_node_t *dis_node, unsigned int index, bool collapse, unsigned int *node_display_ctr)
{
    em_network_node_t *cloned = NULL, *tree_to_add = NULL;
    unsigned int i;
    bool should_consider = false;
    bool trim_result = false;
    em_network_node_t *node;
    unsigned int start_node_ctr = 0;

    if (node_display_ctr == NULL) {
        node_display_ctr = &start_node_ctr;
    }

    if (orig_node == NULL) {
        return NULL;
    }

    if (dis_node == NULL) {
        node = orig_node;
    } else {
        node = dis_node;
    }

	// first check if the node has Result, then trim the result
	for (i = 0; i < node->num_children; i++) {
		if (strncmp(node->child[i]->key, "Result", strlen("Result")) == 0) {
			node = node->child[i];
			trim_result = true;
			break;
		}
	}

    cloned = static_cast<em_network_node_t *> (malloc(sizeof(em_network_node_t)));
    memset(cloned, 0, sizeof(em_network_node_t));

	if (trim_result == false) {
    	strncpy(cloned->key, node->key, strlen(node->key) + 1);
	} else {
		trim_result = false;
	}
    memcpy(&cloned->display_info, &node->display_info, sizeof(em_node_display_info_t));
    cloned->display_info.node_ctr = *node_display_ctr;
    cloned->display_info.orig_node_ctr = node->display_info.orig_node_ctr;

    cloned->type = node->type;
    strncpy(cloned->value_str, node->value_str, sizeof(em_long_string_t));
    cloned->value_int = node->value_int;

    should_consider = (node->display_info.node_ctr == index);

    if (should_consider == true) {
        if (collapse == false) {
            tree_to_add = get_node_from_node_ctr(orig_node, node->display_info.orig_node_ctr);	
            //dump_lib_dbg(get_network_tree_string(tree_to_add));
            assert(tree_to_add != NULL);
            assert(tree_to_add->num_children > 0);
            for (i = 0; i < tree_to_add->num_children; i++) {
                if (node->type == em_network_node_data_type_array_obj) {
                    if ((tree_to_add->child[0]->type == em_network_node_data_type_array_obj) || 
                            (tree_to_add->child[0]->type == em_network_node_data_type_obj)) {
                        (*node_display_ctr)++;
                    }
                } else {
                    (*node_display_ctr)++;
                }
                cloned->child[i] = clone_network_tree_for_display(orig_node, tree_to_add->child[i], index, collapse, node_display_ctr);
            }
            cloned->display_info.collapsed = false;
            cloned->num_children = tree_to_add->num_children;


        } else {
            if (dis_node->num_children > 0) {
                cloned->display_info.collapsed = true;
            }
        }

    } else {
        for (i = 0; i < node->num_children; i++) {
            if (node->type == em_network_node_data_type_array_obj) {
                if ((node->child[0]->type == em_network_node_data_type_array_obj) || (node->child[0]->type == em_network_node_data_type_obj)) {
                    (*node_display_ctr)++;
                }
            } else {
                (*node_display_ctr)++;
            }
            cloned->child[i] = clone_network_tree_for_display(orig_node, node->child[i], index, collapse, node_display_ctr);
            cloned->num_children++;
        }

    }

    return cloned;
}

em_network_node_t *em_net_node_t::get_network_tree_by_file(const char *file_name)
{
    char buff[EM_IO_BUFF_SZ];

    if (em_cmd_exec_t::load_params_file(file_name, buff) < 0) {
        return NULL;
    }

    return get_network_tree(buff);
}

void em_net_node_t::free_network_tree_node(em_network_node_t *node)
{
    unsigned int i;

    for (i = 0; i < node->num_children; i++) {
        free_network_tree_node(node->child[i]);
    }

    free(node);
}

void em_net_node_t::free_network_tree(em_network_node_t *node)
{
    free_network_tree_node(node);
}

em_network_node_t *em_net_node_t::get_child_node_at_index(em_network_node_t *node, unsigned int idx)
{
    //printf("%s:%d: Index: %d(%d), node:%p\n", __func__, __LINE__, idx, node->num_children, node->child[idx]);
    return node->child[idx];
}

unsigned int em_net_node_t::get_node_display_position(em_network_node_t *node)
{
    return node->display_info.node_pos;
}

em_network_node_t *em_net_node_t::get_network_tree_by_key(em_network_node_t *node, em_long_string_t key)
{
	unsigned int i;
	em_network_node_t *tmp;

	if (strncmp(node->key, key, strlen(key)) == 0) {
		return node;
	}	

	for (i = 0; i < node->num_children; i++) {
		if ((tmp = get_network_tree_by_key(node->child[i], key)) != NULL) {
			return tmp;
		}	
	}

	return NULL;
}


em_net_node_t::em_net_node_t()
{
}

em_net_node_t::~em_net_node_t()
{
}

extern "C" void *get_network_tree_by_file(const char *file_name)
{
    return em_net_node_t::get_network_tree_by_file(file_name);
}

extern "C" void *get_network_tree(char *buff)
{
    return em_net_node_t::get_network_tree(buff);
}

extern "C" em_network_node_t *get_child_node_at_index(em_network_node_t *node, unsigned int idx)
{
    return em_net_node_t::get_child_node_at_index(node, idx);
}

extern "C" void free_network_tree(void *node)
{
    return em_net_node_t::free_network_tree((em_network_node_t *)node);
}

extern "C" void *network_tree_to_json(em_network_node_t *node)
{
    return em_net_node_t::network_tree_to_json(node);
}

extern "C" char *get_network_tree_string(em_network_node_t *node)
{
    return em_net_node_t::get_network_tree_string(node);
}

extern "C" void free_network_tree_string(char *str)
{
    em_net_node_t::free_network_tree_string(str);
}

extern "C" char *get_node_scalar_value(em_network_node_t *node)
{
    return em_net_node_t::get_node_scalar_value(node);
}

extern "C" char *get_node_array_value(em_network_node_t *node, em_network_node_data_type_t *type)
{
    return em_net_node_t::get_node_array_value(node, type);
}

extern "C" void set_node_array_value(em_network_node_t *node, char *fmt)
{
	em_net_node_t::set_node_array_value(node, fmt);
}

extern "C" void set_node_scalar_value(em_network_node_t *node, char *fmt)
{
	em_net_node_t::set_node_scalar_value(node, fmt);
}

extern "C" void free_node_value(char *str)
{
    return em_net_node_t::free_node_value(str);
}

extern "C" em_network_node_data_type_t get_node_type(em_network_node_t *node)
{
    return em_net_node_t::get_node_type(node);
}

extern "C" void set_node_type(em_network_node_t *node, int type)
{
	node->type = (em_network_node_data_type_t)type;
}

extern "C" unsigned int get_node_display_position(em_network_node_t *node)
{
    return em_net_node_t::get_node_display_position(node);
}

extern "C" em_network_node_t *get_node_from_node_ctr(em_network_node_t *tree, unsigned int node_display_ctr)
{
    return em_net_node_t::get_node_from_node_ctr(tree, node_display_ctr);
}

extern "C" em_network_node_t *clone_network_tree_for_display(em_network_node_t *orig_node, em_network_node_t *dis_node, unsigned int index, bool collapse)
{
    return em_net_node_t::clone_network_tree_for_display(orig_node, dis_node, index, collapse);
}

extern "C" em_network_node_t *clone_network_tree(em_network_node_t *node)
{
    return em_net_node_t::clone_network_tree(node);
}

extern "C" em_network_node_t *get_network_tree_by_key(em_network_node_t *node, em_long_string_t key)
{
	return em_net_node_t::get_network_tree_by_key(node, key);
}

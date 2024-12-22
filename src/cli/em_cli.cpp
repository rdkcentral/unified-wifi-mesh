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
#include <linux/filter.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "em_cmd_cli.h"
#include "em_cli.h"
#include <readline/readline.h>
#include <readline/history.h>

em_cli_t g_cli;

em_network_node_data_type_t em_cli_t::get_node_type(em_network_node_t *node)
{
	return node->type;
}

void em_cli_t::free_formatted_node_value(char *str)
{
	free(str);
}

char *em_cli_t::get_formatted_node_array_value(em_network_node_t *node)
{
    char *str;
	em_short_string_t tmp_str;
	unsigned int i;

    str = (char *)malloc(sizeof(em_long_string_t));
    memset(str, 0, sizeof(em_long_string_t));

	if (node->num_children == 0) {
		return str;
	}
		
	snprintf(str, sizeof(em_long_string_t), "[");
	for (i = 0; i < node->num_children; i++) {
		if (node->child[0]->type == em_network_node_data_type_string) {
			snprintf(tmp_str, sizeof(em_short_string_t), "%s, ", node->child[i]->value_str);
		} else {
			snprintf(tmp_str, sizeof(em_short_string_t), "%d, ", node->child[i]->value_int);
		}
		strncat(str, tmp_str, strlen(tmp_str));	
	}

	str[strlen(str) - 2] = ']';
	

    return str;
}


char *em_cli_t::get_formatted_node_scalar_value(em_network_node_t *node)
{
	char *str;

	str = (char *)malloc(sizeof(em_long_string_t));
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

        case em_network_node_data_type_array:
            break;

        case em_network_node_data_type_obj:
            snprintf(str, sizeof(em_long_string_t), "object");
            break;

        case em_network_node_data_type_raw:
            break;

    }

	return str;

}

void em_cli_t::get_network_tree_node_string(char *str, em_network_node_t *node, unsigned int *pident)
{
	unsigned int i, ident = 0;
	em_long_string_t fmt = {0};
	em_long_string_t string = {0};
	em_long_string_t value_str = {0};
	em_short_string_t tmp_str;

	ident = *pident;
	ident++;
	*pident = ident;

	for (i = 0; i < ident; i++) {
		strncat(fmt, "   ", strlen("   "));
	}

	switch (node->type) {
		case em_network_node_data_type_invalid:
			break;

		case em_network_node_data_type_false:
			snprintf(string, sizeof(em_long_string_t), "%s%s:\tfalse\n", fmt, node->key);
			break;

		case em_network_node_data_type_true:
			snprintf(string, sizeof(em_long_string_t), "%s%s:\ttrue\n", fmt, node->key);
			break;

		case em_network_node_data_type_null:
			break;

		case em_network_node_data_type_number:
			snprintf(string, sizeof(em_long_string_t), "%s%s:\t%d\n", fmt, node->key, node->value_int);
			break;

		case em_network_node_data_type_string:
			snprintf(string, sizeof(em_long_string_t), "%s%s:\t%s\n", fmt, node->key, node->value_str);
			break;

		case em_network_node_data_type_array:
			snprintf(string, sizeof(em_long_string_t), "%s%s:", fmt, node->key);
			if ((node->num_children > 0) && ((node->child[0]->type == em_network_node_data_type_array) ||
									(node->child[0]->type == em_network_node_data_type_obj))) {
				printf("\n");
			} else if (node->num_children == 0) {
				//printf("\n");
			}
			break;

		case em_network_node_data_type_obj:
			if (node->key[0] != 0) {
				snprintf(string, sizeof(em_long_string_t), "%s%s\t\n", fmt, node->key);
			}
			break;

		case em_network_node_data_type_raw:
			break;

	}

	strncat(str, string, strlen(string));
		
	if ((node->type == em_network_node_data_type_array) && (node->num_children > 0) &&
			((node->child[0]->type == em_network_node_data_type_number) ||
			(node->child[0]->type == em_network_node_data_type_string))) {
			
		snprintf(value_str, sizeof(em_long_string_t), "[");
		for (i = 0; i < node->num_children; i++) {
			if (node->child[0]->type == em_network_node_data_type_string) {
				snprintf(tmp_str, sizeof(em_short_string_t), "%s, ", node->child[i]->value_str);
			} else {
				snprintf(tmp_str, sizeof(em_short_string_t), "%d, ", node->child[i]->value_int);
			}
			strncat(value_str, tmp_str, strlen(tmp_str));	
		}

		value_str[strlen(value_str) - 2] = ']';
		strncat(value_str, "\n", strlen("\n"));
		strncat(str, value_str, strlen(value_str));
	} else {

		if (node->type == em_network_node_data_type_array) {
			if (node->num_children == 0) {
				strncat(str, "[", strlen("["));
			} else {
				snprintf(value_str, sizeof(value_str), "%s[\n", fmt);
				strncat(str, value_str, strlen(value_str));
			}
		} else if (node->type == em_network_node_data_type_obj) {
			if (node->num_children == 0) {
				strncat(str, "{", strlen("{"));
			} else {
				snprintf(value_str, sizeof(value_str), "%s{\n", fmt);
				strncat(str, value_str, strlen(value_str));
			}
		}

		for (i = 0; i < node->num_children; i++) {
			get_network_tree_node_string(str, node->child[i], pident);
		}
		if (node->type == em_network_node_data_type_array) {
			if (node->num_children == 0) {
				strncat(str, "]\n", strlen("]\n"));
			} else {
				snprintf(value_str, sizeof(value_str), "%s]\n", fmt);
				strncat(str, value_str, strlen(value_str));
			}
		} else if (node->type == em_network_node_data_type_obj) {
			if (node->num_children == 0) {
				strncat(str, "}\n", strlen("}\n"));
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

char *em_cli_t::get_network_tree_string(em_network_node_t *node)
{
	unsigned int ident = 0;
	unsigned int size = EM_LONG_IO_BUFF_SZ;
	char *str;
	
	str = (char *)malloc(size);
	memset(str, 0, size);

	get_network_tree_node_string(str, node, &ident);	

	return str;
}

cJSON *em_cli_t::network_tree_node_to_json(em_network_node_t *node, cJSON *parent)
{
	unsigned int i;
	cJSON *obj;

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

		case em_network_node_data_type_array:
			obj = cJSON_CreateArray();
			break;

		case em_network_node_data_type_obj:
			obj = cJSON_CreateObject();
			break;

		case em_network_node_data_type_raw:
			break;
	}

	if (obj == NULL) {
		printf("%s:%d: Failed to allocate JSON object\n");
		return NULL;
	}

	cJSON_AddItemToObject(parent, node->key, obj);

    for (i = 0; i < node->num_children; i++) {
        network_tree_node_to_json(node->child[i], obj);
    }

	return obj;
	
}

void *em_cli_t::network_tree_to_json(em_network_node_t *root)
{
	cJSON *obj;
	unsigned int i;

	obj = cJSON_CreateObject();
	if (obj == NULL) {
		printf("%s:%d: Failed to allocate JSON object\n");
		return NULL;
	}

	for (i = 0; i < root->num_children; i++) {
		network_tree_node_to_json(root->child[i], obj);	
	}

	//printf("%s:%d: %s\n", __func__, __LINE__, cJSON_Print(obj));

	return obj;	
}

int em_cli_t::get_network_tree_node(cJSON *obj, em_network_node_t *root, unsigned int *node_display_ctr)
{
	cJSON *child_obj, *tmp_obj;

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
		root->value_int = obj->valueint;
	} else if (cJSON_IsArray(obj) == true) {
		root->type = em_network_node_data_type_array;
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
		root->child[root->num_children] = (em_network_node_t *)malloc(sizeof(em_network_node_t));
		memset(root->child[root->num_children], 0, sizeof(em_network_node_t));
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
	
	return root->num_children;
}

em_network_node_t *em_cli_t::get_network_tree(char *buff)
{
	cJSON *obj = NULL;
	em_network_node_t *root;
	unsigned int node_display_ctr = 0;

	if ((obj = cJSON_Parse(buff)) == NULL) {
		return NULL;
	}

	root = (em_network_node_t *)malloc(sizeof(em_network_node_t));
	memset(root, 0, sizeof(em_network_node_t));
	
	get_network_tree_node(obj, root, &node_display_ctr);

	cJSON_Delete(obj);

	return root;

}

em_network_node_t *em_cli_t::get_node_from_node_ctr(em_network_node_t *tree, unsigned int node_display_ctr)
{
	em_network_node_t *node = NULL;
	bool found_match = false;
	unsigned int i;
	em_long_string_t	dbg;

	snprintf(dbg, sizeof(em_long_string_t), "Node: %s, Node Counter: %d", tree->key, tree->display_info.node_ctr); 
	dump_lib_dbg(dbg);	

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

em_network_node_t *em_cli_t::clone_network_tree(em_network_node_t *orig_node, em_network_node_t *dis_node, unsigned int index, bool collapse, unsigned int *node_display_ctr)
{
	em_network_node_t *cloned = NULL, *tree_to_add = NULL;
	unsigned int i;
	bool should_consider = false;
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

	cloned = (em_network_node_t *)malloc(sizeof(em_network_node_t));
	memset(cloned, 0, sizeof(em_network_node_t));
	
	strncpy(cloned->key, node->key, strlen(node->key) + 1);
	memcpy(&cloned->display_info, &node->display_info, sizeof(em_node_display_info_t));
	cloned->display_info.node_ctr = *node_display_ctr;
	cloned->display_info.orig_node_ctr = node->display_info.orig_node_ctr;

	cloned->type = node->type;
	strncpy(cloned->value_str, node->value_str, strlen(node->value_str) + 1);
	cloned->value_int = node->value_int;

	should_consider = (node->display_info.node_ctr == index);
		
	if (should_consider == true) {
		if (collapse == false) {
			tree_to_add = get_node_from_node_ctr(orig_node, node->display_info.orig_node_ctr);	
			dump_lib_dbg(get_network_tree_string(tree_to_add));
			assert(tree_to_add != NULL);
			assert(tree_to_add->num_children > 0);
			for (i = 0; i < tree_to_add->num_children; i++) {
				if (node->type == em_network_node_data_type_array) {
					if ((tree_to_add->child[0]->type == em_network_node_data_type_array) || 
								(tree_to_add->child[0]->type == em_network_node_data_type_obj)) {
						(*node_display_ctr)++;
					}
				} else {
					(*node_display_ctr)++;
				}
				cloned->child[i] = clone_network_tree(orig_node, tree_to_add->child[i], index, collapse, node_display_ctr);
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
			if (node->type == em_network_node_data_type_array) {
				if ((node->child[0]->type == em_network_node_data_type_array) || (node->child[0]->type == em_network_node_data_type_obj)) {
					(*node_display_ctr)++;
				}
			} else {
				(*node_display_ctr)++;
			}
			cloned->child[i] = clone_network_tree(orig_node, node->child[i], index, collapse, node_display_ctr);
			cloned->num_children++;
		}

	}

	return cloned;
}

em_network_node_t *em_cli_t::get_network_tree_by_file(const char *file_name)
{
	char buff[EM_IO_BUFF_SZ];

	if (em_cmd_cli_t::load_params_file(file_name, buff) < 0) {
		return NULL;
	}

	return get_network_tree(buff);
}

void em_cli_t::free_network_tree_node(em_network_node_t *node)
{
	unsigned int i;

	for (i = 0; i < node->num_children; i++) {
		free_network_tree_node(node->child[i]);
	}

	free(node);
}

void em_cli_t::free_network_tree(em_network_node_t *node)
{
	free_network_tree_node(node);
}

em_network_node_t *em_cli_t::get_child_node_at_index(em_network_node_t *node, unsigned int idx)
{
	//printf("%s:%d: Index: %d(%d), node:%p\n", __func__, __LINE__, idx, node->num_children, node->child[idx]);
	return node->child[idx];
}

unsigned int em_cli_t::get_node_display_position(em_network_node_t *node)
{
	return node->display_info.node_pos;
}


const char *em_cli_t::get_first_cmd_str()
{
	return em_cmd_cli_t::m_client_cmd_spec[0].get_cmd_name();
}

const char *em_cli_t::get_next_cmd_str(const char *cmd)
{
	unsigned int i = 0;
	bool found_match = false;

	if (cmd == NULL) {
		return NULL;
	}

	while (em_cmd_cli_t::m_client_cmd_spec[i].get_type() != em_cmd_type_max) {
		if (strncmp(em_cmd_cli_t::m_client_cmd_spec[i].get_cmd_name(), cmd, strlen(cmd)) == 0) {
			found_match = true;
			break;
		}

		i++;
	}

	if ((found_match == true) && (em_cmd_cli_t::m_client_cmd_spec[i + 1].get_type() != em_cmd_type_max)) {
		return em_cmd_cli_t::m_client_cmd_spec[i + 1].get_cmd_name();
	}

	return NULL;
}

em_cmd_t& em_cli_t::get_command(char *in, size_t in_len)
{
    unsigned int num_args = 0, idx = 0, i;
    em_cmd_type_t	allowed = em_cmd_type_none;
    char *tmp;
    em_cmd_t	*cmd;
    em_long_string_t args[EM_CLI_MAX_ARGS];

    memset(args[num_args], 0, sizeof(em_long_string_t));
    snprintf(args[num_args], sizeof(args[num_args]), "%s", in);
    tmp = args[num_args];

    tmp = strchr(args[num_args], ' ');
    while (tmp != NULL) {
        *tmp = 0; tmp++; num_args++;
        memset(args[num_args], 0, sizeof(em_long_string_t));
        snprintf(args[num_args], sizeof(args[num_args]), "%s", tmp);
        tmp = strchr(args[num_args], ' ');
    }
    num_args++;

    idx = 0; allowed = em_cmd_type_none;
    while (allowed != em_cmd_type_max) {
        cmd = &em_cmd_cli_t::m_client_cmd_spec[idx];
        tmp = (char *)cmd->get_cmd_name();
        if (strncmp(args[0], tmp, strlen(args[0])) == 0) {
            allowed = cmd->get_type();
            break;
        }
        idx++; allowed = cmd->get_type();
    }
    if ((allowed == em_cmd_type_none) || (allowed >= em_cmd_type_max)) {
        return em_cmd_cli_t::m_client_cmd_spec[em_cmd_type_none];;
    }

    if (num_args != cmd->m_param.u.args.num_args) {
        if ((num_args == cmd->m_param.u.args.num_args + 1)) {
            switch (cmd->get_type()) {
                case em_cmd_type_get_device:
                    strncat(cmd->m_param.u.args.fixed_args, "Summary", strlen("Summary"));
                    break;

                case em_cmd_type_get_sta:
                    if ((tmp = strstr(cmd->m_param.u.args.fixed_args, "Summary")) != NULL) {
                        *tmp = 0;
                    }
                    if (strncmp(args[num_args - 1], "1", strlen("1")) == 0) {
                        strncat(cmd->m_param.u.args.fixed_args, "Summary@Steer", strlen("Summary@Steer"));
                    } else if (strncmp(args[num_args - 1], "2", strlen("2")) == 0) {
                        strncat(cmd->m_param.u.args.fixed_args, "Summary@Disassociate", strlen("Summary@Disassociate"));
                    } else if (strncmp(args[num_args - 1], "3", strlen("3")) == 0) {
                        strncat(cmd->m_param.u.args.fixed_args, "Summary@BTM", strlen("Summary@BTM"));
                    }
                    break;

                case em_cmd_type_get_channel:
                    if ((tmp = strstr(cmd->m_param.u.args.fixed_args, "Summary")) != NULL) {
                        *tmp = 0;
                    }
                    if (strncmp(args[num_args - 1], "1", strlen("1")) == 0) {
                        strncat(cmd->m_param.u.args.fixed_args, "Summary@SetAnticipatedChannelPreference", 
							strlen("Summary@SetAnticipatedChannelPreference"));
                    } else if (strncmp(args[num_args - 1], "2", strlen("2")) == 0) {
                        strncat(cmd->m_param.u.args.fixed_args, "Summary@ScanChannel", 
							strlen("Summary@ScanChannel"));
					}
                    break;

				case em_cmd_type_get_radio:
                    if ((tmp = strstr(cmd->m_param.u.args.fixed_args, "Summary")) != NULL) {
                        *tmp = 0;
                    }
                    if (strncmp(args[num_args - 1], "1", strlen("1")) == 0) {
                        strncat(cmd->m_param.u.args.fixed_args, "Summary@RadioEnable",
                            strlen("Summary@RadioEnable"));
                    }
                    break;

                default:
                    break;
            }
        } else {
            return em_cmd_cli_t::m_client_cmd_spec[em_cmd_type_none];;
        }
    } else {
        if ((tmp = strstr(cmd->m_param.u.args.fixed_args, "Summary")) != NULL) {
            *tmp = 0;
        }
    }
    
    for (i = 0; i < num_args; i++) {
        snprintf(cmd->m_param.u.args.args[i], sizeof(cmd->m_param.u.args.args[i]), "%s", args[i]);
    }

    return em_cmd_cli_t::m_client_cmd_spec[idx];
}

em_network_node_t *em_cli_t::exec(char *in, size_t sz)
{
    em_long_string_t cmd;
    em_status_string_t res;
    em_cmd_cli_t *cli_cmd;

    snprintf(cmd, sizeof(cmd),  "%s", in);
    cli_cmd = new em_cmd_cli_t(get_command(cmd, sz));

    cli_cmd->init();

    if (cli_cmd->validate() == false) {
        cli_cmd->m_cmd.status_to_string(em_cmd_out_status_invalid_input, res);
    } else {
        if (cli_cmd->execute(res) != 0) {
            cli_cmd->m_cmd.status_to_string(em_cmd_out_status_invalid_input, res);

        }
    }

    delete cli_cmd;

	return get_network_tree(res);	
}

void em_cli_t::init_lib_dbg(char *file_name)
{
	FILE *fp;

	strncpy(m_lib_dbg_file_name, file_name, strlen(file_name) + 1);
	if ((fp = fopen(file_name, "w")) == NULL) {
        return;
    }

	fclose(fp);
}

void em_cli_t::dump_lib_dbg(char *str)
{
	FILE *fp;

	if ((fp = fopen(m_lib_dbg_file_name, "a")) == NULL) {
		return;
	}

	fputs("\n==========\n", fp);	
	fputs(str, fp);

	fclose(fp);
}

int em_cli_t::init(em_editor_callback_t cb)
{
	m_editor_cb = cb;

	return 0;
}

em_cli_t::em_cli_t()
{
}

em_cli_t::~em_cli_t()
{
}

em_cli_t *get_cli()
{
	return &g_cli;
}

extern "C" em_network_node_t *exec(char *in, size_t in_len)
{
	return g_cli.exec(in, in_len);
}
    
extern "C" int init(em_editor_callback_t func)
{
	return g_cli.init(func);
}

extern "C" const char *get_first_cmd_str()
{
	return g_cli.get_first_cmd_str();
}

extern "C" const char *get_next_cmd_str(const char *cmd)
{
	return g_cli.get_next_cmd_str(cmd);
}

extern "C" void *get_network_tree_by_file(const char *file_name)
{
	return g_cli.get_network_tree_by_file(file_name);
}

extern "C" void *get_network_tree(char *buff)
{
	return g_cli.get_network_tree(buff);
}

extern "C" em_network_node_t *get_child_node_at_index(em_network_node_t *node, unsigned int idx)
{
	return g_cli.get_child_node_at_index(node, idx);
}

extern "C" void free_network_tree(void *node)
{
	return g_cli.free_network_tree((em_network_node_t *)node);
}

extern "C" void *network_tree_to_json(em_network_node_t *node)
{
    return g_cli.network_tree_to_json(node);
}

extern "C" char *get_network_tree_string(em_network_node_t *node)
{
	return g_cli.get_network_tree_string(node);
}

extern "C" void free_network_tree_string(char *str)
{
	free(str);
}

extern "C" char *get_formatted_node_scalar_value(em_network_node_t *node)
{
	return g_cli.get_formatted_node_scalar_value(node);
}

extern "C" char *get_formatted_node_array_value(em_network_node_t *node)
{
	return g_cli.get_formatted_node_array_value(node);
}

extern "C" void free_formatted_node_value(char *str)
{
	return g_cli.free_formatted_node_value(str);
}

extern "C" em_network_node_data_type_t get_node_type(em_network_node_t *node)
{
	return g_cli.get_node_type(node);
}

extern "C" unsigned int get_node_display_position(em_network_node_t *node)
{
	return g_cli.get_node_display_position(node);
}

extern "C" em_network_node_t *get_node_from_node_ctr(em_network_node_t *tree, unsigned int node_display_ctr)
{
	return g_cli.get_node_from_node_ctr(tree, node_display_ctr);
}

extern "C" em_network_node_t *clone_network_tree(em_network_node_t *orig_node, em_network_node_t *dis_node, unsigned int index, bool collapse)
{
	return g_cli.clone_network_tree(orig_node, dis_node, index, collapse);
}

extern "C" void init_lib_dbg(char *file_name)
{
	g_cli.init_lib_dbg(file_name);
}

extern "C" void dump_lib_dbg(char *str)
{
	g_cli.dump_lib_dbg(str);
}

extern "C" unsigned int can_collapse_node(em_network_node_t *node)
{
	em_long_string_t dbg;

	snprintf(dbg, sizeof(em_long_string_t), "display counter: %d, type: %d, children:%d, node: %s, value:%s\n", 
			node->display_info.node_ctr, node->type, node->num_children, node->key, node->value_str);	
	g_cli.dump_lib_dbg(dbg);

	if ((node->type == em_network_node_data_type_obj) || (node->type == em_network_node_data_type_array)) {
		if ((node->display_info.collapsed == false) && (node->num_children > 0)) {
			return 1;
		}
	}	

	return 0;
}

extern "C" unsigned int can_expand_node(em_network_node_t *node) 
{
    if ((node->type == em_network_node_data_type_obj) || (node->type == em_network_node_data_type_array)) {
        if (node->display_info.collapsed == true) {
            return 1;
        }
    }

    return 0;
}


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

void em_cli_t::print_network_tree_node(em_network_node_t *node, unsigned int *pident)
{
	unsigned int i, ident = 0;
	em_long_string_t fmt = {0};
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
			printf("%s%s:\tfalse\n", fmt, node->key);
			break;

		case em_network_node_data_type_true:
			printf("%s%s:\ttrue\n", fmt, node->key);
			break;

		case em_network_node_data_type_null:
			break;

		case em_network_node_data_type_number:
			printf("%s%s:\t%d\n", fmt, node->key, node->value_int);
			break;

		case em_network_node_data_type_string:
			printf("%s%s:\t%s\n", fmt, node->key, node->value_str);
			break;

		case em_network_node_data_type_array:
			printf("%s%s:", fmt, node->key);
			if ((node->num_children > 0) && ((node->child[0]->type == em_network_node_data_type_array) ||
									(node->child[0]->type == em_network_node_data_type_obj))) {
				printf("\n");
			} else if (node->num_children == 0) {
				//printf("\n");
			}
			break;

		case em_network_node_data_type_obj:
			if (node->key[0] != 0) {
				printf("%s%s\t\n", fmt, node->key);
			}
			break;

		case em_network_node_data_type_raw:
			break;

	}
		
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
		printf("%s\n", value_str);
	} else {

		if (node->type == em_network_node_data_type_array) {
			if (node->num_children == 0) {
				printf("[");
			} else {
				snprintf(value_str, sizeof(value_str), "%s[", fmt);
				printf("%s\n", value_str);
			}
		} else if (node->type == em_network_node_data_type_obj) {
			if (node->num_children == 0) {
				printf("{");
			} else {
				snprintf(value_str, sizeof(value_str), "%s{", fmt);
				printf("%s\n", value_str);
			}
		}

		for (i = 0; i < node->num_children; i++) {
			print_network_tree_node(node->child[i], pident);
		}
		if (node->type == em_network_node_data_type_array) {
			if (node->num_children == 0) {
				printf("]\n");
			} else {
				snprintf(value_str, sizeof(value_str), "%s]", fmt);
				printf("%s\n", value_str);
			}
		} else if (node->type == em_network_node_data_type_obj) {
			if (node->num_children == 0) {
				printf("}\n");
			} else {
				snprintf(value_str, sizeof(value_str), "%s}", fmt);
				printf("%s\n", value_str);
			}

		}
	}

	ident = *pident;
	ident--;
	*pident = ident;
}

void em_cli_t::print_network_tree(em_network_node_t *node)
{
	unsigned int ident = 0;

	print_network_tree_node(node, &ident);	
}

int em_cli_t::get_network_tree_node(cJSON *obj, em_network_node_t *root)
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
		get_network_tree_node(tmp_obj, root->child[root->num_children]);
			
		root->num_children++;

		tmp_obj = tmp_obj->next;	
	}
	
	return root->num_children;
}

em_network_node_t *em_cli_t::get_network_tree(char *buff)
{
	cJSON *obj = NULL;
	em_network_node_t *root;

	if ((obj = cJSON_Parse(buff)) == NULL) {
		return NULL;
	}

	root = (em_network_node_t *)malloc(sizeof(em_network_node_t));
	memset(root, 0, sizeof(em_network_node_t));
	get_network_tree_node(obj, root);

	cJSON_Delete(obj);

	return root;

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

char *em_cli_t::exec(char *in, size_t sz, em_status_string_t out)
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

    snprintf(out, EM_IO_BUFF_SZ, "%s", res);
    delete cli_cmd;

    return out;
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

extern "C" void free_network_tree(void *node)
{
	return g_cli.free_network_tree((em_network_node_t *)node);
}

extern "C" void print_network_tree(em_network_node_t *node)
{
	return g_cli.print_network_tree(node);
}

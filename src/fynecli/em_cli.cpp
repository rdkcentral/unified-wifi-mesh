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
#include "em_cmd_cli.h"
#include "em_cli.h"
#include <readline/readline.h>
#include <readline/history.h>

em_cli_t g_cli;

em_network_node_t *em_cli_t::get_reset_tree(char *platform)
{
	unsigned int len;
    dm_easy_mesh_t dm; 
	em_interface_t *intf;
    //mac_addr_str_t  ctrl_mac, ctrl_al_mac, agent_al_mac;
	em_subdoc_info_t *subdoc;
	em_long_string_t	dbg_str;
	unsigned char buff[EM_IO_BUFF_SZ];

	subdoc = (em_subdoc_info_t *)buff;

	if ((len = em_cmd_exec_t::load_params_file("Reset.json", subdoc->buff)) < 0) {
		return NULL;
	}

    dm.init();
    dm.decode_config(subdoc, "Reset");

	// Prioritize the interface list depending on platform
	if ((intf = dm.get_prioritized_interface(platform)) == NULL) {
		intf = dm.get_interface_by_index(0);
	}

	snprintf(dbg_str, sizeof(em_long_string_t), "Interface Name: %s Media: %d", intf->name, intf->media);	
    g_cli.dump_lib_dbg(dbg_str);
    dm.set_ctrl_al_interface_mac(intf->mac);
    dm.set_ctrl_al_interface_name(intf->name);
	dm.set_controller_id(intf->mac);
	dm.set_controller_intf_media(intf->media);
            
    //dm.print_config();

    dm.encode_config(subdoc, "Reset");

	return em_net_node_t::get_network_tree(subdoc->buff);
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

em_cmd_t& em_cli_t::get_command(char *in, size_t in_len, em_network_node_t *node)
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
                    } else if (strncmp(args[num_args - 1], "3", strlen("3")) == 0) {
                        strncat(cmd->m_param.u.args.fixed_args, "Summary@getCapabilities",
                                strlen("Summary@getCapabilities"));
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

	em_cmd_cli_t::m_client_cmd_spec[idx].m_param.net_node = node;


    return em_cmd_cli_t::m_client_cmd_spec[idx];
}

em_network_node_t *em_cli_t::exec(char *in, size_t sz, em_network_node_t *node)
{
    em_long_string_t cmd;
    char *result;
	em_network_node_t *new_node;
    em_cmd_cli_t *cli_cmd;

    snprintf(cmd, sizeof(cmd),  "%s", in);
	printf("%s:%d: Command: %s\n", __func__, __LINE__, cmd);
    cli_cmd = new em_cmd_cli_t(get_command(cmd, sz, node), m_params.user_data.addr);

    if (cli_cmd->init() != 0) {
		printf("%s:%d: Failed to init command\n", __func__, __LINE__);
		return NULL;
	}

	result = (char *)malloc(EM_MAX_EVENT_DATA_LEN);
	memset(result, 0, EM_MAX_EVENT_DATA_LEN);

    if (cli_cmd->validate() == false) {
        cli_cmd->m_cmd.status_to_string(em_cmd_out_status_invalid_input, result);
    } else {
        if (cli_cmd->execute(result) != 0) {
            cli_cmd->m_cmd.status_to_string(em_cmd_out_status_invalid_input, result);

        }
    }

	cli_cmd->deinit();
    delete cli_cmd;

    new_node = em_net_node_t::get_network_tree(result);	
	free(result);

	return new_node;
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


bool em_cli_t::is_remote_addr_valid()
{
	return m_params.user_data.valid;
}

int em_cli_t::set_remote_addr(unsigned int ip, unsigned int port, bool valid)
{
	m_params.user_data.addr.sin_family = AF_INET;
	m_params.user_data.addr.sin_addr.s_addr = ip;
	m_params.user_data.addr.sin_port = htons(port);
	m_params.user_data.valid = valid;	
	
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

extern "C" em_network_node_t *exec(char *in, size_t in_len, em_network_node_t *node)
{
    return g_cli.exec(in, in_len, node);
}

extern "C" int set_remote_addr(unsigned int ip, unsigned int port, bool valid)
{
    return g_cli.set_remote_addr(ip, port, valid);
}

extern "C" bool is_remote_addr_valid()
{
	return g_cli.is_remote_addr_valid();
}

extern "C" const char *get_first_cmd_str()
{
    return g_cli.get_first_cmd_str();
}

extern "C" const char *get_next_cmd_str(const char *cmd)
{
    return g_cli.get_next_cmd_str(cmd);
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

    if ((node->type == em_network_node_data_type_obj) || (node->type == em_network_node_data_type_array_obj)) {
        if ((node->display_info.collapsed == false) && (node->num_children > 0)) {
            return 1;
        }
    }	

    return 0;
}

extern "C" unsigned int can_expand_node(em_network_node_t *node) 
{
    if ((node->type == em_network_node_data_type_obj) || (node->type == em_network_node_data_type_array_obj)) {
        if (node->display_info.collapsed == true) {
            return 1;
        }
    }

    return 0;
}

extern "C" em_network_node_t *get_reset_tree(char *platform)
{
	return g_cli.get_reset_tree(platform);
}

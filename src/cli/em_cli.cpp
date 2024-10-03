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
const char *em_cli_t::m_prompt = "<<OneWifiMeshCli>>: ";

em_cmd_t& em_cli_t::get_command(char *in, size_t in_len)
{
    unsigned int num_args = 0, idx = 0, i;
    em_cmd_type_t	allowed = em_cmd_type_none;
    char *tmp;
    em_cmd_t	*cmd;
    em_long_string_t args[EM_CLI_AMX_ARGS];

    in[strlen(in) - 1] = 0; // get rid of line feed
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

    if (num_args != cmd->m_param.num_args) {
        return em_cmd_cli_t::m_client_cmd_spec[em_cmd_type_none];;
    }

    cmd->m_param.num_args = num_args;
    for (i = 0; i < num_args; i++) {
        snprintf(cmd->m_param.args[i], sizeof(cmd->m_param.args[i]), "%s", args[i]);
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

int em_cli_t::start()
{
    char *line = NULL;
    em_status_string_t output;

    while(1) {
        //show_prompt();
        line = readline(m_prompt);
        if (line == NULL || strcmp(line, "exit") == 0) {
            free(line);
            break;
        }

        if (strcmp(line, "history") == 0) {
            HIST_ENTRY **hist_list = history_list();
            if (hist_list) {
                for (int i = 0; hist_list[i]; i++) {
                    printf("%d. %s\n", i + 1, hist_list[i]->line);
                }
            }
        } else {
            if (*line) {
                add_history(line);
            }

            printf("%s\n", exec(line, strlen(line), output));        
        }

        free(line);
    }
    return 0;
}

int em_cli_t::init()
{
    return 0;
}

void em_cli_t::show_prompt()
{
    printf("%s", m_prompt);
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

int main(int argc, const char *argv[])
{
    if (g_cli.init() == 0) {
        g_cli.start();
    }

    return 0;
}


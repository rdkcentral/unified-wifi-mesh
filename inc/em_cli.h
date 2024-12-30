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
    em_cmd_t& get_command(char *in, size_t in_len, em_network_node_t *node = NULL);
    em_long_string_t	m_lib_dbg_file_name;

public:

	em_cli_params_t	m_params;

    em_network_node_t *exec(char *in, size_t in_len, em_network_node_t *node);
    int init(em_cli_params_t *params);
	const char *get_first_cmd_str();
	const char *get_next_cmd_str(const char *cmd);
	
    void init_lib_dbg(char *file_name);
    void dump_lib_dbg(char *str);

    em_cli_t();
    ~em_cli_t();
};

em_cli_t *get_cli();

#endif


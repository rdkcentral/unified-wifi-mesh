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

#ifndef EM_CMD_CLI_H
#define EM_CMD_CLI_H

#include "em_cmd_exec.h"
#include "dm_easy_mesh.h"

class em_cli_t;
extern em_cli_t g_cli;

class em_cmd_cli_t : public em_cmd_exec_t {

    em_cli_t& m_cli = g_cli;
public:
    static em_cmd_t m_client_cmd_spec[];
public:
    int     get_edited_node(em_network_node_t *node, const char *header, char *buff);
    int execute(em_long_string_t result);
    int update_platform_defaults(em_subdoc_info_t *info, em_cmd_params_t *param, em_cmd_type_t cmd_type);

    em_cmd_cli_t(em_cmd_t& obj);
	~em_cmd_cli_t();
};

#endif

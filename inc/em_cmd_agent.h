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

#ifndef EM_CMD_AGENT_H
#define EM_CMD_AGENT_H

#include "em_cmd_exec.h"

class em_agent_t;
extern em_agent_t g_agent;

class em_cmd_agent_t : public em_cmd_exec_t {
    em_agent_t& m_agent = g_agent;
    int m_dsock;
public:
    static em_cmd_t m_client_cmd_spec[];
public:
    int execute(em_long_string_t result);
    int send_result(em_cmd_out_status_t status);

    static em_event_t *create_event(char *buff);
    
    em_cmd_agent_t(em_cmd_type_t type);
    em_cmd_agent_t(em_cmd_t& obj);
    em_cmd_agent_t();
};

#endif

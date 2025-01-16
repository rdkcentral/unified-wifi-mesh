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

#ifndef EM_CMD_CTRL_H
#define EM_CMD_CTRL_H

#include "em_cmd_exec.h"

extern em_ctrl_t g_ctrl;

class em_cmd_ctrl_t : public em_cmd_exec_t { 
    em_ctrl_t& m_ctrl = g_ctrl;
    int m_dsock;
public:
    int execute(char *result);
    int send_result(em_cmd_out_status_t status);

    em_cmd_ctrl_t();
};

#endif

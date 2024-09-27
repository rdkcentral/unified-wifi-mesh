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

#ifndef EM_ORCH_CTRL_H
#define EM_ORCH_CTRL_H

#include "em_orch.h"

class em_orch_ctrl_t : public em_orch_t {

public:
    unsigned int build_candidates(em_cmd_t *cmd);
    bool    pre_process_orch_op(em_cmd_t *pcmd);
    bool    is_em_ready_for_orch_exec(em_cmd_t *pcmd, em_t *em);
    bool    is_em_ready_for_orch_fini(em_cmd_t *pcmd, em_t *em);
    void    orch_transient(em_cmd_t *pcmd, em_t *em);

public:
    em_orch_ctrl_t(em_mgr_t *mgr);
};

#endif

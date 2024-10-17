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

#ifndef EM_ORCH_H
#define EM_ORCH_H

#include "em_base.h"
#include "em.h"

class em_cmd_t;
class em_mgr_t;

class em_orch_t {

public:
    em_mgr_t    *m_mgr;
    queue_t *m_pending;
    queue_t *m_active;
    hash_map_t  *m_cmd_map;

public:
    em_orch_state_t get_state(em_cmd_t *cmd);
    void handle_timeout();

    unsigned int submit_commands(em_cmd_t *pcmd[], unsigned int num);
    virtual unsigned int build_candidates(em_cmd_t *cmd) = 0;
    bool eligible_for_active(em_cmd_t *pcmd);

    virtual bool    pre_process_orch_op(em_cmd_t *pcmd) = 0;
    virtual void    pre_process_cancel(em_cmd_t *pcmd, em_t *em) = 0;
    virtual bool    is_em_ready_for_orch_exec(em_cmd_t *pcmd, em_t *em) = 0;
    virtual bool    is_em_ready_for_orch_fini(em_cmd_t *pcmd, em_t *em) = 0;
    virtual void    orch_transient(em_cmd_t *pcmd, em_t *em) = 0;
    bool submit_command(em_cmd_t *pcmd);
    void destroy_command(em_cmd_t *pcmd);
    void cancel_command(em_cmd_type_t type);
    void push_stats(em_cmd_t *pcmd);
    void pop_stats(em_cmd_t *pcmd);
    void update_stats(em_cmd_t *pcmd);
    bool is_cmd_type_in_progress(em_bus_event_type_t type);
    bool orchestrate(em_cmd_t *pcmd, em_t *em);

    em_orch_t();
    ~em_orch_t();
};

#endif

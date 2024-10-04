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

#ifndef EM_CMD_EXEC_H
#define EM_CMD_EXEC_H

#include "em_base.h"
#include "em_cmd.h"


class em_cmd_exec_t {
    static const char *m_sock_path;

    pthread_cond_t  m_cond;
    pthread_mutex_t m_lock;

public:
    em_cmd_t m_cmd;

public:
    //char *get_result() { return m_cmd.get_result(); }
    bool validate() { return m_cmd.validate(); }
    em_event_t *get_event() { return m_cmd.get_event(); }
    em_cmd_t *get_cmd() { return &m_cmd; }
    em_cmd_params_t *get_param() { return m_cmd.get_param(); }
    em_cmd_type_t get_type() { return m_cmd.m_type; }
    const char *get_path() { return m_sock_path; }

    void copy_bus_event(em_bus_event_t *evt) { m_cmd.copy_bus_event(evt); }

    void init();
    static int send_cmd(em_service_type_t to_svc, unsigned char *in, unsigned int in_len, char *out = NULL, unsigned int out_len = 0);
    static int execute(em_cmd_type_t type, em_service_type_t to_svc, unsigned char *in, unsigned int in_len);

    virtual int execute(em_long_string_t result) = 0;
    void release_wait();
    void wait(struct timespec *time_to_wait);

public:
    em_cmd_exec_t();
    ~em_cmd_exec_t();
};

#endif

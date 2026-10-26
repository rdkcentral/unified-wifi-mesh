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

#ifndef OPTIMIZER_H
#define OPTIMIZER_H

#include "em_base.h"
#include "optimizer_event.h"
#include "de_services.h"
#include "de_network.h"
#include "de_devices.h"

class optimizer_t {

public:
    bool m_exit;
    pthread_cond_t  m_cond;
    pthread_mutex_t m_lock;
    queue_t *m_queue;
    optimizer_type_t    m_optimizer_type;
    de_network_t    *m_de_network; 
    de_services_t   *m_de_services;
    de_devices_t   *m_de_devices;

    virtual int init_optimizer_interface(const char *url) { printf("Default optimizer does not connect to cloud\n"); return -1; }
    virtual void deinit_optimizer_interface() { printf("Default optimizer does not connect to cloud\n"); }
    virtual void process_event(optimizer_event_t *ev) {};
    virtual void process_timeout(char *time_str) { printf("%s: Timeout process\n", time_str); }

public:

    int init();
    void deinit();
    int run(optimizer_type_t type);
    void wait() { pthread_mutex_lock(&m_lock); pthread_cond_wait(&m_cond, &m_lock); pthread_mutex_unlock(&m_lock); }
    void signal() { pthread_mutex_lock(&m_lock); pthread_cond_signal(&m_cond); pthread_mutex_unlock(&m_lock); }
    void push_to_queue(optimizer_event_t *ev) { pthread_mutex_lock(&m_lock); queue_push(m_queue, ev); pthread_cond_signal(&m_cond); pthread_mutex_unlock(&m_lock); }

    bool should_exit() { return m_exit; }
    queue_t *get_queue() { return m_queue; }
    pthread_mutex_t* get_lock() { return &m_lock; }

    void set_optimizer_type(optimizer_type_t type) { m_optimizer_type = type; }

    optimizer_type_t get_operator_type() { return m_de_services->get_operator_type(); }
    char *get_url() { return m_de_services->get_url(); }

    void wait_for_de_change();
    
    optimizer_t();
    ~optimizer_t(); 
};

#endif

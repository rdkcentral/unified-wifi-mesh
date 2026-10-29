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

#ifndef DE_TESTER_H
#define DE_TESTER_H

#include "em_base.h"
#include "de_network.h"
#include "de_reader.h"
#include "optimizer_event.h"
#include "collection.h"

class de_tester_t {

    de_reader_t *m_rd;

    bool m_exit;
    pthread_cond_t  m_cond;
    pthread_mutex_t m_lock;
    queue_t *m_queue;

    de_network_t *m_de_network;    
    
public:
    int init();
    void deinit();

    void update();

    bool should_exit() { return m_exit; }

    unsigned int queue_count() { return ::queue_count(m_queue); }
    optimizer_event_t *queue_pop() { optimizer_event_t *ev = static_cast<optimizer_event_t *>(::queue_pop(m_queue)); return ev; }
    int wait();
    void signal() { pthread_mutex_lock(&m_lock); pthread_cond_signal(&m_cond); pthread_mutex_unlock(&m_lock); }
    void push_to_queue(optimizer_event_t *ev) { pthread_mutex_lock(&m_lock); queue_push(m_queue, ev); pthread_cond_signal(&m_cond); pthread_mutex_unlock(&m_lock); }
    void lock() { pthread_mutex_lock(&m_lock); }
    void unlock() { pthread_mutex_unlock(&m_lock); }

    void process_event(optimizer_event_t *ev);

    de_tester_t(de_reader_t *rd);
    ~de_tester_t();
};

#endif

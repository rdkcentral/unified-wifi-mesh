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

#ifndef OPTIMIZER_EVENT_H
#define OPTIMIZER_EVENT_H

typedef enum {
    optimizer_event_type_subscribed,
    optimizer_event_type_de_change,
    optimizer_event_type_get_topology,
    optimizer_event_type_get_de,
    optimizer_event_type_max
} optimizer_event_type_t;

class optimizer_event_t {

    bool m_copy;
    optimizer_event_type_t  m_type;
    void *m_data;
    unsigned int m_len; 

public:
    optimizer_event_type_t get_type() { return m_type; }
    void *get_data() { return m_data; }
    unsigned int get_len() { return m_len; }
    optimizer_event_t(optimizer_event_type_t type, void *data, unsigned int len, bool zero_cp = true);
    ~optimizer_event_t(); 
};

#endif

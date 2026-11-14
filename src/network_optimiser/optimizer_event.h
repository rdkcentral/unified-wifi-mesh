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

#include <stddef.h>
#include <cjson/cJSON.h>

typedef enum {
    optimizer_event_type_hello,
    optimizer_event_type_subscribed,
    optimizer_event_type_de_change,
    optimizer_event_type_notification_max = 16,
    optimizer_event_type_get_topology,
    optimizer_event_type_get_de,
    optimizer_event_type_set_ssid,
    optimizer_event_type_nbr_wifi_diag,
    optimizer_event_type_full_scan,
    optimizer_event_type_channel_scan,
    optimizer_event_type_unknown,
    optimizer_event_type_max
} optimizer_event_type_t;

typedef struct {
    optimizer_event_type_t  type;
    const char *string;
} optimizer_events_map_t;

typedef struct {
    unsigned char *data;
    size_t size;
} ev_buffer_t;

class optimizer_event_t {
public:
    ev_buffer_t   m_buff;
    bool m_copy;
    optimizer_event_type_t  m_type;

public:
    optimizer_event_type_t get_type() { return m_type; }
    void *get_data() { return m_buff.data; }
    unsigned int get_len() { return m_buff.size; }
    static const char *optimizer_event_type_2_string(optimizer_event_type_t type);
    static optimizer_event_type_t optimizer_string_2_event_type(const char *string, size_t length);

    bool is_notification_event(optimizer_event_type_t type) { return (type < optimizer_event_type_notification_max) ? true:false; }

    void init(optimizer_event_type_t type, const char *data, const char *status);

    optimizer_event_t();
    optimizer_event_t(const char *data);
    optimizer_event_t(optimizer_event_type_t type, const cJSON *data, const char *status = NULL);
    optimizer_event_t(optimizer_event_type_t type, const char *data = NULL, const char *status = NULL);
    optimizer_event_t(optimizer_event_type_t type, void *data, unsigned int len, bool zero_cp = true);
    ~optimizer_event_t(); 
};

#endif

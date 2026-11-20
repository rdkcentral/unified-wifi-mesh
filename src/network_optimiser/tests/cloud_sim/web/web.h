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

#ifndef WEB_H
#define WEB_H

#include "common_defs.h"
#include "optimizer_event.h"
#include "collection.h"

typedef enum {
    web_data_extn_type_js,
    web_data_extn_type_ico,
    web_data_extn_type_jpg,
    web_data_extn_type_png,
    web_data_extn_type_php,
    web_data_extn_type_html,
    web_data_extn_type_json,
    web_data_extn_type_css,
    web_data_extn_type_plain,
    web_data_extn_type_none
} web_data_extn_type_t;

class web_t {
    bool m_exit;
    char m_http_header[MAX_HTTP_HDR_SZ];
    char m_head[PATH_NAME_SZ];
    struct sockaddr_in m_address;
    int m_server_fd;
    pthread_mutex_t m_lock;
    queue_t *m_events;
    
public:
    int init(const char *path);
    void deinit();
    
    int start();
    void stop();
    
    int run();
    int server();
    int server(int sock);
    
    void handle_get(int sock, const char *action_string);
    void handle_post(int sock, const char *action_string, char *buff);

    virtual const char *device_request(optimizer_event_t *req, optimizer_event_t *rsp) { return ""; }
    void async_event(optimizer_event_t *ev);

    unsigned int events_count() { pthread_mutex_lock(&m_lock); queue_count(m_events); pthread_mutex_unlock(&m_lock); }
    void push_event(optimizer_event_t *ev) { pthread_mutex_lock(&m_lock); queue_push(m_events, ev); pthread_mutex_unlock(&m_lock); }
    optimizer_event_t *pop_event() { optimizer_event_t *ev; pthread_mutex_lock(&m_lock); ev = (optimizer_event_t *)queue_pop(m_events); pthread_mutex_unlock(&m_lock); return ev; }
    
    char* parse(char line[], const char symbol[]);
    char* parse_method(char line[], const char symbol[]);
    char* find_value(char *buff, const char *name, char *value);
    int send_message(int fd, web_data_extn_type_t data_type, bool file, const char *data);
    
    web_data_extn_type_t get_file_extension(const char *file_name);
    optimizer_event_type_t get_event_type(const char *action);
    
public:
    web_t();
	~web_t();
};

extern void push_optimimizer_event(optimizer_event_t *evt);

#endif

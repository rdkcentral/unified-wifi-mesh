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

#ifndef XMIDT_OPTIMIZER_SERVER_H
#define XMIDT_OPTIMIZER_SERVER_H

#include "em_base.h"
#include "web.h"
#include <pthread.h>

class xmidt_optimizer_server_t: public web_t {

    pthread_t m_id;
    bool m_listener_started;
    unsigned short m_port;
    bool m_exit;

public:
    int init_optimizer_interface(const char *url);
    void deinit_optimizer_interface();
    int register_webhook(const char *argus_url, const char *webhook_url);

    const char *device_request(optimizer_event_t *req, optimizer_event_t *rsp);

    static size_t append_response(void *contents, size_t size, size_t count, void *user_data);
    int read_http_request(int client, char **request_out);
    static void *listener(void *arg);
    void listener();
    int send_device_request(optimizer_event_t *request, optimizer_event_t *response);

    xmidt_optimizer_server_t();
    ~xmidt_optimizer_server_t(); 
};

#endif

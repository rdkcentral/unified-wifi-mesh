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

#ifndef XMIDT_OPTIMIZER_CLIENT_H
#define XMIDT_OPTIMIZER_CLIENT_H

#include "optimizer.h"
#include "xmidt_optimizer.h"

extern "C" {
#include "libparodus.h"
}

#include <pthread.h>

#define DEVICE_ID "mac:112233445566"
#define SERVICE_NAME "xmidt-c-demo"
#define CONTENT_TYPE_JSON "application/json"

class xmidt_optimizer_client_t: public xmidt_optimizer_t {

    libpd_instance_t m_instance;
    pthread_t    m_tid;
    bool m_exit;

    int init_optimizer_interface(const char *url);
    void deinit_optimizer_interface();

    int reply_to_request(const wrp_msg_t *request);
    int send_event(optimizer_event_type_t type);

    static void *listener(void *arg);
    void listener();

public:

    xmidt_optimizer_client_t();
    ~xmidt_optimizer_client_t(); 
};

#endif

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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include "bus.h"
#include "bus_common.h"
#include "optimizer.h"
#include "comcast_optimizer_xmidt.h"
#include "util.h"

int comcast_optimizer_xmidt_t::init_optimizer_interface(const char *url)
{
    libpd_cfg_t cfg;
    int rc;
    wrp_msg_t *msg;

    printf("%s:%d: url: %s\n", __func__, __LINE__, url);

    memset(&cfg, 0, sizeof(libpd_cfg_t));
   
    cfg.service_name = "comcast optimizer";
    cfg.parodus_url = url;
    cfg.keepalive_timeout_secs = 10000;
    
    // Initialize connection to the local parodus daemon
    if ((rc = libparodus_init(&m_instance, &cfg)) != 0) {
        printf("%s:%d: Failed to initialize libparodus with service: %s and url: %s error code: %d\n", 
            __func__, __LINE__, cfg.service_name, cfg.parodus_url, rc);
        return -1;
    }

    while (should_exit() == false) {
        switch (rc = libparodus_receive(m_instance, &msg, 1000)) {
            case 0:
                break;

            case 1:
                continue;
                break;

            default:
                printf("%s:%d: receiver cloded\n", __func__, __LINE__);
        }
    }
    
    return 0;
}

void comcast_optimizer_xmidt_t::deinit_optimizer_interface()
{
    printf("%s:%d: Enter\n", __func__, __LINE__);

    libparodus_close_receiver(m_instance);
    libparodus_shutdown(&m_instance);
}

comcast_optimizer_xmidt_t::comcast_optimizer_xmidt_t()
{
    set_optimizer_type(optimizer_type_comcast);

}

comcast_optimizer_xmidt_t::~comcast_optimizer_xmidt_t()
{

}

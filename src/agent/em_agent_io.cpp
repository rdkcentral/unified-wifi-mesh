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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "em_agent.h"
#include "em_cmd_agent.h"
#include "util.h"


bool em_agent_t::agent_input(void *data)
{
    em_event_t *evt; 
    em_bus_event_t *inp;
    bool ret = true;
    em_bus_event_t *bevt;

    inp = &((em_event_t *)data)->u.bevt;

    if ((inp->type == em_bus_event_type_dev_init) || (inp->type == em_bus_event_type_sta_list) || (inp->type == em_bus_event_type_onewifi_cb) || (inp->type == em_bus_event_type_m2ctrl_configuration) || (inp->type == em_bus_event_type_cfg_renew)) {
        evt = (em_event_t *)malloc(sizeof(em_event_t));
        evt->type = em_event_type_bus;
        bevt = &evt->u.bevt;
        bevt->type = inp->type;
        memcpy(&bevt->u.raw_buff, inp->u.raw_buff, sizeof(inp->u.raw_buff));
    } else {
        evt = em_cmd_agent_t::create_event((char *)inp->u.subdoc.buff);
    }
    if (evt != NULL) {
        push_to_queue(evt);
    } else {
        if (strncmp(m_data_model_path, "sim", strlen("sim")) == 0) {
            ret = false;
        }
    }
    return ret;
}

bool em_agent_t::agent_output(void *data)
{
    // send configuration to OneWifi after translating
    return true;
}

void em_agent_t::io(void *data, bool input)
{
    em_long_string_t result;

    if (input == true) {
        m_agent_cmd->execute(result);   
    } else {
        agent_output(data);
    }
}


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

void em_agent_t::io_add_node(em_interface_t *ruid)
{
    em_event_t *evt;
    em_node_event_t *nevt;
    unsigned int i;
    bool found_match = false;
    webconfig_subdoc_decoded_data_t *decoded;

    evt = (em_event_t *)malloc(sizeof(em_event_t));
    evt->type = em_event_type_node;

    nevt = &evt->u.nevt;
    nevt->type = em_node_event_type_add;

    memcpy(&nevt->u.ruid, ruid, sizeof(em_interface_t));

    push_to_queue(evt);
}

void em_agent_t::io_del_node(em_interface_t *ruid)
{
    em_event_t *evt;
    em_node_event_t *nevt;

    evt = (em_event_t *)malloc(sizeof(em_event_t));
    evt->type = em_event_type_node;

    nevt = &evt->u.nevt;
    nevt->type = em_node_event_type_del;

    memcpy(&nevt->u.ruid, ruid, sizeof(em_interface_t));

    push_to_queue(evt);

}

bool em_agent_t::agent_input(void *data)
{
    em_event_t *evt; 
    em_bus_event_t *inp;
    bool ret = true;

    inp = &((em_event_t *)data)->u.bevt;

    evt = em_cmd_agent_t::create_event((char *)inp->u.subdoc.buff);
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
#if 0
void em_agent_t::rbus_listener_agent(rbusHandle_t handle, rbusEvent_t const* event,rbusEventSubscription_t* subscription)
{
    em_agent_t *ptr;
    rbusValue_t value;
    char *msg;
    int len = 0;

    ptr = static_cast<em_agent_t*> (subscription->userData);

    if(!event || (strcmp(subscription->eventName, WIFI_EASYMESH_NOTIFICATION) != 0)) {
        //em_util_info_print(EM_MGR, "%s:%d: Invalid Event Received %s",__func__, __LINE__, subscription->eventName);
        return;
    } else {
        //em_util_info_print(EM_MGR, "%s:%d: Event Received %s",__func__, __LINE__, subscription->eventName);
    }

    value = rbusObject_GetValue(event->data, NULL);
    if (!value) {
        // em_util_info_print(EM_MGR, "%s:%d: Invalid value in event:%s",__func__, __LINE__, subscription->eventName);
        return;
    }

    msg = (char *)rbusValue_GetString(value, &len);
    if (msg == NULL) {
        // em_util_info_print(EM_MGR,"%s:%d rbus msg string is null! ", __func__,__LINE__);
        return;
    }
    //em_util_info_print(EM_MGR,"%s:%d msg is %s\n", __func__,__LINE__,msg);

    //To modify as per new io function
#if 0 
    if(msg)
        ptr->io(msg);
#endif

}
#endif

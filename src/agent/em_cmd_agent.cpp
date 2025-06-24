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
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "em_agent.h"
#include "em_cmd_agent.h"

em_cmd_t em_cmd_agent_t::m_client_cmd_spec[] = {
    em_cmd_t(em_cmd_type_none,em_cmd_params_t{0, {"", "", "", "", ""}, "none"}),
    em_cmd_t(em_cmd_type_dev_init,em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:Network"}),
    em_cmd_t(em_cmd_type_cfg_renew, em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:Renew"}),
    em_cmd_t(em_cmd_type_vap_config,em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:BssConfig"}),
    em_cmd_t(em_cmd_type_sta_list,em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:StaList"}),
    em_cmd_t(em_cmd_type_ap_cap_query,em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:CapReport"}),
    em_cmd_t(em_cmd_type_max,em_cmd_params_t{0, {"", "", "", "", ""}, "max"}),
};

int em_cmd_agent_t::execute(em_long_string_t result)
{
    int ret, lsock, dsock;
    unsigned int sz = EM_MAX_EVENT_DATA_LEN, i, offset, iter;
    unsigned char *tmp;

    m_cmd.reset();

	if ((lsock = get_listener_socket(em_service_type_agent)) < 0) {
        printf("%s:%d: listener socket get failed, service:%d\n", __func__, __LINE__, get_svc());
        return -1;
    }

    if ((ret = listen(lsock, 20)) == -1) {
        printf("%s:%d: listen error on socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }
    while (1) {

        printf("%s:%d: Waiting for client connection\n", __func__, __LINE__);
        if ((m_dsock = accept(lsock, NULL, NULL)) == -1) {
            printf("%s:%d: listen error on socket, err:%d\n", __func__, __LINE__, errno);
            continue;
        }

        setsockopt(m_dsock, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)); // Send buffer EM_MAX_EVENT_DATA_LEN
        setsockopt(m_dsock, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)); // Receive buffer EM_MAX_EVENT_DATA_LEN

        printf("%s:%d: Connection accepted from client\n", __func__, __LINE__);

        tmp = (unsigned char *)get_event();

        if ((ret = recv(m_dsock, tmp, sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN, 0)) <= 0) {
            printf("%s:%d: listen error on socket, err:%d\n", __func__, __LINE__, errno);
            break;
        }

        switch (get_event()->type) {
            case em_event_type_bus:
				//assert(0);
                m_agent.io_process(get_event());
                break;

            default:
                break;
        }

        m_cmd.reset();

    }

	close_listener_socket(lsock, get_svc());

    return 0;
}

int em_cmd_agent_t::send_result(em_cmd_out_status_t status)
{
    int ret;
    em_status_string_t str;
    unsigned char *tmp;

    tmp = (unsigned char *)m_cmd.status_to_string(status, str);

    if ((ret = send(m_dsock, tmp, sizeof(em_status_string_t), 0)) <= 0) {
        printf("%s:%d: write error on socket, err:%d\n", __func__, __LINE__, errno);
    }

    close(m_dsock);

    return 0;
}

em_event_t *em_cmd_agent_t::create_event(char *buff)
{
    // here is the entry point of RBUS subdocuments
    em_cmd_type_t   type = em_cmd_type_none;
    cJSON *obj, *child_obj;
    char *tmp;
    em_cmd_t    *cmd;
    unsigned int idx;
    em_event_t *evt;
    em_bus_event_t *bevt;

    if ((obj = cJSON_Parse(buff)) == NULL) {
        printf("%s:%d: Failed to parse JSON object\n", __func__, __LINE__);
        return NULL;
    }

    idx = 0; type = em_cmd_agent_t::m_client_cmd_spec[idx].get_type();
    cmd = &em_cmd_agent_t::m_client_cmd_spec[idx];
    while (type != em_cmd_type_max) {
        //cmd = &em_cmd_agent_t::m_client_cmd_spec[idx];

        if (cmd->get_svc() != em_service_type_agent) {
            idx++;
            cmd = &em_cmd_agent_t::m_client_cmd_spec[idx];
            type = em_cmd_agent_t::m_client_cmd_spec[idx].get_type(); continue;
        }

        tmp = (char *)cmd->get_arg();

        if ((child_obj = cJSON_GetObjectItem(obj, tmp)) != NULL) {
            break;
        }

        idx++;
        type = em_cmd_agent_t::m_client_cmd_spec[idx].get_type();
        cmd = &em_cmd_agent_t::m_client_cmd_spec[idx];
    }

    cJSON_Delete(obj);

    if ((type == em_cmd_type_none) || (type >= em_cmd_type_max)) {
        printf("%s:%d: type invalid=%d\n", __func__, __LINE__,type);
        return NULL;
    }

    evt = (em_event_t *)malloc(sizeof(em_event_t));
    evt->type = em_event_type_bus;
    bevt = &evt->u.bevt;

    switch (type) {
        case em_cmd_type_dev_init:  
            bevt->type = em_bus_event_type_dev_init;
            break;

        case em_cmd_type_sta_list:
            bevt->type = em_bus_event_type_sta_list;
            break;

        case em_cmd_type_ap_cap_query:
            bevt->type = em_bus_event_type_ap_cap_query;
            break;

	    case em_cmd_type_client_cap_query:
	        bevt->type = em_bus_event_type_client_cap_query;
	        break;

        case em_cmd_type_cfg_renew:
            bevt->type = em_bus_event_type_cfg_renew;
            break;
       
         default:
            break;
    }

    memcpy(&bevt->params, &cmd->m_param, sizeof(em_cmd_params_t));
    memcpy(&bevt->u.subdoc.buff, buff, EM_MAX_EVENT_DATA_LEN);
    bevt->data_len = strlen(buff) + 1;   
    return evt;
}

em_cmd_agent_t::em_cmd_agent_t(em_cmd_t& obj)
{
    memcpy(&m_cmd.m_param, &obj.m_param, sizeof(em_cmd_params_t));
}

em_cmd_agent_t::em_cmd_agent_t(em_cmd_type_t type)
{
    memcpy(&m_cmd.m_param, &em_cmd_agent_t::m_client_cmd_spec[type].m_param, sizeof(em_cmd_params_t));
}

em_cmd_agent_t::em_cmd_agent_t()
{

}

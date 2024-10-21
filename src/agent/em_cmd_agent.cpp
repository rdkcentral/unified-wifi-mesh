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
    em_cmd_t(em_cmd_type_radio_config,em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:RadioConfig"}),
    em_cmd_t(em_cmd_type_vap_config,em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:BssConfig"}),
    em_cmd_t(em_cmd_type_sta_list,em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:StaList"}),
    em_cmd_t(em_cmd_type_ap_cap_query,em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:CapReport"}),
    em_cmd_t(em_cmd_type_client_cap_query,em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:ClientCapReport"}),
    em_cmd_t(em_cmd_type_onewifi_private_subdoc,em_cmd_params_t{1, {"", "", "", "", ""},"wfa-dataelements:dm_cache"}),
    em_cmd_t(em_cmd_type_max,em_cmd_params_t{0, {"", "", "", "", ""}, "max"}),
};

int em_cmd_agent_t::execute(em_long_string_t result)
{
    struct sockaddr_un addr;
    int ret, lsock, dsock;
    unsigned int sz = sizeof(em_event_t), i, offset, iter;
    unsigned char *tmp;
    bool wait = false;

    m_cmd.reset();

    unlink(get_path());

    if ((lsock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        printf("%s:%d: error opening socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", get_path());
    //strcpy(addr.sun_path, m_sock_path);

    if ((ret = bind(lsock, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un))) == -1) {
        printf("%s:%d: bind error on socket: %d, err:%d\n", __func__, __LINE__, lsock, errno);
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

        setsockopt(m_dsock, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)); // Send buffer 1K
        setsockopt(m_dsock, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)); // Receive buffer 1K

        printf("%s:%d: Connection accepted from client\n", __func__, __LINE__);

        tmp = (unsigned char *)get_event();
        offset = 0;
        iter = ((sizeof(em_event_t)%EM_IO_BUFF_SZ) == 0) ? sizeof(em_event_t)/EM_IO_BUFF_SZ:(sizeof(em_event_t)/EM_IO_BUFF_SZ + 1);
        sz = EM_IO_BUFF_SZ;

        //printf("%s:%d: Iterations: %d\n", __func__, __LINE__, iter);

        for (i = 0; i < iter; i++) {
            if ((ret = recv(m_dsock, tmp + offset, sz, 0)) <= 0) {
                printf("%s:%d: listen error on socket, err:%d\n", __func__, __LINE__, errno);
                break;
            }

            offset += ret;
            sz = ((sizeof(em_event_t) - offset) < EM_IO_BUFF_SZ) ? sizeof(em_event_t) - offset:EM_IO_BUFF_SZ;

            //printf("%s:%d Received Bytes: %d, Size to receive: %d\n", __func__, __LINE__, offset, sz);
        }

        printf("%s:%d: Read bytes: %d Type:%d, Subtype: %d Size: %d Buff: %s\n", __func__, __LINE__, ret,
                get_event()->type, get_event()->u.bevt.type, get_event()->u.bevt.u.subdoc.sz, get_event()->u.bevt.u.subdoc.buff);

        switch (get_event()->type) {
            case em_event_type_bus:
                wait = m_agent.agent_input(get_event());
                break;

            default:
                wait = false;
                break;
        }

        if (wait == false) {
            send_result(em_cmd_out_status_other);
        }

        m_cmd.reset();

    }

    close(lsock);
    unlink(get_path());

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
       
        case em_cmd_type_onewifi_private_subdoc:
			bevt->type = em_bus_event_type_onewifi_private_subdoc;
			break;

         default:
            break;
    }

    memcpy(&bevt->params, &cmd->m_param, sizeof(em_cmd_params_t));
    memcpy(&bevt->u.subdoc.buff, buff, EM_SUBDOC_BUFF_SZ-1);
    bevt->u.subdoc.sz = strlen(buff);   
    printf("%s:%d: Parse JSON btype=%d priv=%d\n", __func__, __LINE__,bevt->type,em_bus_event_type_onewifi_private_subdoc);
    return evt;
}

em_event_t *em_cmd_agent_t::create_raw_event(char *buff, em_bus_event_type_t type)

{
    printf("entering create_raw_event\n");
    em_cmd_type_t   cmd_type = em_cmd_type_none;
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
    cJSON_Delete(obj);
    evt = (em_event_t *)malloc(sizeof(em_event_t));
    evt->type = em_event_type_bus;
    bevt = &evt->u.bevt;

    if(type == em_bus_event_type_dev_init)
    {
        cmd = &em_cmd_agent_t::m_client_cmd_spec[1];
    }
    else if(type == em_bus_event_type_sta_list)
    {
        cmd = &em_cmd_agent_t::m_client_cmd_spec[5];
    }

    bevt->type = type;

    memcpy(&bevt->u.raw_buff, buff, strlen(buff));
    bevt->u.subdoc.sz = strlen(buff);

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
    snprintf(m_sock_path, sizeof(m_sock_path), "%s_%s", EM_PATH_PREFIX, EM_AGENT_PATH);
}

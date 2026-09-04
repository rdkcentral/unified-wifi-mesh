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
#include "em_agent.h"
#include "em_cmd_agent.h"

int em_cmd_agent_t::execute(em_long_string_t result)
{
    int ret, lsock;
    unsigned int sz = EM_MAX_EVENT_DATA_LEN;
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

        tmp = reinterpret_cast<unsigned char *>(get_event());

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

    tmp = reinterpret_cast<unsigned char *>(m_cmd.status_to_string(status, str));

    if ((ret = send(m_dsock, tmp, sizeof(em_status_string_t), 0)) <= 0) {
        printf("%s:%d: write error on socket, err:%d\n", __func__, __LINE__, errno);
    }

    close(m_dsock);

    return 0;
}

em_cmd_agent_t::em_cmd_agent_t(em_cmd_t& obj) : m_dsock(-1)
{
    memcpy(&m_cmd.m_param, &obj.m_param, sizeof(em_cmd_params_t));
}

em_cmd_agent_t::em_cmd_agent_t() : m_dsock(-1)
{

}

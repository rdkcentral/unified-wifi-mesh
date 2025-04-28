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
#include "em_cmd_ctrl.h"

int em_cmd_ctrl_t::execute(char *result)
{
    struct sockaddr_un addr;
    int lsock;
    ssize_t ret;
    unsigned int sz = sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN;
    unsigned char *tmp;
    bool wait = false;

    m_cmd.reset();

    unlink(get_path());

    printf("%s:%d: Controller communication path: %s\n", __func__, __LINE__, get_path());

    if ((lsock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        printf("%s:%d: error opening socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%.*s", static_cast<int>(sizeof(addr.sun_path) - 1), get_path());

    if ((ret = bind(lsock, reinterpret_cast<const struct sockaddr *> (&addr), sizeof(struct sockaddr_un))) == -1) {
        printf("%s:%d: bind error on socket: %d, err:%d\n", __func__, __LINE__, lsock, errno);
        return -1;
    }

    if ((ret = listen(lsock, 20)) == -1) {
        printf("%s:%d: listen error on socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    while (1) {

        //printf("%s:%d: Waiting for client connection\n", __func__, __LINE__);
        if ((m_dsock = accept(lsock, NULL, NULL)) == -1) {
            printf("%s:%d: listen error on socket, err:%d\n", __func__, __LINE__, errno);
            continue;
        }

        setsockopt(m_dsock, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)); // Send buffer EM_MAX_EVENT_DATA_LEN
        setsockopt(m_dsock, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)); // Receive buffer EM_MAX_EVENT_DATA_LEN

        //printf("%s:%d: Connection accepted from client\n", __func__, __LINE__);

        tmp = reinterpret_cast<unsigned char *> (get_event());

		if ((ret = recv(m_dsock, tmp, sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN, 0)) <= 0) {
			printf("%s:%d: listen error on socket, err:%d\n", __func__, __LINE__, errno);
		}

        //printf("%s:%d: Read bytes: %d Size: %d Name: %s Buff: %s\n", __func__, __LINE__, ret, 
        	//get_event()->u.bevt.data_len, get_event()->u.bevt.u.subdoc.name, get_event()->u.bevt.u.subdoc.buff);
        
        switch (get_event()->type) {
            case em_event_type_bus:
                if (m_ctrl.is_data_model_initialized() == true && m_ctrl.is_network_topology_initialized() == true) {
                    wait = m_ctrl.io_process(get_event());
                } else {
                    if (get_event()->u.bevt.type == em_bus_event_type_reset) {
                        wait = m_ctrl.io_process(get_event());
                    } else {
                        wait = false;
                    }
                }
                break;

            default:
                wait = false;
                break;
        }	

		//printf("%s:%d: Sending result: Wait: %d\n", __func__, __LINE__, wait);
        if (wait == false) {
            send_result(em_cmd_out_status_other);
        }

        m_cmd.reset();

    }

    close(lsock);
    unlink(get_path());

    return 0;
}

int em_cmd_ctrl_t::send_result(em_cmd_out_status_t status)
{
    ssize_t ret;
    char *str; 
    unsigned char *tmp;

	str = static_cast<char *> (malloc(EM_MAX_EVENT_DATA_LEN));
	memset(str, 0, EM_MAX_EVENT_DATA_LEN);

    tmp = reinterpret_cast<unsigned char *> (m_cmd.status_to_string(status, str));

    if ((ret = send(m_dsock, tmp, strlen(str) + 1, 0)) <= 0) {
        printf("%s:%d: write error on socket, err:%d\n", __func__, __LINE__, errno);
    }

	//printf("%s:%d: Send success bytes sent:%d\n", __func__, __LINE__, ret);

    close(m_dsock);
	free(str);

    return 0;
}


em_cmd_ctrl_t::em_cmd_ctrl_t()
{
    dm_easy_mesh_t dm;

    m_cmd.init(&dm);
    snprintf(m_sock_path, sizeof(m_sock_path), "%s_%s", EM_PATH_PREFIX, EM_CTRL_PATH);
}


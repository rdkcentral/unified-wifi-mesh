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

int em_cmd_ctrl_t::execute(em_long_string_t result)
{
    struct sockaddr_un addr;
    int ret, lsock, dsock;
    unsigned int sz = sizeof(em_event_t);
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

            if ((ret = recv(m_dsock, tmp, sizeof(em_event_t), 0)) <= 0) {
                printf("%s:%d: listen error on socket, err:%d\n", __func__, __LINE__, errno);
            }


        //printf("%s:%d: Read bytes: %d Size: %d Buff: %s\n", __func__, __LINE__, ret, 
        //			get_event()->u.bevt.u.subdoc.sz, get_event()->u.bevt.u.subdoc.buff);
        //printf("%s:%d: Read bytes: %d\n", __func__, __LINE__, ret);
        
        switch (get_event()->type) {
            case em_event_type_bus:
                wait = m_ctrl.io_process(get_event());
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

int em_cmd_ctrl_t::send_result(em_cmd_out_status_t status)
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


em_cmd_ctrl_t::em_cmd_ctrl_t()
{
    dm_easy_mesh_t dm;

    m_cmd.init(&dm);
    snprintf(m_sock_path, sizeof(m_sock_path), "%s_%s", EM_PATH_PREFIX, EM_CTRL_PATH);
}


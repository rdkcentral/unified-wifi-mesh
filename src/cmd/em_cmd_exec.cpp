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
#include "em_cli.h"

const char *em_cmd_exec_t::m_sock_path = "/tmp/onewifimesh";

void em_cmd_exec_t::wait(struct timespec *time_to_wait)
{
    printf("Waiting\n");
    pthread_mutex_lock(&m_lock);
    //pthread_cond_timedwait(&m_cond, &m_lock, time_to_wait);
    pthread_cond_wait(&m_cond, &m_lock);
    printf("End Waiting\n");
}

void em_cmd_exec_t::release_wait()
{
    printf("Signaling\n");
    pthread_cond_signal(&m_cond);
    pthread_mutex_unlock(&m_lock);
}

int em_cmd_exec_t::execute(em_cmd_type_t type, em_service_type_t to_svc, unsigned char *in, unsigned int len)
{
    em_event_t ev;
    em_bus_event_t *bevt;
    em_subdoc_info_t    *info;
    ev.type = em_event_type_bus;
    bevt = &ev.u.bevt;
    bevt->type = em_cmd_t::cmd_2_bus_event_type(type);
    info = &bevt->u.subdoc;
    memcpy(info->buff, in, len);
    info->sz = len;
    return send_cmd(to_svc, (unsigned char *)&ev, sizeof(em_event_t));;
}

int em_cmd_exec_t::send_cmd(em_service_type_t to_svc, unsigned char *in, unsigned int in_len, char *out, unsigned int out_len)
{
    struct sockaddr_un addr;
    int dsock, ret;
    em_long_string_t sock_path;
    unsigned int sz = sizeof(em_event_t);
    switch (to_svc) {
        case em_service_type_ctrl:
            snprintf(sock_path, sizeof(sock_path), "%s_%s", EM_PATH_PREFIX, EM_CTRL_PATH);
            break;
        case em_service_type_agent:
            snprintf(sock_path, sizeof(sock_path), "%s_%s", EM_PATH_PREFIX, EM_AGENT_PATH);
            break;
        case em_service_type_cli:
            snprintf(sock_path, sizeof(sock_path), "%s_%s", EM_PATH_PREFIX, EM_CLI_PATH);
            break;
        default:
            return -1;
            break;
    }
    if ((dsock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        snprintf(out, out_len, "%s:%d: error opening socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }
    setsockopt(dsock, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)); // Send buffer 1K
    setsockopt(dsock, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)); // Receive buffer 1K
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/onewifimesh", sizeof(addr.sun_path));    
    //snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);
    if ((ret = connect(dsock, (const struct sockaddr *) &addr, sizeof(struct sockaddr_un))) != 0) {
        snprintf(out, out_len, "%s:%d: connect error on socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }
    if ((ret = send(dsock, in, in_len, 0)) <= 0) {
        close(dsock);
        return -1;
    }
    if (out == NULL) {
        close(dsock);
        return 0;
    }
    /* Receive result. */
    if ((ret = recv(dsock, (unsigned char *)out, out_len, 0)) <= 0) {
        snprintf(out, out_len, "%s:%d: result read error on socket, err:%d\n", __func__, __LINE__, errno);
        close(dsock);
        return -1;
    }
    close(dsock);
    return 0;
}

void em_cmd_exec_t::init()
{
    pthread_cond_init(&m_cond, NULL);
    pthread_mutex_init(&m_lock, NULL);

}

em_cmd_exec_t::em_cmd_exec_t()
{

}

em_cmd_exec_t::~em_cmd_exec_t()
{

}

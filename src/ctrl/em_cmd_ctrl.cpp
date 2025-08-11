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
    int lsock, dsock;
    ssize_t ret;
    unsigned int sz = sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN;
    unsigned char *tmp;
    bool wait = false;

    m_cmd.reset();


	if ((lsock = get_listener_socket(em_service_type_ctrl)) < 0) {
        printf("%s:%d: listener socket get failed, service:%d\n", __func__, __LINE__, get_svc());
        return -1;
	}

    if ((ret = listen(lsock, 20)) == -1) {
        printf("%s:%d: listen error on socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    while (1) {

        //printf("%s:%d: Waiting for client connection\n", __func__, __LINE__);
        if ((dsock = accept(lsock, NULL, NULL)) == -1) {
            printf("%s:%d: listen error on socket, err:%d\n", __func__, __LINE__, errno);
            continue;
        }

        setsockopt(dsock, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)); // Send buffer EM_MAX_EVENT_DATA_LEN
        setsockopt(dsock, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)); // Receive buffer EM_MAX_EVENT_DATA_LEN

        //printf("%s:%d: Connection accepted from client\n", __func__, __LINE__);

        tmp = reinterpret_cast<unsigned char *> (get_event());
        m_ssl = SSL_new(get_ssl_ctx());
        SSL_set_fd(m_ssl, dsock);

        if (SSL_accept(m_ssl) <= 0) {
            SSL_free(m_ssl);
            close(dsock);
            continue;
        }

		if ((ret = SSL_read(m_ssl, tmp, sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN)) <= 0) {
			printf("%s:%d: listen error on socket, err:%d\n", __func__, __LINE__, errno);
		}

        //printf("%s:%d: Read bytes: %d Size: %d Name: %s Buff: %s\n", __func__, __LINE__, ret, 
        	//get_event()->u.bevt.data_len, get_event()->u.bevt.u.subdoc.name, get_event()->u.bevt.u.subdoc.buff);
        
        switch (get_event()->type) {
            case em_event_type_bus:
                if (m_ctrl.is_data_model_initialized() == true && m_ctrl.is_network_topology_initialized() == true) {
                    wait = m_ctrl.io_process(get_event());
                } else {
                    if ((get_event()->u.bevt.type == em_bus_event_type_reset) || (get_event()->u.bevt.type == em_bus_event_type_get_reset) ){
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

	close_listener_socket(lsock, get_svc());

    return 0;
}

int em_cmd_ctrl_t::send_result(unsigned char *data, unsigned int len)
{
    ssize_t ret;
    int sd;

    if ((ret = SSL_write(m_ssl, data, len)) <= 0) {
        printf("%s:%d: write error on socket, err:%d\n", __func__, __LINE__, errno);
    }

    //printf("%s:%d: Send success bytes sent:%d\n", __func__, __LINE__, ret);
    sd = SSL_get_fd(m_ssl);
    SSL_shutdown(m_ssl);
    SSL_free(m_ssl);
    close(sd);

    return 0;
}

int em_cmd_ctrl_t::send_result(em_cmd_out_status_t status)
{
    ssize_t ret;
    char *str; 
    unsigned char *tmp;
	int sd;

	str = static_cast<char *> (malloc(EM_MAX_EVENT_DATA_LEN));
	memset(str, 0, EM_MAX_EVENT_DATA_LEN);

    tmp = reinterpret_cast<unsigned char *> (m_cmd.status_to_string(status, str));

    if ((ret = SSL_write(m_ssl, tmp, strlen(str) + 1)) <= 0) {
        printf("%s:%d: write error on socket, err:%d\n", __func__, __LINE__, errno);
    }

	//printf("%s:%d: Send success bytes sent:%d\n", __func__, __LINE__, ret);
	sd = SSL_get_fd(m_ssl);
	SSL_shutdown(m_ssl);
	SSL_free(m_ssl);
	close(sd);

	free(str);

    return 0;
}


em_cmd_ctrl_t::em_cmd_ctrl_t()
{
    dm_easy_mesh_t dm;

    m_cmd.init(dm);
}


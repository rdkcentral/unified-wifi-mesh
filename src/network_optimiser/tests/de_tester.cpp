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
#include <sys/stat.h>
#include <sys/types.h>
#include "assert.h"
#include "de_tester.h"

void de_tester_t::update()
{
    unsigned int num, i, j, k, l, o, p, rcount, bcount, scount, occount, opccount;
    de_network_t net;
    de_service_t svc;
    de_device_t dev;
    de_radio_t rd;
    de_bss_t bss;
    de_sta_t sta;
    de_curr_op_class_t curr_op_class;
    de_cap_t cap;
    de_op_class_t op_class;
    de_net_ssid_t net_ssid;

    m_rd->update_network(net);
    m_de_network->update(net);

    num = m_rd->get_num_services();
    for (i = 0; i < num; i++) {
        m_rd->update_service(svc, i);
        m_de_network->m_de_services->update(svc, i);
    }

    num = m_rd->get_num_devices();
    for (i = 0; i < num; i++) {
        m_rd->update_device(dev, i);
        m_de_network->m_de_devices->update(dev, i);
        rcount = m_rd->get_num_radios(i);
        for (j = 0; j < rcount; j++) {
            m_rd->update_radio(rd, i, j);
            m_de_network->m_de_devices->update(rd, i, j);
            occount = m_rd->get_num_curr_op_classes(i, j);
            for (o = 0; o < occount; o++) {
                m_rd->update_curr_op_class(curr_op_class, i, j, o);
                m_de_network->m_de_devices->update(curr_op_class, i, j, o);
            }
            m_rd->update_cap(cap, i, j);
            m_de_network->m_de_devices->update(cap, i, j);
            opccount = m_rd->get_num_op_classes(i, j);
            for (p = 0; p < opccount; p++) {
                m_rd->update_op_class(op_class, i, j, p);
                m_de_network->m_de_devices->update(op_class, i, j, p);
            }
            bcount = m_rd->get_num_bsss(i, j);
            for (k = 0; k < bcount; k++) {
                m_rd->update_bss(bss, i, j, k);
                m_de_network->m_de_devices->update(bss, i, j, k);
                scount = m_rd->get_num_stas(i, j, k);
                for (l = 0; l < scount; l++) {
                    m_rd->update_sta(sta, i, j, k, l);
                    m_de_network->m_de_devices->update(sta, i, j, k, l);
                }
            }
        }
    }

    num = m_rd->get_num_net_ssids();
    for (i = 0; i < num; i++) {
        m_rd->update_net_ssid(net_ssid, i);
        m_de_network->m_de_net_ssids->update(net_ssid, i);
    }
}

void de_tester_t::process_event(optimizer_event_t *ev)
{
    switch (ev->get_type()) {
        case optimizer_event_type_subscribed: {
            const char *name = static_cast<const char *>(ev->get_data());
            if ((name == NULL) || (ev->get_len() == 0) ||
                (name[ev->get_len() - 1] != '\0')) {
                printf("%s:%d: Invalid subscribed event name\n", __func__, __LINE__);
                break;
            }
            m_de_network->publish(name);
            break;
        }
   
        default:
            break;                 
    }

}

int de_tester_t::wait()
{
    struct timespec time_to_wait;
    struct timeval tm_now;

    gettimeofday(&tm_now, NULL);

    time_to_wait.tv_sec = tm_now.tv_sec;
    time_to_wait.tv_nsec = tm_now.tv_usec*1000;
    time_to_wait.tv_sec += 2;

    return pthread_cond_timedwait(&m_cond, &m_lock, &time_to_wait);
}

int de_tester_t::init()
{
    de_t::notifier_t notifier = [this](optimizer_event_t *event) { push_to_queue(event); };

    pthread_cond_init(&m_cond, NULL);
    pthread_mutex_init(&m_lock, NULL);
    m_queue = queue_create();

    m_de_network = new de_network_t(NETWORK, true, notifier);
    if (m_de_network->init() != 0) {
        printf("%s:%d: Network init failed\n", __func__, __LINE__);

        return -1;
    }

    update();
    
    return 0;
}

void de_tester_t::deinit()
{
    m_de_network->deinit();

    queue_destroy(m_queue);
    pthread_mutex_destroy(&m_lock);
    pthread_cond_destroy(&m_cond);
}

de_tester_t::de_tester_t(de_reader_t *rd)
{
    m_exit = false;
    m_rd = rd;
    m_queue = NULL;
    m_de_network = NULL;
}

de_tester_t::~de_tester_t()
{

}

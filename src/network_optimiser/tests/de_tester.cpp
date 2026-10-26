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
    unsigned int num, i, j, k, l, rcount, bcount, scount;
    de_network_t net;
    de_service_t svc;
    de_device_t dev;
    de_radio_t rd;
    de_bss_t bss;
    de_sta_t sta;

    m_rd->update_network(net);
    m_de_network->update(net);

    num = m_rd->get_num_services();
    for (i = 0; i < num; i++) {
        m_rd->update_service(svc, i);
        m_de_services->update(svc, i);
    }

    num = m_rd->get_num_devices();
    for (i = 0; i < num; i++) {
        m_rd->update_device(dev, i);
        m_de_devices->update(dev, i);
        rcount = m_rd->get_num_radios(i);
        for (j = 0; j < rcount; j++) {
            m_rd->update_radio(rd, i, j);
            m_de_devices->update(rd, i, j);
            bcount = m_rd->get_num_bsss(i, j);
            for (k = 0; k < bcount; k++) {
                m_rd->update_bss(bss, i, j, k);
                m_de_devices->update(bss, i, j, k);
                scount = m_rd->get_num_stas(i, j, k);
                for (l = 0; l < scount; l++) {
                    m_rd->update_sta(sta, i, j, k, l);
                    m_de_devices->update(sta, i, j, k, l);
                }
            }
        }
    }
}

void de_tester_t::process_event(optimizer_event_t *ev)
{
    const char *name;

    switch (ev->get_type()) {
        case optimizer_event_type_subscribed:
            name = static_cast<const char *>(ev->get_data());
            if ((strcmp(name, DE_NETWORK_ID) == 0) || (strcmp(name, DE_NETWORK_CTRLID) == 0)) {
                m_de_network->publish(name);
            } else if (strncmp(name, SERVICES, strlen(SERVICES)) == 0) {
                m_de_services->publish(name);
            } else if (strncmp(name, DEVICES, strlen(DEVICES)) == 0) {
                m_de_devices->publish(name);
            } else if (strncmp(name, RADIOS, strlen(RADIOS)) == 0) {
                m_de_devices->publish(name);
            } else if (strncmp(name, BSSS, strlen(BSSS)) == 0) {
                m_de_devices->publish(name);
            } else if (strncmp(name, STAS, strlen(STAS)) == 0) {
                m_de_devices->publish(name);
            }
            break;
   
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

    m_de_services = new de_services_t(SERVICES, true, notifier);
    if (m_de_services->init() != 0) {
        printf("%s:%d: Services init failed\n", __func__, __LINE__);

        return -1;
    }

    m_de_devices = new de_devices_t(DEVICES, true, notifier);
    if (m_de_devices->init() != 0) {
        printf("%s:%d: Devices init failed\n", __func__, __LINE__);

        return -1;
    }

    update();
    
    return 0;
}

void de_tester_t::deinit()
{
    if (m_de_devices) delete m_de_devices;
    if (m_de_services) delete m_de_services;
    if (m_de_network) delete m_de_network;

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
    m_de_services = NULL;
    m_de_devices = NULL;
}

de_tester_t::~de_tester_t()
{

}

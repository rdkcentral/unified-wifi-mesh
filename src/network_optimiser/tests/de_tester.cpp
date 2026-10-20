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

void de_tester_t::update(de_device_t& dev, unsigned int pos)
{
    unsigned int num, i;
    de_radio_t radio;

    num = m_rd->get_num_radios(pos);
    printf("%s:%d: Number of radios for device at pos: %d is %d\n", __func__, __LINE__, pos, num);
    for (i = 0; i < num; i++) {
        m_rd->update_radio(radio, pos, i);
        m_de_radios->update(radio, pos, i);
    }
}

void de_tester_t::update()
{
    unsigned int num, i;
    de_network_t net;
    de_service_t svc;
    de_device_t dev;

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

        //update(dev, i); 
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
            } else if (strncmp(name, DE_SERVICES, strlen(DE_SERVICES)) == 0) {
                m_de_services->publish(name);
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

/*

    m_de_radios = new de_radios_t(DE_RADIOS, push_to_queue, true);
    if (m_de_radios->init() != 0) {
        printf("%s:%d: Radios init failed\n", __func__, __LINE__);

        return -1;
    }
*/

    update();
    
    return 0;
}

void de_tester_t::deinit()
{
    if (m_de_radios) delete m_de_radios;
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
    m_de_radios = NULL;
}

de_tester_t::~de_tester_t()
{

}

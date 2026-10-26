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
#include "optimizer.h"
#include "comcast_optimizer.h"
#include "comcast_optimizer_xmidt.h"
#include "comcast_optimizer_web.h"
#include "util.h"
#include "assert.h"

int optimizer_t::run(optimizer_type_t type)
{
    int rc;
    struct timespec time_to_wait;
    struct timeval tm_now;
    em_string_t time_str;
    optimizer_t *opt = NULL;
    optimizer_event_t *ev;

    switch (type) {
        case optimizer_type_comcast:
            opt = new comcast_optimizer_web_t();
            opt->m_de_network = m_de_network;
            opt->m_de_services = m_de_services;
            opt->m_de_devices = m_de_devices;
            m_exit = false;
            break;

        default:
            ;       
    }

    if (opt == NULL) {
        printf("%s:%d: Optimizer for operator (%d) not implemented\n", __func__, __LINE__, type);
        return -1;
    }

    if (opt->init_optimizer_interface(get_url()) != 0) {
        m_exit = true;
        delete (comcast_optimizer_t *)opt;
        return -1;
    }

    pthread_mutex_lock(&m_lock);
    while (m_exit == false) {
        rc = 0;

        gettimeofday(&tm_now, NULL);

        time_to_wait.tv_sec = tm_now.tv_sec;
        time_to_wait.tv_nsec = tm_now.tv_usec*1000;

        time_to_wait.tv_sec += 2;

        rc = pthread_cond_timedwait(&m_cond, &m_lock, &time_to_wait);
        if ((rc == 0)  || (queue_count(m_queue) != 0)) {
            pthread_mutex_unlock(&m_lock);
            while (queue_count(m_queue)) {
                ev = static_cast<optimizer_event_t *>(queue_pop(m_queue));
                if (ev == NULL) {
                    continue;
                }
                switch (ev->get_type()) {
                    case optimizer_event_type_de_change:
                        // need to come out of run loop
                        m_exit = true;
                        break;

                    default:
                        opt->process_event(ev);
                }
                delete ev;
            }
            pthread_mutex_lock(&m_lock);
        } else if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&m_lock);
            gettimeofday(&tm_now, NULL);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&tm_now.tv_sec));
            opt->process_timeout(time_str);
            pthread_mutex_lock(&m_lock);
        } else {
            printf("%s:%d em exited with rc - %d\n",__func__,__LINE__,rc);
            pthread_mutex_unlock(&m_lock);
            return -1;
        }
    }
    pthread_mutex_unlock(&m_lock);

    opt->deinit_optimizer_interface();
    delete (comcast_optimizer_t *)opt;

    return 0;
}

int optimizer_t::init()
{
    em_long_string_t key = {0};
    rbusHandle_t handle;

    m_exit = false;
    pthread_cond_init(&m_cond, NULL);
    pthread_mutex_init(&m_lock, NULL);
    m_queue = queue_create();
 
    // Network
    m_de_network = new de_network_t(NETWORK); 
    if (m_de_network->init() != 0) {
        printf("%s:%d: South Bound Data Elements Interface init failed\n", __func__, __LINE__);
        return -1;
    }

    // Services 
    m_de_services = new de_services_t(SERVICES); 
    if (m_de_services->init() != 0) {
        printf("%s:%d: South Bound Data Elements Interface init failed\n", __func__, __LINE__);
        return -1;
    }

    // Devices 
    m_de_devices = new de_devices_t(DEVICES); 
    if (m_de_devices->init() != 0) {
        printf("%s:%d: South Bound Data Elements Interface init failed\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

void optimizer_t::deinit()
{
    queue_destroy(m_queue);
    pthread_mutex_destroy(&m_lock);
    pthread_cond_destroy(&m_cond);
}

void optimizer_t::wait_for_de_change()
{
    optimizer_event_t *ev;
    printf("%s:%d: Generic optimizer, should wait for type to be set to correct operator\n", __func__, __LINE__);
    wait();
    pthread_mutex_unlock(&m_lock);
    while (queue_count(m_queue)) {
        ev = static_cast<optimizer_event_t *>(queue_pop(m_queue));
        if (ev != NULL) {
            delete ev;
        }
    }
    pthread_mutex_unlock(&m_lock);
}

optimizer_t::optimizer_t()
{
    m_optimizer_type = optimizer_type_generic;
    m_de_network = NULL;
    m_de_services = NULL;
    m_de_devices = NULL;
}

optimizer_t::~optimizer_t()
{

}

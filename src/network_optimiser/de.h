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

#ifndef DE_H
#define DE_H

#include <functional>
#include "rbus.h"
#include "em_base.h"
#include "collection.h"
#include "de_defs.h"


#define MAX_NUM_ELEMS     20 

class optimizer_event_t;

class de_t {

public:
    typedef std::function<void(optimizer_event_t *ev)> notifier_t;

    rbusHandle_t    m_bus_handle;
    bool    m_provider;
    unsigned int    m_num_elems;
    rbusDataElement_t  m_elems[MAX_NUM_ELEMS];

    unsigned int m_num_subs;
    rbusEventSubscription_t m_subs[MAX_NUM_ELEMS];

    notifier_t  m_func;
    em_string_t m_name;

    int init(rbusHandle_t handle = NULL);
    void deinit(bool bus_close = true);

    int subscribe_events();
    void unsubscribe_events();
    
    int register_elements();
    void deregister_elements(); 

    const char *get_name() { return m_name; }

    virtual rbusError_t add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num);
    virtual rbusError_t remove(rbusHandle_t handle, char const* row_name);
    virtual rbusError_t get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options);
    virtual rbusError_t set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options);
    virtual rbusError_t event(rbusHandle_t handle, rbusEventSubAction_t action, char const* event_name, rbusFilter_t filter, int32_t interval, bool* auto_publish);
    virtual void handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription);

    de_t();
    ~de_t(); 
};

#endif

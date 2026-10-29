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
#include "util.h"
#include "optimizer.h"
#include "de.h"

rbusError_t de_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    de_t *de = (de_t *)rbusHandle_GetUserData(handle);

    return ((de_t *)rbusHandle_GetUserData(handle))->add(handle, table_name, alias_name, inst_num);
}

rbusError_t de_t::remove(rbusHandle_t handle, char const* row_name)
{
    return RBUS_ERROR_SUCCESS;
}

static rbusError_t remove(rbusHandle_t handle, char const* row_name)
{
    return ((de_t *)rbusHandle_GetUserData(handle))->remove(handle, row_name);
}

rbusError_t de_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    return ((de_t *)rbusHandle_GetUserData(handle))->get(handle, property, options);;
}


rbusError_t de_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

static rbusError_t set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    return ((de_t *)rbusHandle_GetUserData(handle))->set(handle, property, options);
}

rbusError_t de_t::event(rbusHandle_t handle, rbusEventSubAction_t action, char const* event_name, rbusFilter_t filter, int32_t interval, bool* auto_publish)
{
    if (action == RBUS_EVENT_ACTION_SUBSCRIBE) {
        *auto_publish = false;
        if (m_func != NULL) {
            m_func(new optimizer_event_t(optimizer_event_type_subscribed, (char *)event_name, strlen(event_name) + 1, false));
        } else {
            printf("%s:%d: Null function\n", __func__, __LINE__);
        }

    } else if (action == RBUS_EVENT_ACTION_UNSUBSCRIBE) {
        printf("%s:%d: Last subscriber removed, can disable event generation\n", __func__, __LINE__);
    }

    return RBUS_ERROR_SUCCESS;
}

static rbusError_t event(rbusHandle_t handle, rbusEventSubAction_t action, char const* event_name, rbusFilter_t filter, int32_t interval, bool* auto_publish)
{
    return ((de_t *)rbusHandle_GetUserData(handle))->event(handle, action, event_name, filter, interval, auto_publish);
}

void de_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{

}

static void handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    return ((de_t *)subscription->userData)->handler(handle, event, subscription);
    
}

int de_t::subscribe_events()
{
    unsigned int i;
    
    for (i = 0; i < m_num_subs; i++) {
        m_subs[i].handler = (void *)::handler;
        m_subs[i].userData = this;
        m_subs[i].publishOnSubscribe = true;
    }

    if (rbusEvent_SubscribeEx(m_bus_handle, m_subs, m_num_subs, 0) != RBUS_ERROR_SUCCESS) {
        printf("%s:%d: Failed to subscribe for de: %s(num: %d)\n", __func__, __LINE__, m_name, m_num_subs);
        return -1;
    }

    return 0;
}

void de_t::unsubscribe_events()
{
    rbusEvent_UnsubscribeEx(m_bus_handle, m_subs, m_num_subs); 
}

void de_t::deregister_elements()
{
    rbus_unregDataElements(m_bus_handle, m_num_elems, m_elems);
}

int de_t::register_elements()
{
    unsigned int i;

    for (i = 0; i < m_num_elems; i++) {
        if (m_elems[i].type == RBUS_ELEMENT_TYPE_TABLE) {
            m_elems[i].cbTable.tableAddRowHandler = ::add;
            m_elems[i].cbTable.tableRemoveRowHandler = ::remove; 
        } else {
            m_elems[i].cbTable.getHandler = ::get; 
            m_elems[i].cbTable.setHandler = ::set; 
        }
            
        m_elems[i].cbTable.eventSubHandler = ::event;
    } 

    if (rbus_regDataElements(m_bus_handle, m_num_elems, m_elems) != RBUS_ERROR_SUCCESS) {
        printf("%s:%d: Failed to register table elements(%d)\n", __func__, __LINE__, m_num_elems);
        rbus_close(m_bus_handle);
        return -1;
    }

    return 0;
}

int de_t::init(rbusHandle_t handle)
{
    int ret = 0;
    em_string_t name = {0};

    snprintf(name, sizeof(name), "%s-%s", m_name, (m_provider == true)?"Provider":"Consumer");

    if (handle == NULL) {
        if (rbus_open(&m_bus_handle, name) != RBUS_ERROR_SUCCESS) {
            printf("%s:%d: Failed to open rbus, name: %s\n", __func__, __LINE__, m_name);
            return -1;
        }
        rbusHandle_SetUserData(m_bus_handle, this);
    } else {
        m_bus_handle = handle;
    }

    if (m_provider == true) {
        ret = register_elements();
    } else {
        ret = subscribe_events();
    }

    return ret;
}

void de_t::deinit(bool bus_close)
{
    if (m_provider == true) {
        deregister_elements();
    } else {
        unsubscribe_events();
    }

    if (bus_close == true) {
        rbus_close(m_bus_handle);
    } else {
        m_bus_handle = NULL;
    }
}

de_t::de_t()
{
    m_num_elems = 0;
    memset(m_elems, 0, (MAX_NUM_ELEMS)*sizeof(rbusDataElement_t));
    memset(m_name, 0, sizeof(em_string_t));

    m_num_subs = 0;
    memset(m_subs, 0, (MAX_NUM_ELEMS)*sizeof(rbusEventSubscription_t));
}

de_t::~de_t()
{

}

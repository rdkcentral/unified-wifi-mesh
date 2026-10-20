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
#include "de_network.h"
#include "optimizer.h"

void de_network_t::update(de_network_t& net)
{
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusValue_SetString(value, net.m_id);
    rbus_set(m_bus_handle, DE_NETWORK_ID, value, NULL);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, net.m_controller_id);
    rbus_set(m_bus_handle, DE_NETWORK_CTRLID, value, NULL);
    rbusValue_Release(value);
}

rbusError_t de_network_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    const char *name, *ptr;

    name  = rbusProperty_GetName(property);
    printf("%s:%d: Property Name: %s\n", __func__, __LINE__, name);

    if ((ptr = strstr(name, "Network.")) == NULL) {
        return RBUS_ERROR_INVALID_OPERATION;
    }

    ptr += strlen("Network.");

    if (strncmp(ptr, "ID", strlen("ID")) == 0) {
        rbusProperty_SetString(property, m_id);
    } else if (strncmp(ptr, "ControllerID", strlen("ControllerID")) == 0) {
        rbusProperty_SetString(property, m_controller_id);
    }

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_network_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    const char *name, *ptr;
    int len;

    name  = rbusProperty_GetName(property);
    printf("%s:%d: Property Name: %s\n", __func__, __LINE__, name);

    if ((ptr = strstr(name, "Network.")) == NULL) {
        return RBUS_ERROR_INVALID_OPERATION;
    }
    
    ptr += strlen("Network.");

    if (strncmp(ptr, "ID", strlen("ID")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(m_id, ptr, len); 
    } else if (strncmp(ptr, "ControllerID", strlen("ControllerID")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(m_controller_id, ptr, len); 
    }

    return RBUS_ERROR_SUCCESS;
}

void de_network_t::publish(const char *name)
{
    char *ptr;
    rbusValue_t value;
    rbusObject_t data;
    int rc;
    rbusEvent_t event = {0};

    if ((ptr = strstr((char *)name, "Network.")) == NULL) {
        return;
    }
    
    ptr += strlen("Network.");

    rbusValue_Init(&value);
    
    if (strncmp(ptr, "ID", strlen("ID")) == 0) {
        rbusValue_SetString(value, m_id);
        event.name = DE_NETWORK_ID;
    } else if (strncmp(ptr, "ControllerID", strlen("ControllerID")) == 0) {
        rbusValue_SetString(value, m_controller_id);
        event.name = DE_NETWORK_CTRLID;
    } else {
        rbusValue_Release(value);
        return;
    }
    
    rbusObject_Init(&data, NULL);
    rbusObject_SetValue(data, "value", value);

    event.data = data;
    event.type = RBUS_EVENT_GENERAL;

    if ((rc = rbusEvent_Publish(m_bus_handle, &event)) != RBUS_ERROR_SUCCESS) {
        printf("%s:%d: Failed to publish data for event: %s, err: %d\n", __func__, __LINE__, 
            event.name, rc);
    } else {
        printf("%s:%d: Successfully published data for event: %s\n", __func__, __LINE__, event.name);
    }

    rbusValue_Release(value);
    rbusObject_Release(data);
}

void de_network_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{

}

int de_network_t::init()
{
    m_elems[m_num_elems].name = DE_NETWORK_ID;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;
    
    m_elems[m_num_elems].name = DE_NETWORK_CTRLID;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_subs[m_num_subs].eventName = DE_NETWORK_ID;
    m_num_subs++;

    m_subs[m_num_subs].eventName = DE_NETWORK_CTRLID;
    m_num_subs++;

    return de_t::init();
}

void de_network_t::deinit()
{

}

de_network_t::de_network_t(const char *name, bool provider, notifier_t func)
{
    strncpy(m_name, name, strlen(name));
    memset(m_id, 0, sizeof(em_string_t));
    memset(m_controller_id, 0, sizeof(em_string_t));
    m_provider = provider;
    m_func = func;
}

de_network_t::de_network_t()
{

}

de_network_t::~de_network_t()
{

}

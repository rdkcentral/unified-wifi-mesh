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

rbusError_t de_network_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    if (strstr(table_name, DEVICES) != NULL) {
        return m_de_devices->add(handle, table_name, alias_name, inst_num);
    } else if (strstr(table_name, SERVICES) != NULL) {
        return m_de_services->add(handle, table_name, alias_name, inst_num);
    } else if (strstr(table_name, NET_SSIDS) != NULL) {
        return m_de_net_ssids->add(handle, table_name, alias_name, inst_num);
    }

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_network_t::remove(rbusHandle_t handle, char const* row_name)
{
    if (strstr(row_name, DEVICES) != NULL) {
        return m_de_devices->remove(handle, row_name);
    } else if (strstr(row_name, SERVICES) != NULL) {
        return m_de_services->remove(handle, row_name);
    } else if (strstr(row_name, NET_SSIDS) != NULL) {
        return m_de_net_ssids->remove(handle, row_name);
    }

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_network_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    const char *name, *ptr;

    name  = rbusProperty_GetName(property);
    printf("%s:%d: Property Name: %s\n", __func__, __LINE__, name);

    if ((ptr = strstr(name, SERVICES)) != NULL) {
        return m_de_services->get(handle, property, options);
    } else if ((ptr = strstr(name, DEVICES)) != NULL) {
        return m_de_devices->get(handle, property, options);
    } else if ((ptr = strstr(name, NET_SSIDS)) != NULL) {
        return m_de_net_ssids->get(handle, property, options);
    } else if ((ptr = strstr(name, "Network.")) == NULL) {
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

    if ((ptr = strstr(name, SERVICES)) != NULL) {
        return m_de_services->set(handle, property, options);
    } else if ((ptr = strstr(name, DEVICES)) != NULL) {
        return m_de_devices->set(handle, property, options);
    } else if ((ptr = strstr(name, NET_SSIDS)) != NULL) {
        return m_de_net_ssids->set(handle, property, options);
    } else if ((ptr = strstr(name, "Network.")) == NULL) {
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

    printf("%s:%d: Name: %s\n", __func__, __LINE__, name);
    if ((strncmp(name, DEVICES, strlen(DEVICES)) == 0) || (strncmp(name, RADIOS, strlen(RADIOS)) == 0) || 
            (strncmp(name, BSSS, strlen(BSSS)) == 0) || (strncmp(name, STAS, strlen(STAS)) == 0) ||
            (strncmp(name, CURR_OP_CLASSES, strlen(CURR_OP_CLASSES)) == 0) ||
            (strncmp(name, CAPS, strlen(CAPS)) == 0) || (strncmp(name, OP_CLASSES, strlen(OP_CLASSES)) == 0)) {
        m_de_devices->publish(name);
        return;

    } else if (strncmp(name, SERVICES, strlen(SERVICES)) == 0) {
        m_de_services->publish(name);
        return;
    } else if (strncmp(name, NET_SSIDS, strlen(NET_SSIDS)) == 0) {
        m_de_net_ssids->publish(name);
        return;
    }


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
    rbusValue_t value;
    const char *ptr;

    printf("%s:%d: Event Name: %s\n", __func__, __LINE__, subscription->eventName);
    if (strncmp(subscription->eventName, DE_NETWORK_CTRLID, strlen(DE_NETWORK_CTRLID)) == 0) {
        if ((value = rbusObject_GetValue(event->data, "value")) == NULL) {
            printf("%s:%d: No value in event\n", __func__, __LINE__);
            return;
        }
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_controller_id, ptr, strlen(ptr)); 
        printf("%s:%d: Controller ID: %s\n", __func__, __LINE__, m_controller_id);
    } else if (strncmp(subscription->eventName, DE_NETWORK_ID, strlen(DE_NETWORK_ID)) == 0) {
        if ((value = rbusObject_GetValue(event->data, "value")) == NULL) {
            printf("%s:%d: No value in event\n", __func__, __LINE__);
            return;
        }
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_id, ptr, strlen(ptr)); 
        printf("%s:%d: Network ID: %s\n", __func__, __LINE__, m_id);
    }
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

    if (de_t::init() != 0) {
        printf("%s:%d: Failed to initialize network\n", __func__, __LINE__);
        return -1;
    }

    m_de_services = new de_services_t(SERVICES, m_provider, m_func);
    if (m_de_services->init(m_bus_handle) != 0) {
        printf("%s:%d: Failed to initialize services\n", __func__, __LINE__);
        return -1;
    }
    
    m_de_devices = new de_devices_t(DEVICES, m_provider, m_func);
    if (m_de_devices->init(m_bus_handle) != 0) {
        printf("%s:%d: Failed to initialize devices\n", __func__, __LINE__);
        return -1;
    }
    
    m_de_net_ssids = new de_net_ssids_t(NET_SSIDS, m_provider, m_func);
    if (m_de_net_ssids->init(m_bus_handle) != 0) {
        printf("%s:%d: Failed to initialize net ssids\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

void de_network_t::deinit()
{
    if (m_de_net_ssids != NULL) {
        m_de_net_ssids->deinit(false);
    }
    if (m_de_devices != NULL) {
        m_de_devices->deinit(false);
    }
    if (m_de_services != NULL) {
        m_de_services->deinit(false);
    }

    de_t::deinit();
}

de_network_t::de_network_t(const char *name, bool provider, notifier_t func)
{
    strncpy(m_name, name, strlen(name));
    memset(m_id, 0, sizeof(em_string_t));
    memset(m_controller_id, 0, sizeof(em_string_t));
    m_provider = provider;
    m_func = func;
    m_de_services = NULL;
    m_de_devices = NULL;
    m_de_net_ssids = NULL;
}

de_network_t::de_network_t()
{
    m_de_services = NULL;
    m_de_devices = NULL;
    m_de_net_ssids = NULL;
}

de_network_t::~de_network_t()
{

}

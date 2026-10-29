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
#include "de_services.h"
#include "optimizer.h"

void de_services_t::update(de_service_t& svc, unsigned int pos)
{
    rbusValue_t value;
    em_long_string_t name = {0};
    unsigned int inst;
    de_service_t *psvc = NULL;
    em_string_t alias = {0};

    snprintf(alias, sizeof(em_string_t), "%s.%d", SERVICES, pos);

    if ((psvc = (de_service_t *)hash_map_get(m_service_map, alias)) == NULL) {
        snprintf(name, sizeof(em_long_string_t), "%s", DE_SERVICES);
        rbusTable_addRow(m_bus_handle, name, alias, &inst);
    }

    snprintf(name, sizeof(em_long_string_t), "%s%d.Type", DE_SERVICES, pos);
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, svc.m_type);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);

    snprintf(name, sizeof(em_long_string_t), "%s%d.Operator", DE_SERVICES, pos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, svc.m_operator_name);
    printf("%s:%d: Operator: %s\n", __func__, __LINE__, svc.m_operator_name);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.URL", DE_SERVICES, pos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, svc.m_url);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
}

optimizer_type_t de_services_t::get_operator_type()
{
    de_service_t *svc = NULL;
    optimizer_type_t type = optimizer_type_generic;

    svc = (de_service_t *)hash_map_get_first(m_service_map);
    while (svc != NULL) {
        printf("%s:%d: Service: %d, Operator: %s\n", __func__, __LINE__, svc->m_type, svc->m_operator_name);
        if (svc->m_type == service_type_optimizer) {
            if (strncasecmp(svc->m_operator_name, "comcast", strlen("comcast")) == 0) {
                type = optimizer_type_comcast;
            } else if (strncasecmp(svc->m_operator_name, "vodafone", strlen("vodafone")) == 0) {
                type = optimizer_type_vodafone;
            } else if (strncasecmp(svc->m_operator_name, "dt", strlen("dt")) == 0) {
                type = optimizer_type_dt;
            } else {
                type = optimizer_type_generic;
            }
            break;
        }

        svc = (de_service_t *)hash_map_get_next(m_service_map, svc);
    }

    printf("%s:%d: Operator Type: %d, count: %d\n", __func__, __LINE__, type, hash_map_count(m_service_map));

    return type; 
}

char *de_services_t::get_url()
{
    de_service_t *svc = NULL;
    char *ptr = NULL;

    svc = (de_service_t *)hash_map_get_first(m_service_map);
    while (svc != NULL) {

        if (svc->m_type == service_type_optimizer) {
            ptr = svc->m_url;
            break;
        }

        svc = (de_service_t *)hash_map_get_next(m_service_map, svc);
    }

    return ptr;
}


rbusError_t de_services_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    unsigned int row;
    de_service_t *svc;
    
    printf("%s:%d: name: %s, alias: %s\n", __func__, __LINE__, table_name, alias_name);
    sscanf(alias_name, "X_RDK_Services.%d", &row);

    svc = new de_service_t();
    svc->init(alias_name);
    hash_map_put(m_service_map, strdup(alias_name), svc);

    *inst_num = row;

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_services_t::remove(rbusHandle_t handle, char const* row_name)
{
    printf("%s:%d: name: %s, row: %s\n", __func__, __LINE__, row_name);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_services_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    em_string_t str = {0}, key = {0};
    unsigned int inst;
    int len;
    de_service_t *svc;
    const char *name, *ptr;

    name  = rbusProperty_GetName(property);
    printf("%s:%d: Property Name: %s\n", __func__, __LINE__, name);

    snprintf(key, sizeof(em_string_t), "%s.", DE_SERVICES);

    if ((ptr = strstr(name, key)) == NULL) {
        return RBUS_ERROR_INVALID_OPERATION;
    }

    sscanf(ptr, "X_RDK_Services.%d.%s", &inst, str);
    snprintf(key, sizeof(em_string_t), "%s.%d", SERVICES, inst);

    if ((svc = (de_service_t *)hash_map_get(m_service_map, key)) == NULL) {
        printf("%s:%d: Could not find object\n", __func__, __LINE__);
        return RBUS_ERROR_INVALID_HANDLE;
    }

    if (strncmp(str, "Type", strlen("Type")) == 0) {
        rbusProperty_SetUInt32(property, (uint32_t)svc->m_type);
    } else if (strncmp(str, "Operator", strlen("Operator")) == 0) {
        rbusProperty_SetString(property, svc->m_operator_name);
    } else if (strncmp(str, "URL", strlen("URL")) == 0) {
        rbusProperty_SetString(property, svc->m_url);
    }

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_services_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    em_string_t str, key;
    unsigned int inst;
    int len;
    de_service_t *svc;
    const char *name, *ptr;

    name  = rbusProperty_GetName(property);

    snprintf(key, sizeof(em_string_t), "%s.", DE_SERVICES);
    
    if ((ptr = strstr(name, key)) == NULL) {
        return RBUS_ERROR_INVALID_OPERATION;
    }
   
    ptr += strlen(DE_NETWORK); 
    sscanf(ptr, "X_RDK_Services.%d.%s", &inst, str);
    snprintf(key, sizeof(em_string_t), "%s.%d", SERVICES, inst);
        
    if ((svc = (de_service_t *)hash_map_get(m_service_map, key)) == NULL) {
        printf("%s:%d: Could not find object\n", __func__, __LINE__);
        return RBUS_ERROR_INVALID_HANDLE;
    }

    if (strncmp(str, "Type", strlen("Type")) == 0) {
        svc->m_type = (service_type_t)rbusProperty_GetUInt32(property);
    } else if (strncmp(str, "Operator", strlen("Operator")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(svc->m_operator_name, ptr, len + 1);
    } else if (strncmp(str, "URL", strlen("URL")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(svc->m_url, ptr, len + 1);
    }

    return RBUS_ERROR_SUCCESS;
}

void de_services_t::publish(const char *name)
{
    int rc, inst;
    de_service_t *svc;
    rbusEvent_t event = {0};
    rbusValue_t value;
    rbusObject_t data, row;

    if (strncmp(name, SERVICES, strlen(SERVICES)) != 0) {
        return;
    }

    rbusObject_Init(&data, NULL);

    svc = (de_service_t *)hash_map_get_first(m_service_map);
    while (svc != NULL) {
        rbusObject_Init(&row, svc->m_key);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, svc->m_type);
        rbusObject_SetValue(row, "Type", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, svc->m_operator_name);
        rbusObject_SetValue(row, "Operator", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, svc->m_url);
        rbusObject_SetValue(row, "URL", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetObject(value, row);
        rbusObject_Release(row);
 
        rbusObject_SetValue(data, svc->m_key, value);
        rbusValue_Release(value);
    
        svc = (de_service_t *)hash_map_get_next(m_service_map, svc);
    }

        
    event.name = name;;
    event.data = data;
    event.type = RBUS_EVENT_GENERAL;

    if ((rc = rbusEvent_Publish(m_bus_handle, &event)) != RBUS_ERROR_SUCCESS) {
        printf("%s:%d: Failed to publish data for event: %s, err: %d\n", __func__, __LINE__,
            event.name, rc);
    } else {
        printf("%s:%d: Successfully published data for event: %s\n", __func__, __LINE__, event.name);
    }

    rbusObject_Release(data);
       
}


void de_services_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    rbusValue_t value;
    rbusObject_t row;
    rbusProperty_t prop;
    
    const char *ptr; 
    de_service_t *svc;


    if (strncmp(subscription->eventName, SERVICES, strlen(SERVICES)) != 0) {
        printf("%s:%d: Unknown event: %s\n", __func__, __LINE__, event->name);
        return;
    }

    prop = rbusObject_GetProperties(event->data);
    printf("%s:%d: Event Name: %s, prop: %p\n", __func__, __LINE__, subscription->eventName, prop);
    while (prop != NULL) {
        ptr = rbusProperty_GetName(prop);

        if ((svc = (de_service_t *)hash_map_get(m_service_map, ptr)) == NULL) {
            svc = new de_service_t();
            svc->init(ptr);
            hash_map_put(m_service_map, strdup(ptr), svc);
        }

        row = rbusProperty_GetObject(prop);

        if ((value = rbusObject_GetValue(row, "Type")) == NULL) {
            printf("%s:%d: Could not find Type value\n", __func__, __LINE__);
        } else {
            svc->m_type = (service_type_t)rbusValue_GetUInt32(value);
        }

        if ((value = rbusObject_GetValue(row, "Operator")) == NULL) {
            printf("%s:%d: Could not find Operator value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(svc->m_operator_name, ptr, strlen(ptr) + 1);     
        }

        if ((value = rbusObject_GetValue(row, "URL")) == NULL) {
            printf("%s:%d: Could not find URL value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(svc->m_url, ptr, strlen(ptr) + 1);     
        }

        prop = rbusProperty_GetNext(prop);
        
    }

}

int de_services_t::init(rbusHandle_t handle)
{
    m_service_map = hash_map_create();
    
    m_elems[m_num_elems].name = SERVICES;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_SERVICES_TABLE;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_TABLE;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_SERVICES_TYPE;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_SERVICES_OPERATOR;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;
    
    m_elems[m_num_elems].name = DE_SERVICES_URL;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_subs[m_num_subs].eventName = SERVICES;
    m_num_subs++;

#ifdef FUTURE
    m_subs[m_num_subs].eventName = DE_SERVICES_ANY_TYPE;
    m_num_subs++;

    m_subs[m_num_subs].eventName = DE_SERVICES_ANY_OPERATOR;
    m_num_subs++;

    m_subs[m_num_subs].eventName = DE_SERVICES_ANY_URL;
    m_num_subs++;
#endif

    return de_t::init(handle);
}

void de_services_t::deinit(bool bus_close)
{
    if (m_service_map != NULL) {
        hash_map_destroy(m_service_map);
    }
    de_t::deinit(bus_close);
}

de_services_t::de_services_t(const char *name, bool provider, notifier_t func)
{
    strncpy(m_name, name, strlen(name));
    m_provider = provider; 
    m_func = func;
    m_service_map = NULL;
}

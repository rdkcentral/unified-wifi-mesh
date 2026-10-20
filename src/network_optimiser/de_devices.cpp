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
#include "de_devices.h"
#include "optimizer.h"

void de_devices_t::update(de_device_t& dev, unsigned int pos)
{
    rbusValue_t value;
    em_long_string_t name = {0};
    unsigned int inst;
    de_device_t *pdev;
    em_string_t alias = {0};

    snprintf(name, sizeof(em_long_string_t), "%s", DE_DEVICES);
    snprintf(alias, sizeof(em_string_t), "%s.%d", DEVICES, pos);


    if ((pdev = (de_device_t *)hash_map_get(m_device_map, alias)) == NULL) {
        rbusTable_addRow(m_bus_handle, name, alias, &inst);
    }

    snprintf(name, sizeof(em_long_string_t), "%s%d.ID", DE_DEVICES, pos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, dev.m_id);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);

    snprintf(name, sizeof(em_long_string_t), "%s%d.Manufacturer", DE_DEVICES, pos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, dev.m_manufacturer);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);

    snprintf(name, sizeof(em_long_string_t), "%s%d.ManufacturerModel", DE_DEVICES, pos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, dev.m_model);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.SerialNumber", DE_DEVICES, pos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, dev.m_serial);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.SoftwareVersion", DE_DEVICES, pos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, dev.m_version);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
}


rbusError_t de_devices_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    unsigned int row;
    de_device_t *dev;

    printf("%s:%d: name: %s, alias: %s\n", __func__, __LINE__, table_name, alias_name);
    sscanf(alias_name, "DeviceList.%d", &row);

    dev = new de_device_t();
    dev->init();

    hash_map_put(m_device_map, strdup(alias_name), dev);

    *inst_num = row;

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_devices_t::remove(rbusHandle_t handle, char const* row_name)
{
    printf("%s:%d: name: %s, row: %s\n", __func__, __LINE__, row_name);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_devices_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    em_string_t str = {0}, key = {0};
    unsigned int inst;
    int len;
    de_device_t *dev;
    const char *name, *ptr;

    name  = rbusProperty_GetName(property);
    printf("%s:%d: Property Name: %s\n", __func__, __LINE__, name);

    snprintf(key, sizeof(em_string_t), "%s.", DE_DEVICES);

    if ((ptr = strstr(name, key)) == NULL) {
        printf("%s:%d: Could not find data for key: %s\n", __func__, __LINE__, key);
        return RBUS_ERROR_INVALID_OPERATION;
    }

    sscanf(ptr, "DeviceList.%d.%s", &inst, str);
    snprintf(key, sizeof(em_string_t), "%s.%d", DEVICES, inst);

    if ((dev = (de_device_t *)hash_map_get(m_device_map, key)) == NULL) {
        printf("%s:%d: Could not find object\n", __func__, __LINE__);
        return RBUS_ERROR_INVALID_HANDLE;
    }

    if (strncmp(str, "ID", strlen("ID")) == 0) {
        rbusProperty_SetString(property, dev->m_id);
    } else if (strncmp(str, "Manufacturer", strlen("Manufacturer")) == 0) {
        rbusProperty_SetString(property, dev->m_manufacturer);
    } else if (strncmp(str, "SerialNumber", strlen("SerialNumber")) == 0) {
        rbusProperty_SetString(property, dev->m_serial);
    } else if (strncmp(str, "ManufacturerModel", strlen("ManufacturerModel")) == 0) {
        rbusProperty_SetString(property, dev->m_model);
    } else if (strncmp(str, "SoftwareVersion", strlen("SoftwareVersion")) == 0) {
        //rbusProperty_SetString(property, dev->m_version);
    }


    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_devices_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    em_string_t str, key;
    unsigned int inst;
    int len;
    de_device_t *dev;
    const char *name, *ptr;

    name  = rbusProperty_GetName(property);
    printf("%s:%d: Property Name: %s\n", __func__, __LINE__, name);

    snprintf(key, sizeof(em_string_t), "%s.", DE_DEVICES);

    if ((ptr = strstr(name, key)) == NULL) {
        return RBUS_ERROR_INVALID_OPERATION;
    }

    sscanf(ptr, "DeviceList.%d.%s", &inst, str);
    snprintf(key, sizeof(em_string_t), "%s.%d", DEVICES, inst);

    if ((dev = (de_device_t *)hash_map_get(m_device_map, key)) == NULL) {
        printf("%s:%d: Could not find object\n", __func__, __LINE__);
        return RBUS_ERROR_INVALID_HANDLE;
    }

    if (strncmp(str, "ID", strlen("ID")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(dev->m_id, ptr, len + 1);
    } else if (strncmp(str, "Manufacturer", strlen("Manufacturer")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(dev->m_manufacturer, ptr, len + 1);
    } else if (strncmp(str, "SerialNumber", strlen("SerialNumber")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        if (ptr == NULL || len < 0) {
            return RBUS_ERROR_INVALID_INPUT;
        }
        size_t copy_len = (len < static_cast<int>(sizeof(dev->m_serial) - 1)) ?
            static_cast<size_t>(len) : sizeof(dev->m_serial) - 1;
        memcpy(dev->m_serial, ptr, copy_len);
        dev->m_serial[copy_len] = '\0';
    } else if (strncmp(str, "ManufacturerModel", strlen("ManufacturerModel")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(dev->m_model, ptr, len + 1);
    } else if (strncmp(str, "SoftwareVersion", strlen("SoftwareVersion")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(dev->m_serial, ptr, len + 1);
    }

    return RBUS_ERROR_SUCCESS;
}

de_device_t *de_devices_t::get_device(de_device_t& dev)
{
    de_device_t *pd;
    bool found = false;

    pd = (de_device_t *)hash_map_get_first(m_device_map);
    while (pd) {
        if (strncmp(pd->m_id, dev.m_id, strlen(dev.m_id)) == 0) {
            found = true;
            break;
        }
        pd = (de_device_t *)hash_map_get_next(m_device_map, pd);
    }

    return (found == true) ? pd:NULL; 
}

void de_devices_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{

}

int de_devices_t::init()
{
    m_device_map = hash_map_create();
    
    m_elems[m_num_elems].name = DE_DEVICES_TABLE;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_TABLE;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_DEVICES_ID;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_DEVICES_MANUFACTURER;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;
    
    m_elems[m_num_elems].name = DE_DEVICES_MODEL;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_DEVICES_SERIAL;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_DEVICES_VERSION;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_subs[m_num_subs].eventName = DE_DEVICES_ANY_ID;
    m_num_subs++;

    m_subs[m_num_subs].eventName = DE_DEVICES_ANY_MANUFACTURER;
    m_num_subs++;

    m_subs[m_num_subs].eventName = DE_DEVICES_ANY_MODEL;
    m_num_subs++;

    m_subs[m_num_subs].eventName = DE_DEVICES_ANY_SERIAL;
    m_num_subs++;

    m_subs[m_num_subs].eventName = DE_DEVICES_ANY_VERSION;
    m_num_subs++;


    return de_t::init();
}

void de_devices_t::deinit()
{
    hash_map_destroy(m_device_map);
}

de_devices_t::de_devices_t(const char *name, bool provider, notifier_t func)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
    m_func = func;
}

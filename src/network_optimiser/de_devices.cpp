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

void de_devices_t::update(de_radio_t& rd, unsigned int dpos, unsigned int rpos)
{
    m_de_radios->update(rd, dpos, rpos);
}

void de_devices_t::update(de_bss_t& bss, unsigned int dpos, unsigned int rpos, unsigned int bpos)
{
    m_de_radios->update(bss, dpos, rpos, bpos);
}

void de_devices_t::update(de_sta_t& sta, unsigned int dpos, unsigned int rpos, unsigned int bpos, unsigned int spos)
{
    m_de_radios->update(sta, dpos, rpos, bpos, spos);
}

void de_devices_t::update(de_device_t& dev, unsigned int pos)
{
    rbusValue_t value;
    em_long_string_t name = {0};
    unsigned int inst;
    de_device_t *pdev;
    em_string_t alias = {0};

    snprintf(alias, sizeof(em_string_t), "%s.%d", DEVICES, pos);

    if ((pdev = (de_device_t *)hash_map_get(m_device_map, alias)) == NULL) {
        snprintf(name, sizeof(em_long_string_t), "%s", DE_DEVICES);
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

    if (strstr(table_name, RADIOS) != NULL) {
        return m_de_radios->add(handle, table_name, alias_name, inst_num);
    }

    sscanf(alias_name, "DeviceList.%d", &row);

    dev = new de_device_t();
    dev->init(alias_name);

    hash_map_put(m_device_map, strdup(alias_name), dev);

    *inst_num = row;

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_devices_t::remove(rbusHandle_t handle, char const* row_name)
{
    if (strstr(row_name, RADIOS) != NULL) {
        return m_de_radios->remove(handle, row_name);
    }

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
    if (strstr(name, RADIOS) != NULL) {
        return m_de_radios->get(handle, property, options);
    }

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
    if (strstr(name, RADIOS) != NULL) {
        return m_de_radios->set(handle, property, options);
    }


    snprintf(key, sizeof(em_string_t), "%s.", DE_DEVICES);

    if ((ptr = strstr(name, key)) == NULL) {
        return RBUS_ERROR_INVALID_OPERATION;
    }

    ptr += strlen(DE_NETWORK);

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

void de_devices_t::publish(const char *name)
{
    int rc, inst;
    de_device_t *dev;
    rbusEvent_t event = {0};
    rbusValue_t value;
    rbusObject_t data, row;

    if ((strncmp(name, RADIOS, strlen(RADIOS)) == 0) || (strncmp(name, BSSS, strlen(BSSS)) == 0) ||
            (strncmp(name, STAS, strlen(STAS)) == 0)) {
        m_de_radios->publish(name);
        return;
    } else if (strncmp(name, DEVICES, strlen(DEVICES)) != 0) {
        printf("%s:%d: Name mismatch, name: %s\n", __func__, __LINE__, name);
        return;
    }

    rbusObject_Init(&data, NULL);

    dev = (de_device_t *)hash_map_get_first(m_device_map);
    while (dev != NULL) {
        rbusObject_Init(&row, dev->m_key);

        rbusValue_Init(&value);
        rbusValue_SetString(value, dev->m_id);
        rbusObject_SetValue(row, "ID", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, dev->m_manufacturer);
        rbusObject_SetValue(row, "Manufacturer", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, dev->m_model);
        rbusObject_SetValue(row, "ManufacturerModel", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, dev->m_serial);
        rbusObject_SetValue(row, "SerialNumber", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, dev->m_version);
        rbusObject_SetValue(row, "SoftwareVersion", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetObject(value, row);
        rbusObject_Release(row);

        rbusObject_SetValue(data, dev->m_key, value);
        rbusValue_Release(value);

        dev = (de_device_t *)hash_map_get_next(m_device_map, dev);
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


void de_devices_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    rbusValue_t value;
    rbusObject_t row;
    rbusProperty_t prop;

    const char *ptr;
    de_device_t *dev;

    if (strncmp(event->name, DEVICES, strlen(DEVICES)) != 0) {
        printf("%s:%d: Unknown event: %s\n", __func__, __LINE__, event->name);
        return;
    }

    prop = rbusObject_GetProperties(event->data);
    while (prop != NULL) {
        ptr = rbusProperty_GetName(prop);

        if ((dev = (de_device_t *)hash_map_get(m_device_map, ptr)) == NULL) {
            dev = new de_device_t();
            dev->init(ptr);
            hash_map_put(m_device_map, strdup(ptr), dev);
        }

        row = rbusProperty_GetObject(prop);

        if ((value = rbusObject_GetValue(row, "ID")) == NULL) {
            printf("%s:%d: Could not find Type value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(dev->m_id, ptr, strlen(ptr) + 1);
        }

        if ((value = rbusObject_GetValue(row, "Manufacturer")) == NULL) {
            printf("%s:%d: Could not find Operator value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(dev->m_manufacturer, ptr, strlen(ptr) + 1);
        }

        if ((value = rbusObject_GetValue(row, "ManufacturerModel")) == NULL) {
            printf("%s:%d: Could not find URL value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(dev->m_model, ptr, strlen(ptr) + 1);
        }

        if ((value = rbusObject_GetValue(row, "SerialNumber")) == NULL) {
            printf("%s:%d: Could not find URL value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(dev->m_serial, ptr, strlen(ptr) + 1);
        }

        if ((value = rbusObject_GetValue(row, "SoftwareVersion")) == NULL) {
            printf("%s:%d: Could not find URL value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(dev->m_version, ptr, strlen(ptr) + 1);
        }

        prop = rbusProperty_GetNext(prop);

    }

}

int de_devices_t::init()
{
    m_device_map = hash_map_create();

    m_elems[m_num_elems].name = DEVICES;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;
    
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

    m_subs[m_num_subs].eventName = DEVICES;
    m_num_subs++;

#ifdef FUTURE
    m_subs[m_num_subs].eventName = DE_DEVICES_ANY_ID;
    m_num_subs++;

    m_subs[m_num_subs].eventName = DE_DEVICES_ANY_MANUFACTURER;
    m_num_subs++;

    m_subs[m_num_subs].eventName = DE_DEVICES_ANY_MODEL;
    m_num_subs++;

    m_subs[m_num_subs].eventName = DE_DEVICES_ANY_IAL;
    m_num_subs++;

    m_subs[m_num_subs].eventName = DE_DEVICES_ANY_VERSION;
    m_num_subs++;
#endif

    if (de_t::init() != 0) {
        printf("%s:%d: Failed to initialize devices\n", __func__, __LINE__);
        return -1;
    }

    m_de_radios = new de_radios_t(RADIOS, m_provider, m_func);

    return m_de_radios->init(m_bus_handle); 
}

void de_devices_t::deinit()
{
    m_de_radios->deinit(false);
    hash_map_destroy(m_device_map);
    de_t::deinit();
}

de_devices_t::de_devices_t(const char *name, bool provider, notifier_t func)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
    m_func = func;
}

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
#include "de_radios.h"
#include "de_device.h"
#include "optimizer.h"

void de_radios_t::update(de_sta_t& sta, unsigned int dpos, unsigned int rpos, unsigned int bpos, unsigned int spos)
{
    m_de_bsss->update(sta, dpos, rpos, bpos, spos);
}

void de_radios_t::update(de_bss_t& bss, unsigned int dpos, unsigned int rpos, unsigned int bpos)
{
    m_de_bsss->update(bss, dpos, rpos, bpos);
}

void de_radios_t::update(de_radio_t& radio, unsigned int dpos, unsigned int rpos)
{
    rbusValue_t value;
    em_long_string_t name = {0};
    unsigned int inst;
    de_radio_t *prd = NULL;
    em_string_t alias = {0};

    snprintf(alias, sizeof(em_string_t), "%s.%d.%s.%d", DEVICES, dpos, RADIOS, rpos);
    if ((prd = (de_radio_t *)hash_map_get(m_radio_map, alias)) == NULL) { 
        snprintf(name, sizeof(em_long_string_t), "%s%d.%s.", DE_DEVICES, dpos, RADIOS);
        printf("%s:%d: adding row, name: %s, alias: %s\n", __func__, __LINE__, name, alias);
        rbusTable_addRow(m_bus_handle, name, alias, &inst);
        prd = (de_radio_t *)hash_map_get(m_radio_map, alias);
    }

    if (prd != NULL) {
        prd->update(radio);
    }
       
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.ID", DE_DEVICES, dpos, RADIOS, rpos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, radio.m_id);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.Noise", DE_DEVICES, dpos, RADIOS, rpos);
    rbusValue_Init(&value);
    rbusValue_SetInt32(value, radio.m_noise);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.Utilization", DE_DEVICES, dpos, RADIOS, rpos);
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, radio.m_util);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.Enabled", DE_DEVICES, dpos, RADIOS, rpos);
    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, radio.m_enabled);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
}


rbusError_t de_radios_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    unsigned int dpos, rpos;
    de_radio_t *radio;

    if (strstr(table_name, BSSS) != NULL) {
        return m_de_bsss->add(handle, table_name, alias_name, inst_num);
    }

    sscanf(alias_name, "DeviceList.%d.RadioList.%d", &dpos, &rpos);

    if ((radio = (de_radio_t *)hash_map_get(m_radio_map, alias_name)) == NULL) {
        radio = new de_radio_t();
        radio->init(alias_name);

        hash_map_put(m_radio_map, strdup(alias_name), radio);
    }

    *inst_num = rpos;

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_radios_t::remove(rbusHandle_t handle, char const* row_name)
{
    if (strstr(row_name, BSSS) != NULL) {
        return m_de_bsss->remove(handle, row_name);
    }
    
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_radios_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_radios_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    em_string_t str, key;
    unsigned int dpos, rpos;
    int len;
    de_radio_t *rd;
    const char *name, *ptr;

    name  = rbusProperty_GetName(property);
    if (strstr(name, BSSS) != NULL) {
        return m_de_bsss->set(handle, property, options);
    }

    snprintf(key, sizeof(em_string_t), "%s.", DE_DEVICES);

    if ((ptr = strstr(name, key)) == NULL) {
        return RBUS_ERROR_INVALID_OPERATION;
    }

    ptr += strlen(DE_DEVICES);

    sscanf(ptr, "%d.RadioList.%d.%s", &dpos, &rpos, str);
    snprintf(key, sizeof(em_string_t), "DeviceList.%d.RadioList.%d", dpos, rpos);

    if ((rd = (de_radio_t *)hash_map_get(m_radio_map, key)) == NULL) {
        printf("%s:%d: Could not find radio at key: %s\n", __func__, __LINE__, key);
        return RBUS_ERROR_INVALID_HANDLE;
    }

    if (strncmp(str, "ID", strlen("ID")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(rd->m_id, ptr, len + 1);
    } else if (strncmp(str, "Enabled", strlen("Enabled")) == 0) {
        rd->m_enabled = rbusProperty_GetBoolean(property);
    } else if (strncmp(str, "Utilization", strlen("Utilization")) == 0) {
        rd->m_util = rbusProperty_GetUInt32(property);
    } else if (strncmp(str, "Noise", strlen("Noise")) == 0) {
        rd->m_noise = rbusProperty_GetInt32(property);
    }

    return RBUS_ERROR_SUCCESS;
}

void de_radios_t::publish(const char *name)
{
    int rc, inst;
    de_radio_t *rd;
    rbusEvent_t event = {0};
    rbusValue_t value;
    rbusObject_t data, row;

    if ((strncmp(name, BSSS, strlen(BSSS)) == 0) || (strncmp(name, STAS, strlen(STAS)) == 0)) {
        m_de_bsss->publish(name);
        return;
    } else if (strncmp(name, RADIOS, strlen(RADIOS)) != 0) {
        return;
    }

    rbusObject_Init(&data, NULL);

    rd = (de_radio_t *)hash_map_get_first(m_radio_map);
    while (rd != NULL) {
        rbusObject_Init(&row, rd->m_key);

        rbusValue_Init(&value);
        rbusValue_SetString(value, rd->m_id);
        rbusObject_SetValue(row, "ID", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetBoolean(value, rd->m_enabled);
        rbusObject_SetValue(row, "Enabled", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, rd->m_util);
        rbusObject_SetValue(row, "Utilization", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetInt32(value, rd->m_noise);
        rbusObject_SetValue(row, "Noise", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetObject(value, row);
        rbusObject_Release(row);

        rbusObject_SetValue(data, rd->m_key, value);
        rbusValue_Release(value);

        rd = (de_radio_t *)hash_map_get_next(m_radio_map, rd);
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

void de_radios_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    rbusValue_t value;
    rbusObject_t row;
    rbusProperty_t prop;

    const char *ptr;
    de_radio_t *rd;

    if (strncmp(event->name, RADIOS, strlen(RADIOS)) != 0) {
        printf("%s:%d: Unknown event: %s\n", __func__, __LINE__, event->name);
        return;
    }

    prop = rbusObject_GetProperties(event->data);
    while (prop != NULL) {
        ptr = rbusProperty_GetName(prop);

        if ((rd = (de_radio_t *)hash_map_get(m_radio_map, ptr)) == NULL) {
            rd = new de_radio_t();
            rd->init(ptr);
            hash_map_put(m_radio_map, strdup(ptr), rd);
        }

        row = rbusProperty_GetObject(prop);

        if ((value = rbusObject_GetValue(row, "ID")) == NULL) {
            printf("%s:%d: Could not find Type value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(rd->m_id, ptr, strlen(ptr) + 1);
        }

        if ((value = rbusObject_GetValue(row, "Enabled")) == NULL) {
            printf("%s:%d: Could not find Operator value\n", __func__, __LINE__);
        } else {
            rd->m_enabled = rbusValue_GetBoolean(value);
        }

        if ((value = rbusObject_GetValue(row, "Utilization")) == NULL) {
            printf("%s:%d: Could not find Utilization value\n", __func__, __LINE__);
        } else {
            rd->m_util = rbusValue_GetUInt32(value);
        }

        if ((value = rbusObject_GetValue(row, "Noise")) == NULL) {
            printf("%s:%d: Could not find Noise value\n", __func__, __LINE__);
        } else {
            rd->m_noise = rbusValue_GetInt32(value);
        }

        prop = rbusProperty_GetNext(prop);
    }

}

int de_radios_t::init(rbusHandle_t handle)
{
    m_radio_map = hash_map_create();

    m_elems[m_num_elems].name = RADIOS;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;
    
    m_elems[m_num_elems].name = DE_RADIOS_TABLE;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_TABLE;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_RADIOS_ID;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_RADIOS_ENABLED;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_subs[m_num_subs].eventName = RADIOS;
    m_num_subs++;

    if (de_t::init(handle) != 0) {
        printf("%s:%d: Failed to initialize radios\n", __func__, __LINE__);
        return -1;
    }

    m_de_bsss = new de_bsss_t(BSSS, m_provider, m_func);

    return m_de_bsss->init(handle);
}

void de_radios_t::deinit(bool bus_close)
{
    m_de_bsss->deinit(false);
    hash_map_destroy(m_radio_map);
    de_t::deinit(false);
}

de_radios_t::de_radios_t(const char *name, bool provider, notifier_t func)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
    m_func = func;
}

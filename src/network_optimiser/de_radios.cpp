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

void de_radios_t::update(de_radio_t& radio, unsigned int dpos, unsigned int rpos)
{
    rbusValue_t value;
    em_long_string_t name = {0};
    unsigned int inst;
    de_radio_t *prd = NULL;
    em_string_t alias = {0};

    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.", DE_DEVICES, dpos, DE_RADIOS);
    snprintf(alias, sizeof(em_string_t), "%s.%d.%s.%d", DEVICES, dpos, RADIOS, rpos);
    if ((prd = (de_radio_t *)hash_map_get(m_radio_map, alias)) == NULL) { 
        rbusTable_addRow(m_bus_handle, name, alias, &inst);
    }
       
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.ID", DE_DEVICES, dpos, DE_RADIOS, rpos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, radio.m_id);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.Enabled", DE_DEVICES, dpos, DE_RADIOS, rpos);
    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, radio.m_enabled);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
}


rbusError_t de_radios_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    unsigned int row, pos;
    de_radio_t *radio;

    printf("%s:%d: name: %s, alias: %s\n", __func__, __LINE__, table_name, alias_name);

    sscanf(alias_name, "DeviceList.%d.RadioList.%d", &pos, &row);

    radio = new de_radio_t();
    radio->init();

    hash_map_put(m_radio_map, strdup(alias_name), radio);

    *inst_num = row;


    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_radios_t::remove(rbusHandle_t handle, char const* row_name)
{
    printf("%s:%d: name: %s, row: %s\n", __func__, __LINE__, row_name);

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
    printf("%s:%d: Property Name: %s\n", __func__, __LINE__, name);

    snprintf(key, sizeof(em_string_t), "%s.", DE_DEVICES);

    if ((ptr = strstr(name, key)) == NULL) {
        return RBUS_ERROR_INVALID_OPERATION;
    }

    sscanf(ptr, "DeviceList.%d.RadioList.%d.%s", &dpos, &rpos, str);
    snprintf(key, sizeof(em_string_t), "DeviceList.%d.RadioList.%d", dpos, rpos);

    if ((rd = (de_radio_t *)hash_map_get(m_radio_map, key)) == NULL) {
        printf("%s:%d: Could not find radio at ley: %s\n", __func__, __LINE__, key);
        return RBUS_ERROR_INVALID_HANDLE;
    }

    if (strncmp(str, "ID", strlen("ID")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(rd->m_id, ptr, len + 1);
    } else if (strncmp(str, "Enabled", strlen("Enabled")) == 0) {
        rd->m_enabled = rbusProperty_GetBoolean(property);
    }

    return RBUS_ERROR_SUCCESS;
}

void de_radios_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{

}

int de_radios_t::init()
{
    m_radio_map = hash_map_create();
    
    m_elems[m_num_elems].name = DE_RADIOS_TABLE;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_TABLE;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_RADIOS_ID;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_RADIOS_ENABLED;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    return de_t::init();
}

void de_radios_t::deinit()
{
    hash_map_destroy(m_radio_map);
}

de_radios_t::de_radios_t(const char *name, bool provider)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
}

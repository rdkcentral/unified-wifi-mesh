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
#include "de_bsss.h"
#include "optimizer.h"

void de_bsss_t::update(de_sta_t& sta, unsigned int dpos, unsigned int rpos, unsigned int bpos, unsigned int spos)
{
    m_de_stas->update(sta, dpos, rpos, bpos, spos);
}

void de_bsss_t::update(de_bss_t& bss, unsigned int dpos, unsigned int rpos, unsigned int bpos)
{
    rbusValue_t value;
    em_long_string_t name = {0};
    unsigned int inst;
    de_bss_t *pbss = NULL;
    em_long_string_t alias = {0};

    snprintf(alias, sizeof(em_long_string_t), "%s.%d.%s.%d.%s.%d", DEVICES, dpos, RADIOS, rpos, BSSS, bpos);
    if ((pbss = (de_bss_t *)hash_map_get(m_bss_map, alias)) == NULL) { 
        snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.", DE_DEVICES, dpos, RADIOS, rpos, BSSS);
        printf("%s:%d: adding row, name: %s, alias: %s\n", __func__, __LINE__, name, alias);
        rbusTable_addRow(m_bus_handle, name, alias, &inst);
        pbss = (de_bss_t *)hash_map_get(m_bss_map, alias);
    }

    if (pbss != NULL) {
        pbss->update(bss);
    }
       
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.BSSID", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, bss.m_bssid);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.SSID", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, bss.m_ssid);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.Enabled", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos);
    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, bss.m_enabled);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.TransmittedBSSID", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos);
    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, bss.m_broadcast);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);

    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.FronthaulUse", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos);
    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, bss.m_fronthaul);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);

    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.BackhaulUse", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos);
    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, bss.m_backhaul);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
}


rbusError_t de_bsss_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    unsigned int dpos, rpos, bpos;
    de_bss_t *bss;

    if (strstr(table_name, STAS) != NULL) {
        return m_de_stas->add(handle, table_name, alias_name, inst_num);
    }
    
    sscanf(alias_name, "DeviceList.%d.RadioList.%d.BSSList.%d", &dpos, &rpos, &bpos);
    printf("%s:%d: Name: %s\n", __func__, __LINE__, alias_name);

    if ((bss = (de_bss_t *)hash_map_get(m_bss_map, alias_name)) == NULL) {
        bss = new de_bss_t();
        bss->init(alias_name);

        hash_map_put(m_bss_map, strdup(alias_name), bss);
    }

    *inst_num = bpos;

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_bsss_t::remove(rbusHandle_t handle, char const* row_name)
{
    if (strstr(row_name, STAS) != NULL) {
        return m_de_stas->remove(handle, row_name);
    }

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_bsss_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_bsss_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    em_string_t str; 
    em_long_string_t key;
    unsigned int dpos, rpos, bpos;
    int len;
    de_bss_t *bss;
    const char *name, *ptr;

    name  = rbusProperty_GetName(property);
    if (strstr(name, STAS) != NULL) {
        return m_de_stas->set(handle, property, options);
    }

    snprintf(key, sizeof(em_long_string_t), "%s", DE_DEVICES);

    if ((ptr = strstr(name, key)) == NULL) {
        printf("%s:%d: Substring(%s) not found in %s\n", __func__, __LINE__, key, name);
        return RBUS_ERROR_INVALID_OPERATION;
    }

    ptr += strlen(DE_DEVICES);

    sscanf(ptr, "%d.RadioList.%d.BSSList.%d.%s", &dpos, &rpos, &bpos, str);
    snprintf(key, sizeof(em_long_string_t), "DeviceList.%d.RadioList.%d.BSSList.%d", dpos, rpos, bpos);

    if ((bss = (de_bss_t *)hash_map_get(m_bss_map, key)) == NULL) {
        printf("%s:%d: Could not find radio at key: %s\n", __func__, __LINE__, key);
        return RBUS_ERROR_INVALID_HANDLE;
    }

    if (strncmp(str, "BSSID", strlen("BSSID")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(bss->m_bssid, ptr, len + 1);
    } else if (strncmp(str, "SSID", strlen("SSID")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(bss->m_ssid, ptr, len + 1);
    } else if (strncmp(str, "Enabled", strlen("Enabled")) == 0) {
        bss->m_enabled = rbusProperty_GetBoolean(property);
    } else if (strncmp(str, "TransmittedBSSID", strlen("TransmittedBSSID")) == 0) {
        bss->m_broadcast = rbusProperty_GetBoolean(property);
    } else if (strncmp(str, "FronthaulUse", strlen("FronthaulUse")) == 0) {
        bss->m_fronthaul = rbusProperty_GetBoolean(property);
    } else if (strncmp(str, "BackhaulUse", strlen("BackhaulUse")) == 0) {
        bss->m_backhaul = rbusProperty_GetBoolean(property);
    }

    return RBUS_ERROR_SUCCESS;
}

void de_bsss_t::publish(const char *name)
{
    int rc, inst;
    de_bss_t *bss;
    rbusEvent_t event = {0};
    rbusValue_t value;
    rbusObject_t data, row;

    if (strncmp(name, STAS, strlen(STAS)) == 0) { 
        m_de_stas->publish(name);
        return;
    } else if (strncmp(name, BSSS, strlen(BSSS)) != 0) {
        return;
    }

    rbusObject_Init(&data, NULL);

    bss = (de_bss_t *)hash_map_get_first(m_bss_map);
    while (bss != NULL) {
        rbusObject_Init(&row, bss->m_key);

        rbusValue_Init(&value);
        rbusValue_SetString(value, bss->m_bssid);
        rbusObject_SetValue(row, "BSSID", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, bss->m_ssid);
        rbusObject_SetValue(row, "SSID", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetBoolean(value, bss->m_enabled);
        rbusObject_SetValue(row, "Enabled", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetBoolean(value, bss->m_broadcast);
        rbusObject_SetValue(row, "TransmittedBSSID", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetBoolean(value, bss->m_fronthaul);
        rbusObject_SetValue(row, "FronthaulUse", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetBoolean(value, bss->m_backhaul);
        rbusObject_SetValue(row, "BackhaulUse", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetObject(value, row);
        rbusObject_Release(row);

        rbusObject_SetValue(data, bss->m_key, value);
        rbusValue_Release(value);

        bss = (de_bss_t *)hash_map_get_next(m_bss_map, bss);
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

void de_bsss_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    rbusValue_t value;
    rbusObject_t row;
    rbusProperty_t prop;

    const char *ptr;
    de_bss_t *bss;

    if (strncmp(subscription->eventName, BSSS, strlen(BSSS)) != 0) {
        printf("%s:%d: Unknown event: %s\n", __func__, __LINE__, event->name);
        return;
    }


    prop = rbusObject_GetProperties(event->data);
    while (prop != NULL) {
        ptr = rbusProperty_GetName(prop);
        printf("%s:%d: Name: %s\n", __func__, __LINE__, ptr);

        if ((bss = (de_bss_t *)hash_map_get(m_bss_map, ptr)) == NULL) {
            bss = new de_bss_t();
            bss->init(ptr);
            hash_map_put(m_bss_map, strdup(ptr), bss);
        }

        row = rbusProperty_GetObject(prop);

        if ((value = rbusObject_GetValue(row, "BSSID")) == NULL) {
            printf("%s:%d: Could not find Type value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(bss->m_bssid, ptr, strlen(ptr) + 1);
        }

        if ((value = rbusObject_GetValue(row, "SSID")) == NULL) {
            printf("%s:%d: Could not find Type value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(bss->m_ssid, ptr, strlen(ptr) + 1);
        }

        if ((value = rbusObject_GetValue(row, "Enabled")) == NULL) {
            printf("%s:%d: Could not find Enabled value\n", __func__, __LINE__);
        } else {
            bss->m_enabled = rbusValue_GetBoolean(value);
        }

        if ((value = rbusObject_GetValue(row, "TransmittedBSSID")) == NULL) {
            printf("%s:%d: Could not find TransmittedBSSID value\n", __func__, __LINE__);
        } else {
            bss->m_broadcast = rbusValue_GetBoolean(value);
        }

        if ((value = rbusObject_GetValue(row, "FronthaulUse")) == NULL) {
            printf("%s:%d: Could not find FronthaulUse value\n", __func__, __LINE__);
        } else {
            bss->m_fronthaul = rbusValue_GetBoolean(value);
        }

        if ((value = rbusObject_GetValue(row, "BackhaulUse")) == NULL) {
            printf("%s:%d: Could not find BackhaulUse value\n", __func__, __LINE__);
        } else {
            bss->m_backhaul = rbusValue_GetBoolean(value);
        }

        prop = rbusProperty_GetNext(prop);
    }

}

int de_bsss_t::init(rbusHandle_t handle)
{
    m_bss_map = hash_map_create();

    m_elems[m_num_elems].name = BSSS;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;
    
    m_elems[m_num_elems].name = DE_BSSS_TABLE;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_TABLE;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_BSSS_BSSID;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_BSSS_SSID;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_BSSS_ENABLED;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_BSSS_TXBSSID;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_BSSS_FRONT;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_BSSS_BACK;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_subs[m_num_subs].eventName = BSSS;
    m_num_subs++;

    if (de_t::init(handle) != 0) { 
        printf("%s:%d: Failed to initialize bsss\n", __func__, __LINE__);
        return -1;
    }

    m_de_stas = new de_stas_t(STAS, m_provider, m_func);

    return m_de_stas->init(handle);
}

void de_bsss_t::deinit(bool bus_close)
{
    if (m_de_stas != NULL) {
        m_de_stas->deinit(false);
    }
    if (m_bss_map != NULL) {
        hash_map_destroy(m_bss_map);
    }
    de_t::deinit(false);
}

de_bsss_t::de_bsss_t(const char *name, bool provider, notifier_t func)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
    m_func = func;
    m_bss_map = NULL;
    m_de_stas = NULL;
}

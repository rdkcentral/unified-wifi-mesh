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
#include "de_caps.h"
#include "optimizer.h"

void de_caps_t::update(de_op_class_t& op_class, unsigned int dpos, unsigned int rpos, unsigned int opos)
{
    m_de_op_classes->update(op_class, dpos, rpos, opos);
}

void de_caps_t::update(de_cap_t& cap, unsigned int dpos, unsigned int rpos)
{
    rbusValue_t value;
    em_long_string_t name = {0};
    de_cap_t *pcap = NULL;
    em_long_string_t alias = {0};

    snprintf(alias, sizeof(em_long_string_t), "%s.%d.%s.%d.%s", DEVICES, dpos, RADIOS, rpos, CAPS);
    if ((pcap = (de_cap_t *)hash_map_get(m_cap_map, alias)) == NULL) {
        pcap = new de_cap_t();
        pcap->init(alias);
        hash_map_put(m_cap_map, strdup(alias), pcap);
    }

    pcap->update(cap);

    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.NumberOfOpClass", DE_DEVICES, dpos, RADIOS, rpos, CAPS);
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, cap.m_num_op_class);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);

    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.HTCapabilities", DE_DEVICES, dpos, RADIOS, rpos, CAPS);
    rbusValue_Init(&value);
    rbusValue_SetString(value, cap.m_ht_cap);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
}


rbusError_t de_caps_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    if (strstr(table_name, OP_CLASSES) != NULL) {
        return m_de_op_classes->add(handle, table_name, alias_name, inst_num);
    }

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_caps_t::remove(rbusHandle_t handle, char const* row_name)
{
    if (strstr(row_name, OP_CLASSES) != NULL) {
        return m_de_op_classes->remove(handle, row_name);
    }

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_caps_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    const char *name;

    name = rbusProperty_GetName(property);
    if (strstr(name, OP_CLASSES) != NULL) {
        return m_de_op_classes->get(handle, property, options);
    }

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_caps_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    em_string_t str;
    em_long_string_t key;
    unsigned int dpos, rpos;
    int len;
    de_cap_t *cap;
    const char *name, *ptr;

    name  = rbusProperty_GetName(property);
    if (strstr(name, OP_CLASSES) != NULL) {
        return m_de_op_classes->set(handle, property, options);
    }

    snprintf(key, sizeof(em_long_string_t), "%s", DE_DEVICES);

    if ((ptr = strstr(name, key)) == NULL) {
        printf("%s:%d: Substring(%s) not found in %s\n", __func__, __LINE__, key, name);
        return RBUS_ERROR_INVALID_OPERATION;
    }

    ptr += strlen(DE_DEVICES);

    sscanf(ptr, "%d.RadioList.%d.Capabilities.%s", &dpos, &rpos, str);
    snprintf(key, sizeof(em_long_string_t), "DeviceList.%d.RadioList.%d.Capabilities", dpos, rpos);

    if ((cap = (de_cap_t *)hash_map_get(m_cap_map, key)) == NULL) {
        cap = new de_cap_t();
        cap->init(key);
        hash_map_put(m_cap_map, strdup(key), cap);
    }

    if (strncmp(str, "NumberOfOpClass", strlen("NumberOfOpClass")) == 0) {
        cap->m_num_op_class = rbusProperty_GetUInt32(property);
    } else if (strncmp(str, "HTCapabilities", strlen("HTCapabilities")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(cap->m_ht_cap, ptr, len + 1);
    }

    return RBUS_ERROR_SUCCESS;
}

void de_caps_t::publish(const char *name)
{
    int rc, inst;
    de_cap_t *cap;
    rbusEvent_t event = {0};
    rbusValue_t value;
    rbusObject_t data, row;

    if (strncmp(name, OP_CLASSES, strlen(OP_CLASSES)) == 0) {
        m_de_op_classes->publish(name);
        return;
    } else if (strncmp(name, CAPS, strlen(CAPS)) != 0) {
        return;
    }

    rbusObject_Init(&data, NULL);

    cap = (de_cap_t *)hash_map_get_first(m_cap_map);
    while (cap != NULL) {
        rbusObject_Init(&row, cap->m_key);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, cap->m_num_op_class);
        rbusObject_SetValue(row, "NumberOfOpClass", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, cap->m_ht_cap);
        rbusObject_SetValue(row, "HTCapabilities", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetObject(value, row);
        rbusObject_Release(row);

        rbusObject_SetValue(data, cap->m_key, value);
        rbusValue_Release(value);

        cap = (de_cap_t *)hash_map_get_next(m_cap_map, cap);
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

void de_caps_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    rbusValue_t value;
    rbusObject_t row;
    rbusProperty_t prop;

    const char *ptr;
    de_cap_t *cap;

    if (strncmp(subscription->eventName, CAPS, strlen(CAPS)) != 0) {
        printf("%s:%d: Unknown event: %s\n", __func__, __LINE__, event->name);
        return;
    }

    prop = rbusObject_GetProperties(event->data);
    while (prop != NULL) {
        ptr = rbusProperty_GetName(prop);
        printf("%s:%d: Name: %s\n", __func__, __LINE__, ptr);

        if ((cap = (de_cap_t *)hash_map_get(m_cap_map, ptr)) == NULL) {
            cap = new de_cap_t();
            cap->init(ptr);
            hash_map_put(m_cap_map, strdup(ptr), cap);
        }

        row = rbusProperty_GetObject(prop);

        if ((value = rbusObject_GetValue(row, "NumberOfOpClass")) == NULL) {
            printf("%s:%d: Could not find NumberOfOpClass value\n", __func__, __LINE__);
        } else {
            cap->m_num_op_class = rbusValue_GetUInt32(value);
        }

        if ((value = rbusObject_GetValue(row, "HTCapabilities")) == NULL) {
            printf("%s:%d: Could not find HTCapabilities value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(cap->m_ht_cap, ptr, strlen(ptr) + 1);
        }

        prop = rbusProperty_GetNext(prop);
    }

}

int de_caps_t::init(rbusHandle_t handle)
{
    m_cap_map = hash_map_create();

    m_elems[m_num_elems].name = CAPS;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_CAPS_NUM_OP_CLASS;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_CAPS_HT_CAP;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_subs[m_num_subs].eventName = CAPS;
    m_num_subs++;

    if (de_t::init(handle) != 0) {
        printf("%s:%d: Failed to initialize caps\n", __func__, __LINE__);
        return -1;
    }

    m_de_op_classes = new de_op_classes_t(OP_CLASSES, m_provider, m_func);

    return m_de_op_classes->init(handle);
}

void de_caps_t::deinit(bool bus_close)
{
    if (m_de_op_classes != NULL) {
        m_de_op_classes->deinit(false);
    }
    if (m_cap_map != NULL) {
        hash_map_destroy(m_cap_map);
    }
    de_t::deinit(false);
}

de_caps_t::de_caps_t(const char *name, bool provider, notifier_t func)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
    m_func = func;
    m_cap_map = NULL;
    m_de_op_classes = NULL;
}

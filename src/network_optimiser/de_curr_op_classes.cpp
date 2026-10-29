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
#include "de_curr_op_classes.h"
#include "optimizer.h"

void de_curr_op_classes_t::update(de_curr_op_class_t& curr_op_class, unsigned int dpos, unsigned int rpos, unsigned int opos)
{
    rbusValue_t value;
    em_long_string_t name = {0};
    unsigned int inst;
    de_curr_op_class_t *poc = NULL;
    em_long_string_t alias = {0};

    snprintf(alias, sizeof(em_long_string_t), "%s.%d.%s.%d.%s.%d", DEVICES, dpos, RADIOS, rpos, CURR_OP_CLASSES, opos);
    if ((poc = (de_curr_op_class_t *)hash_map_get(m_op_class_map, alias)) == NULL) {
        snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.", DE_DEVICES, dpos, RADIOS, rpos, CURR_OP_CLASSES);
        printf("%s:%d: adding row, name: %s, alias: %s\n", __func__, __LINE__, name, alias);
        rbusTable_addRow(m_bus_handle, name, alias, &inst);
        poc = (de_curr_op_class_t *)hash_map_get(m_op_class_map, alias);
    }

    if (poc != NULL) {
        poc->update(curr_op_class);
    }

    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.Class", DE_DEVICES, dpos, RADIOS, rpos, CURR_OP_CLASSES, opos);
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, curr_op_class.m_class);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);

    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.TxPower", DE_DEVICES, dpos, RADIOS, rpos, CURR_OP_CLASSES, opos);
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, curr_op_class.m_tx_power);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);

    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.Channel", DE_DEVICES, dpos, RADIOS, rpos, CURR_OP_CLASSES, opos);
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, curr_op_class.m_channel);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
}


rbusError_t de_curr_op_classes_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    unsigned int dpos, rpos, opos;
    de_curr_op_class_t *op_class;

    sscanf(alias_name, "DeviceList.%d.RadioList.%d.CurrentOperatingClasses.%d", &dpos, &rpos, &opos);
    printf("%s:%d: Name: %s\n", __func__, __LINE__, alias_name);

    if ((op_class = (de_curr_op_class_t *)hash_map_get(m_op_class_map, alias_name)) == NULL) {
        op_class = new de_curr_op_class_t();
        op_class->init(alias_name);

        hash_map_put(m_op_class_map, strdup(alias_name), op_class);
    }

    *inst_num = opos;

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_curr_op_classes_t::remove(rbusHandle_t handle, char const* row_name)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_curr_op_classes_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_curr_op_classes_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    em_string_t str;
    em_long_string_t key;
    unsigned int dpos, rpos, opos;
    de_curr_op_class_t *op_class;
    const char *name, *ptr;

    name  = rbusProperty_GetName(property);

    snprintf(key, sizeof(em_long_string_t), "%s", DE_DEVICES);

    if ((ptr = strstr(name, key)) == NULL) {
        printf("%s:%d: Substring(%s) not found in %s\n", __func__, __LINE__, key, name);
        return RBUS_ERROR_INVALID_OPERATION;
    }

    ptr += strlen(DE_DEVICES);

    sscanf(ptr, "%d.RadioList.%d.CurrentOperatingClasses.%d.%s", &dpos, &rpos, &opos, str);
    snprintf(key, sizeof(em_long_string_t), "DeviceList.%d.RadioList.%d.CurrentOperatingClasses.%d", dpos, rpos, opos);

    if ((op_class = (de_curr_op_class_t *)hash_map_get(m_op_class_map, key)) == NULL) {
        printf("%s:%d: Could not find operating class at key: %s\n", __func__, __LINE__, key);
        return RBUS_ERROR_INVALID_HANDLE;
    }

    if (strncmp(str, "Class", strlen("Class")) == 0) {
        op_class->m_class = rbusProperty_GetUInt32(property);
    } else if (strncmp(str, "TxPower", strlen("TxPower")) == 0) {
        op_class->m_tx_power = rbusProperty_GetUInt32(property);
    } else if (strncmp(str, "Channel", strlen("Channel")) == 0) {
        op_class->m_channel = rbusProperty_GetUInt32(property);
    }

    return RBUS_ERROR_SUCCESS;
}

void de_curr_op_classes_t::publish(const char *name)
{
    int rc, inst;
    de_curr_op_class_t *op_class;
    rbusEvent_t event = {0};
    rbusValue_t value;
    rbusObject_t data, row;

    if (strncmp(name, CURR_OP_CLASSES, strlen(CURR_OP_CLASSES)) != 0) {
        return;
    }

    rbusObject_Init(&data, NULL);

    op_class = (de_curr_op_class_t *)hash_map_get_first(m_op_class_map);
    while (op_class != NULL) {
        rbusObject_Init(&row, op_class->m_key);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, op_class->m_class);
        rbusObject_SetValue(row, "Class", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, op_class->m_tx_power);
        rbusObject_SetValue(row, "TxPower", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, op_class->m_channel);
        rbusObject_SetValue(row, "Channel", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetObject(value, row);
        rbusObject_Release(row);

        rbusObject_SetValue(data, op_class->m_key, value);
        rbusValue_Release(value);

        op_class = (de_curr_op_class_t *)hash_map_get_next(m_op_class_map, op_class);
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

void de_curr_op_classes_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    rbusValue_t value;
    rbusObject_t row;
    rbusProperty_t prop;

    const char *ptr;
    de_curr_op_class_t *op_class;

    if (strncmp(subscription->eventName, CURR_OP_CLASSES, strlen(CURR_OP_CLASSES)) != 0) {
        printf("%s:%d: Unknown event: %s\n", __func__, __LINE__, event->name);
        return;
    }

    prop = rbusObject_GetProperties(event->data);
    while (prop != NULL) {
        ptr = rbusProperty_GetName(prop);
        printf("%s:%d: Name: %s\n", __func__, __LINE__, ptr);

        if ((op_class = (de_curr_op_class_t *)hash_map_get(m_op_class_map, ptr)) == NULL) {
            op_class = new de_curr_op_class_t();
            op_class->init(ptr);
            hash_map_put(m_op_class_map, strdup(ptr), op_class);
        }

        row = rbusProperty_GetObject(prop);

        if ((value = rbusObject_GetValue(row, "Class")) == NULL) {
            printf("%s:%d: Could not find Class value\n", __func__, __LINE__);
        } else {
            op_class->m_class = rbusValue_GetUInt32(value);
        }

        if ((value = rbusObject_GetValue(row, "TxPower")) == NULL) {
            printf("%s:%d: Could not find TxPower value\n", __func__, __LINE__);
        } else {
            op_class->m_tx_power = rbusValue_GetUInt32(value);
        }

        if ((value = rbusObject_GetValue(row, "Channel")) == NULL) {
            printf("%s:%d: Could not find Channel value\n", __func__, __LINE__);
        } else {
            op_class->m_channel = rbusValue_GetUInt32(value);
        }

        prop = rbusProperty_GetNext(prop);
    }

}

int de_curr_op_classes_t::init(rbusHandle_t handle)
{
    m_op_class_map = hash_map_create();

    m_elems[m_num_elems].name = CURR_OP_CLASSES;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_CURR_OP_CLASSES_TABLE;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_TABLE;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_CURR_OP_CLASSES_CLASS;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_CURR_OP_CLASSES_TXPOWER;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_CURR_OP_CLASSES_CHANNEL;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_subs[m_num_subs].eventName = CURR_OP_CLASSES;
    m_num_subs++;

    if (de_t::init(handle) != 0) {
        printf("%s:%d: Failed to initialize curr op classes\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

void de_curr_op_classes_t::deinit(bool bus_close)
{
    if (m_op_class_map != NULL) {
        hash_map_destroy(m_op_class_map);
    }
    de_t::deinit(false);
}

de_curr_op_classes_t::de_curr_op_classes_t(const char *name, bool provider, notifier_t func)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
    m_func = func;
    m_op_class_map = NULL;
}

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
#include "de_nbr_nodes.h"
#include "optimizer.h"

void de_nbr_nodes_t::update(de_nbr_node_t& node)
{
    de_nbr_node_t *pnode;
    em_string_t key;

    snprintf(key, sizeof(em_string_t), "%s.%s", node.m_radio, node.m_bssid);

    if ((pnode = (de_nbr_node_t *)hash_map_get(m_nbr_node_map, key)) == NULL) {
        pnode = new de_nbr_node_t();
        pnode->init(key);
        hash_map_put(m_nbr_node_map, strdup(key), pnode);
    }

    pnode->update(node);
}

void de_nbr_nodes_t::remove(de_nbr_node_t& node)
{
    de_nbr_node_t *pnode;
    em_string_t key;

    snprintf(key, sizeof(em_string_t), "%s.%d", node.m_radio, node.m_bssid);
    if ((pnode = (de_nbr_node_t *)hash_map_remove(m_nbr_node_map, key)) != NULL) {
        delete pnode;
    }
}


rbusError_t de_nbr_nodes_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_nbr_nodes_t::remove(rbusHandle_t handle, char const* row_name)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_nbr_nodes_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_nbr_nodes_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

void de_nbr_nodes_t::publish(const char *name)
{

}


void de_nbr_nodes_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{

}

rbusError_t de_nbr_nodes_t::method(rbusHandle_t handle, char const* name, rbusObject_t in, rbusObject_t out, rbusMethodAsyncHandle_t async)
{
    rbusValue_t value;
    rbusObject_t ob;
    de_nbr_node_t *node;
    em_string_t     key;
    unsigned int index = 0;

    rbusValue_Init(&value);
    rbusValue_SetString(value, "Complete");
    rbusObject_SetValue(out, "Status", value);
    rbusValue_Release(value);

    node = (de_nbr_node_t *)hash_map_get_first(m_nbr_node_map);
    while (node != NULL) {
        snprintf(key, sizeof(key), "Result.%d.", index); 
        rbusObject_Init(&ob, key);

        rbusValue_Init(&value);
        rbusValue_SetString(value, node->m_radio);
        rbusObject_SetValue(ob, "Radio", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, node->m_ssid);
        rbusObject_SetValue(ob, "SSID", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, node->m_bssid);
        rbusObject_SetValue(ob, "BSSID", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, node->m_mode);
        rbusObject_SetValue(ob, "Mode", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, node->m_channel);
        rbusObject_SetValue(ob, "Channel", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetInt32(value, node->m_signal_strength);
        rbusObject_SetValue(ob, "SignalStrength", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, node->m_security_mode_enabled);
        rbusObject_SetValue(ob, "SecurityModeEnabled", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, node->m_encryption_mode);
        rbusObject_SetValue(ob, "EncryptionMode", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, node->m_op_frequency_band);
        rbusObject_SetValue(ob, "OperatingFrequencyBand", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, node->m_supported_standards);
        rbusObject_SetValue(ob, "SupportedStandards", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, node->m_op_standards);
        rbusObject_SetValue(ob, "OperatingStandards", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, node->m_op_channel_bw);
        rbusObject_SetValue(ob, "OperatingChannelBandwidth", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, node->m_beacon_period);
        rbusObject_SetValue(ob, "BeaconPeriod", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetInt32(value, node->m_noise);
        rbusObject_SetValue(ob, "Noise", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, node->m_basic_data_tx_rated);
        rbusObject_SetValue(ob, "BasicDataTransferRates", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, node->m_supported_data_tx_rates);
        rbusObject_SetValue(ob, "SupportedDataTransferRates", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, node->m_dtim_period);
        rbusObject_SetValue(ob, "DTIMPeriod", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetObject(value, ob);
        rbusObject_Release(ob);

        rbusObject_SetValue(out, key, value);
        rbusValue_Release(value);

        node = (de_nbr_node_t *)hash_map_get_next(m_nbr_node_map, node);
        index++;
    }

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_nbr_nodes_t::invoke_method(char const* name, void *in, void *out)
{
    de_nbr_node_t node, *pnode;
    rbusObject_t ob, in_obj, out_obj;
    rbusProperty_t prop;
    rbusValue_t value;
    em_string_t key;
    int rc;
    const char *ptr;

    rbusObject_Init(&in_obj, NULL);
    rc = rbusMethod_Invoke(m_bus_handle, NBR_WIFI_DIAG, in_obj, &out_obj);

    prop = rbusObject_GetProperties(out_obj);
    while (prop != NULL) {
        if (strstr(rbusProperty_GetName(prop), "Result.") == NULL) {
            prop = rbusProperty_GetNext(prop);
            continue;
        }

        ob = rbusProperty_GetObject(prop);
           
        if ((value = rbusObject_GetValue(ob, "Radio")) == NULL) {
            printf("%s:%d: Could not find Radio value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(node.m_radio, ptr, strlen(ptr) + 1);
        }
        
        if ((value = rbusObject_GetValue(ob, "SSID")) == NULL) {
            printf("%s:%d: Could not find SSID value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(node.m_ssid, ptr, strlen(ptr) + 1);
        }
        
        if ((value = rbusObject_GetValue(ob, "BSSID")) == NULL) {
            printf("%s:%d: Could not find BSSID value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(node.m_bssid, ptr, strlen(ptr) + 1);
        }
        
        if ((value = rbusObject_GetValue(ob, "Mode")) == NULL) {
            printf("%s:%d: Could not find Mode value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(node.m_mode, ptr, strlen(ptr) + 1);
        }
        
        if ((value = rbusObject_GetValue(ob, "Channel")) == NULL) {
            printf("%s:%d: Could not find Channel value\n", __func__, __LINE__);
        } else {
            node.m_channel = rbusValue_GetUInt32(value);
        }
        
        if ((value = rbusObject_GetValue(ob, "SignalStrength")) == NULL) {
            printf("%s:%d: Could not find SignalStrength value\n", __func__, __LINE__);
        } else {
            node.m_signal_strength = rbusValue_GetInt32(value);
        }
        
        if ((value = rbusObject_GetValue(ob, "SecurityModeEnabled")) == NULL) {
            printf("%s:%d: Could not find SecurityModeEnabled value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(node.m_security_mode_enabled, ptr, strlen(ptr) + 1);
        }
        
        if ((value = rbusObject_GetValue(ob, "EncryptionMode")) == NULL) {
            printf("%s:%d: Could not find EncryptionMode value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(node.m_encryption_mode, ptr, strlen(ptr) + 1);
        }
        
        if ((value = rbusObject_GetValue(ob, "OperatingFrequencyBand")) == NULL) {
            printf("%s:%d: Could not find OperatingFrequencyBand value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(node.m_op_frequency_band, ptr, strlen(ptr) + 1);
        }
        
        if ((value = rbusObject_GetValue(ob, "SupportedStandards")) == NULL) {
            printf("%s:%d: Could not find SupportedStandards value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(node.m_supported_standards, ptr, strlen(ptr) + 1);
        }
        
        if ((value = rbusObject_GetValue(ob, "OperatingStandards")) == NULL) {
            printf("%s:%d: Could not find OperatingStandards value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(node.m_op_standards, ptr, strlen(ptr) + 1);
        }
        
        if ((value = rbusObject_GetValue(ob, "OperatingChannelBandwidth")) == NULL) {
            printf("%s:%d: Could not find OperatingChannelBandwidth value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(node.m_op_channel_bw, ptr, strlen(ptr) + 1);
        }
        
        if ((value = rbusObject_GetValue(ob, "BeaconPeriod")) == NULL) {
            printf("%s:%d: Could not find BeaconPeriod value\n", __func__, __LINE__);
        } else {
            node.m_beacon_period = rbusValue_GetUInt32(value);
        }
        
        if ((value = rbusObject_GetValue(ob, "Noise")) == NULL) {
            printf("%s:%d: Could not find Noise value\n", __func__, __LINE__);
        } else {
            node.m_noise = rbusValue_GetInt32(value);
        }
        
        if ((value = rbusObject_GetValue(ob, "BasicDataTransferRates")) == NULL) {
            printf("%s:%d: Could not find BasicDataTransferRates value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(node.m_basic_data_tx_rated, ptr, strlen(ptr) + 1);
        }
        
        if ((value = rbusObject_GetValue(ob, "SupportedDataTransferRates")) == NULL) {
            printf("%s:%d: Could not find SupportedDataTransferRates value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(node.m_supported_data_tx_rates, ptr, strlen(ptr) + 1);
        }
        
        if ((value = rbusObject_GetValue(ob, "DTIMPeriod")) == NULL) {
            printf("%s:%d: Could not find DTIMPeriod value\n", __func__, __LINE__);
        } else {
            node.m_dtim_period = rbusValue_GetUInt32(value);
        }
        
        snprintf(key, sizeof(em_string_t), "%s.%s", node.m_radio, node.m_bssid);
        if ((pnode = (de_nbr_node_t *)hash_map_get(m_nbr_node_map, key)) == NULL) {
            pnode = new de_nbr_node_t();
            pnode->init(key);
            hash_map_put(m_nbr_node_map, strdup(key), pnode);
        }

        pnode->update(node);
        prop = rbusProperty_GetNext(prop);
    }

    rbusObject_Release(in_obj);
    rbusObject_Release(out_obj);

    return (rbusError_t)rc;
}

int de_nbr_nodes_t::init()
{
    m_nbr_node_map = hash_map_create();

    m_elems[m_num_elems].name = NBR_WIFI_DIAG;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_METHOD;
    m_num_elems++;

    return de_t::init(); 
}

void de_nbr_nodes_t::deinit()
{
    if (m_nbr_node_map != NULL) {
        hash_map_destroy(m_nbr_node_map);
    }
    de_t::deinit();
}

de_nbr_nodes_t::de_nbr_nodes_t(const char *name, bool provider, notifier_t func)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
    m_func = func;
    m_nbr_node_map = NULL;
}

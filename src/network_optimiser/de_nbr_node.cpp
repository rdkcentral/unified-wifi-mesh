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
#include "de_nbr_node.h"

void de_nbr_node_t::update(de_nbr_node_t& node)
{
    strncpy(m_radio, node.m_radio, strlen(node.m_radio) + 1);
    strncpy(m_ssid, node.m_ssid, strlen(node.m_ssid) + 1);
    strncpy(m_bssid, node.m_bssid, strlen(node.m_bssid) + 1);
    strncpy(m_mode, node.m_mode, strlen(node.m_mode) + 1);
    m_channel = node.m_channel;
    m_signal_strength = node.m_signal_strength;
    strncpy(m_security_mode_enabled, node.m_security_mode_enabled, strlen(node.m_security_mode_enabled) + 1);
    strncpy(m_encryption_mode, node.m_encryption_mode, strlen(node.m_encryption_mode) + 1);
    strncpy(m_op_frequency_band, node.m_op_frequency_band, strlen(node.m_op_frequency_band) + 1);
    strncpy(m_supported_standards, node.m_supported_standards, strlen(node.m_supported_standards) + 1);
    strncpy(m_op_standards, node.m_op_standards, strlen(node.m_op_standards) + 1);
    strncpy(m_op_channel_bw, node.m_op_channel_bw, strlen(node.m_op_channel_bw) + 1);
    m_beacon_period = node.m_beacon_period;
    m_noise = node.m_noise;
    strncpy(m_basic_data_tx_rated, node.m_basic_data_tx_rated, strlen(node.m_basic_data_tx_rated) + 1);
    strncpy(m_supported_data_tx_rates, node.m_supported_data_tx_rates, strlen(node.m_supported_data_tx_rates) + 1);
    m_dtim_period = node.m_dtim_period;
}

void de_nbr_node_t::serialize(rbusObject_t& ob)
{
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_radio);
    rbusObject_SetValue(ob, "Radio", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_ssid);
    rbusObject_SetValue(ob, "SSID", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_bssid);
    rbusObject_SetValue(ob, "BSSID", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_mode);
    rbusObject_SetValue(ob, "Mode", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_channel);
    rbusObject_SetValue(ob, "Channel", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetInt32(value, m_signal_strength);
    rbusObject_SetValue(ob, "SignalStrength", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_security_mode_enabled);
    rbusObject_SetValue(ob, "SecurityModeEnabled", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_encryption_mode);
    rbusObject_SetValue(ob, "EncryptionMode", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_op_frequency_band);
    rbusObject_SetValue(ob, "OperatingFrequencyBand", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_supported_standards);
    rbusObject_SetValue(ob, "SupportedStandards", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_op_standards);
    rbusObject_SetValue(ob, "OperatingStandards", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_op_channel_bw);
    rbusObject_SetValue(ob, "OperatingChannelBandwidth", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_beacon_period);
    rbusObject_SetValue(ob, "BeaconPeriod", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetInt32(value, m_noise);
    rbusObject_SetValue(ob, "Noise", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_basic_data_tx_rated);
    rbusObject_SetValue(ob, "BasicDataTransferRates", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_supported_data_tx_rates);
    rbusObject_SetValue(ob, "SupportedDataTransferRates", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_dtim_period);
    rbusObject_SetValue(ob, "DTIMPeriod", value);
    rbusValue_Release(value);

}

void de_nbr_node_t::deserialize(rbusObject_t& ob)
{
    rbusValue_t value;
    const char *ptr;

    if ((value = rbusObject_GetValue(ob, "Radio")) == NULL) {
        printf("%s:%d: Could not find Radio value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_radio, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "SSID")) == NULL) {
        printf("%s:%d: Could not find SSID value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_ssid, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "BSSID")) == NULL) {
        printf("%s:%d: Could not find BSSID value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_bssid, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "Mode")) == NULL) {
        printf("%s:%d: Could not find Mode value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_mode, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "Channel")) == NULL) {
        printf("%s:%d: Could not find Channel value\n", __func__, __LINE__);
    } else {
        m_channel = rbusValue_GetUInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "SignalStrength")) == NULL) {
        printf("%s:%d: Could not find SignalStrength value\n", __func__, __LINE__);
    } else {
        m_signal_strength = rbusValue_GetInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "SecurityModeEnabled")) == NULL) {
        printf("%s:%d: Could not find SecurityModeEnabled value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_security_mode_enabled, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "EncryptionMode")) == NULL) {
        printf("%s:%d: Could not find EncryptionMode value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_encryption_mode, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "OperatingFrequencyBand")) == NULL) {
        printf("%s:%d: Could not find OperatingFrequencyBand value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_op_frequency_band, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "SupportedStandards")) == NULL) {
        printf("%s:%d: Could not find SupportedStandards value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_supported_standards, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "OperatingStandards")) == NULL) {
        printf("%s:%d: Could not find OperatingStandards value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_op_standards, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "OperatingChannelBandwidth")) == NULL) {
        printf("%s:%d: Could not find OperatingChannelBandwidth value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_op_channel_bw, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "BeaconPeriod")) == NULL) {
        printf("%s:%d: Could not find BeaconPeriod value\n", __func__, __LINE__);
    } else {
        m_beacon_period = rbusValue_GetUInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "Noise")) == NULL) {
        printf("%s:%d: Could not find Noise value\n", __func__, __LINE__);
    } else {
        m_noise = rbusValue_GetInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "BasicDataTransferRates")) == NULL) {
        printf("%s:%d: Could not find BasicDataTransferRates value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_basic_data_tx_rated, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "SupportedDataTransferRates")) == NULL) {
        printf("%s:%d: Could not find SupportedDataTransferRates value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_supported_data_tx_rates, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "DTIMPeriod")) == NULL) {
        printf("%s:%d: Could not find DTIMPeriod value\n", __func__, __LINE__);
    } else {
        m_dtim_period = rbusValue_GetUInt32(value);
    }

}

void de_nbr_node_t::serialize(cJSON *ob)
{
    cJSON_AddStringToObject(ob, "Radio", m_radio);
    cJSON_AddStringToObject(ob, "SSID", m_ssid);
    cJSON_AddStringToObject(ob, "BSSID", m_bssid);
    cJSON_AddStringToObject(ob, "Mode", m_mode);
    cJSON_AddNumberToObject(ob, "Channel", m_channel);
    cJSON_AddNumberToObject(ob, "SignalStrength", m_signal_strength);
    cJSON_AddStringToObject(ob, "SecurityModeEnabled", m_security_mode_enabled);
    cJSON_AddStringToObject(ob, "EncryptionMode", m_encryption_mode);
    cJSON_AddStringToObject(ob, "OperatingFrequencyBand", m_op_frequency_band);
    cJSON_AddStringToObject(ob, "SupportedStandards", m_supported_standards);
    cJSON_AddStringToObject(ob, "OperatingStandards", m_op_standards);
    cJSON_AddStringToObject(ob, "OperatingChannelBandwidth", m_op_channel_bw);
    cJSON_AddNumberToObject(ob, "BeaconPeriod", m_beacon_period);
    cJSON_AddNumberToObject(ob, "Noise", m_noise);
    cJSON_AddStringToObject(ob, "BasicDataTransferRates", m_basic_data_tx_rated);
    cJSON_AddStringToObject(ob, "SupportedDataTransferRates", m_supported_data_tx_rates);
    cJSON_AddNumberToObject(ob, "DTIMPeriod", m_dtim_period);
}

void de_nbr_node_t::deserialize(cJSON *ob)
{

}

int de_nbr_node_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_nbr_node_t::deinit()
{

}

de_nbr_node_t::de_nbr_node_t()
{
    memset(m_key, 0, sizeof(m_key));
    memset(m_radio, 0, sizeof(m_radio));
    memset(m_ssid, 0, sizeof(m_ssid));
    memset(m_bssid, 0, sizeof(m_bssid));
    memset(m_mode, 0, sizeof(m_mode));
    memset(m_security_mode_enabled, 0, sizeof(m_security_mode_enabled));
    memset(m_encryption_mode, 0, sizeof(m_encryption_mode));
    memset(m_op_frequency_band, 0, sizeof(m_op_frequency_band));
    memset(m_supported_standards, 0, sizeof(m_supported_standards));
    memset(m_op_standards, 0, sizeof(m_op_standards));
    memset(m_op_channel_bw, 0, sizeof(m_op_channel_bw));
    memset(m_basic_data_tx_rated, 0, sizeof(m_basic_data_tx_rated));
    memset(m_supported_data_tx_rates, 0, sizeof(m_supported_data_tx_rates));
}

de_nbr_node_t::~de_nbr_node_t()
{

}

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
#include "de_nbr_bss.h"

void de_nbr_bss_t::update(de_nbr_bss_t& bss)
{
    strncpy(m_bssid, bss.m_bssid, strlen(bss.m_bssid) + 1);
    strncpy(m_ssid, bss.m_ssid, strlen(bss.m_ssid) + 1);
    m_signal_strength = bss.m_signal_strength;
    strncpy(m_channel_bw, bss.m_channel_bw, strlen(bss.m_channel_bw) + 1);
    m_channel_util = bss.m_channel_util;
    m_sta_count = bss.m_sta_count;
    strncpy(m_mld_mac, bss.m_mld_mac, strlen(bss.m_mld_mac) + 1);
    strncpy(m_rep_bssid, bss.m_rep_bssid, strlen(bss.m_rep_bssid) + 1);
    m_multi_bssid = bss.m_multi_bssid;
    m_bss_load_elem_present = bss.m_bss_load_elem_present;
    m_bss_color = bss.m_bss_color; 
    strncpy(m_security_mode_enabled, bss.m_security_mode_enabled, strlen(bss.m_security_mode_enabled) + 1);
    strncpy(m_encryption_mode, bss.m_encryption_mode, strlen(bss.m_encryption_mode) + 1);
    strncpy(m_supp_standards, bss.m_supp_standards, strlen(bss.m_supp_standards) + 1);
    strncpy(m_op_standards, bss.m_op_standards, strlen(bss.m_op_standards) + 1);
    strncpy(m_basic_data_tx_rates, bss.m_basic_data_tx_rates, strlen(bss.m_basic_data_tx_rates) + 1);
    strncpy(m_supp_data_tx_rates, bss.m_supp_data_tx_rates, strlen(bss.m_supp_data_tx_rates) + 1);
    m_supp_nss = bss.m_supp_nss; 
    m_dtim_period = bss.m_dtim_period; 
    m_beacon_period = bss.m_beacon_period; 
}

void de_nbr_bss_t::serialize(rbusObject_t& ob)
{
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_bssid);
    rbusObject_SetValue(ob, "BSSID", value);
    rbusValue_Release(value);
    
    rbusValue_Init(&value);
    rbusValue_SetString(value, m_ssid);
    rbusObject_SetValue(ob, "SSID", value);
    rbusValue_Release(value);
    
    rbusValue_Init(&value);
    rbusValue_SetInt32(value, m_signal_strength);
    rbusObject_SetValue(ob, "SignalStrength", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_channel_bw);
    rbusObject_SetValue(ob, "ChannelBandwidth", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_channel_util);
    rbusObject_SetValue(ob, "ChannelUtilization", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_sta_count);
    rbusObject_SetValue(ob, "StationCount", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_mld_mac);
    rbusObject_SetValue(ob, "MLDMACAddress", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_rep_bssid);
    rbusObject_SetValue(ob, "ReportingBSSID", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, m_multi_bssid);
    rbusObject_SetValue(ob, "MultiBSSID", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, m_bss_load_elem_present);
    rbusObject_SetValue(ob, "BSSLoadElementPresent", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_bss_color);
    rbusObject_SetValue(ob, "BSSColor", value);
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
    rbusValue_SetString(value, m_supp_standards);
    rbusObject_SetValue(ob, "SupportedStandards", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_op_standards);
    rbusObject_SetValue(ob, "OperatingStandards", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_basic_data_tx_rates);
    rbusObject_SetValue(ob, "BasicDataTransferRates", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_supp_data_tx_rates);
    rbusObject_SetValue(ob, "SupportedDataTransferRates", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_supp_nss);
    rbusObject_SetValue(ob, "SupportedNSS", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_dtim_period);
    rbusObject_SetValue(ob, "DTIMPeriod", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, m_beacon_period);
    rbusObject_SetValue(ob, "BeaconPeriod", value);
    rbusValue_Release(value);

}

void de_nbr_bss_t::deserialize(rbusObject_t& ob)
{
    rbusValue_t value;
    const char *ptr;

    if ((value = rbusObject_GetValue(ob, "BSSID")) == NULL) {
        printf("%s:%d: Could not find BSSID value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_bssid, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "SSID")) == NULL) {
        printf("%s:%d: Could not find SSID value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_ssid, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "SignalStrength")) == NULL) {
        printf("%s:%d: Could not find SignalStrength  value\n", __func__, __LINE__);
    } else {
        m_signal_strength = rbusValue_GetInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "ChannelBandwidth")) == NULL) {
        printf("%s:%d: Could not find ChannelBandwidth value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_channel_bw, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "ChannelUtilization")) == NULL) {
        printf("%s:%d: Could not find ChannelUtilization  value\n", __func__, __LINE__);
    } else {
        m_channel_util = rbusValue_GetUInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "StationCount")) == NULL) {
        printf("%s:%d: Could not find StationCount  value\n", __func__, __LINE__);
    } else {
        m_sta_count = rbusValue_GetUInt32(value);
    }

    if ((value = rbusObject_GetValue(ob, "MLDMACAddress")) == NULL) {
        printf("%s:%d: Could not find MLDMACAddress value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_mld_mac, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "ReportingBSSID")) == NULL) {
        printf("%s:%d: Could not find ReportingBSSID value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_rep_bssid, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "MultiBSSID")) == NULL) {
        printf("%s:%d: Could not find MultiBSSID  value\n", __func__, __LINE__);
    } else {
        m_multi_bssid = rbusValue_GetBoolean(value);
    }

    if ((value = rbusObject_GetValue(ob, "BSSLoadElementPresent")) == NULL) {
        printf("%s:%d: Could not find BSSLoadElementPresent  value\n", __func__, __LINE__);
    } else {
        m_bss_color = rbusValue_GetBoolean(value);
    }

    if ((value = rbusObject_GetValue(ob, "BSSColor")) == NULL) {
        printf("%s:%d: Could not find BSSColor  value\n", __func__, __LINE__);
    } else {    
        m_bss_color = rbusValue_GetUInt32(value);
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

    if ((value = rbusObject_GetValue(ob, "SupportedStandards")) == NULL) {
        printf("%s:%d: Could not find SupportedStandards value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_supp_standards, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "OperatingStandards")) == NULL) {
        printf("%s:%d: Could not find OperatingStandards value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_op_standards, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "BasicDataTransferRates")) == NULL) {
        printf("%s:%d: Could not find BasicDataTransferRates value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_basic_data_tx_rates, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "SupportedDataTransferRates")) == NULL) {
        printf("%s:%d: Could not find SupportedDataTransferRates value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_supp_data_tx_rates, ptr, strlen(ptr) + 1);
    }
    
    if ((value = rbusObject_GetValue(ob, "SupportedNSS")) == NULL) {
        printf("%s:%d: Could not find SupportedNSS  value\n", __func__, __LINE__);
    } else {    
        m_supp_nss = rbusValue_GetUInt32(value);
    }
    
    if ((value = rbusObject_GetValue(ob, "DTIMPeriod")) == NULL) {
        printf("%s:%d: Could not find DTIMPeriod  value\n", __func__, __LINE__);
    } else {    
        m_dtim_period = rbusValue_GetUInt32(value);
    }
    
    if ((value = rbusObject_GetValue(ob, "BeaconPeriod")) == NULL) {
        printf("%s:%d: Could not find BeaconPeriod  value\n", __func__, __LINE__);
    } else {    
        m_beacon_period = rbusValue_GetUInt32(value);
    }



}

void de_nbr_bss_t::serialize(cJSON *ob)
{
    cJSON_AddStringToObject(ob, "BSSID", m_bssid);
    cJSON_AddStringToObject(ob, "SSID", m_ssid);
    cJSON_AddNumberToObject(ob, "SignalStrength", m_signal_strength);
    cJSON_AddStringToObject(ob, "ChannelBandwidth", m_channel_bw);
    cJSON_AddNumberToObject(ob, "ChannelUtilization", m_channel_util);
    cJSON_AddNumberToObject(ob, "StationCount", m_sta_count);
    cJSON_AddStringToObject(ob, "MLDMACAddress", m_mld_mac);
    cJSON_AddStringToObject(ob, "ReportingBSSID", m_rep_bssid);
    cJSON_AddBoolToObject(ob, "MultiBSSID", m_multi_bssid);
    cJSON_AddBoolToObject(ob, "BSSLoadElementPresent", m_bss_load_elem_present);
    cJSON_AddNumberToObject(ob, "BSSColor", m_bss_color);
    cJSON_AddStringToObject(ob, "SecurityModeEnabled", m_security_mode_enabled);
    cJSON_AddStringToObject(ob, "EncryptionMode", m_encryption_mode);
    cJSON_AddStringToObject(ob, "SupportedStandards", m_supp_standards);
    cJSON_AddStringToObject(ob, "OperatingStandards", m_op_standards);
    cJSON_AddStringToObject(ob, "BasicDataTransferRates", m_basic_data_tx_rates);
    cJSON_AddStringToObject(ob, "SupportedDataTransferRates", m_supp_data_tx_rates);
    cJSON_AddNumberToObject(ob, "SupportedNSS", m_supp_nss);
    cJSON_AddNumberToObject(ob, "DTIMPeriod", m_dtim_period);
    cJSON_AddNumberToObject(ob, "BeaconPeriod", m_beacon_period);
}

void de_nbr_bss_t::deserialize(cJSON *ob)
{
    cJSON *elem;
    const char *str;

    elem = cJSON_GetObjectItem(ob, "BSSID");
    str = cJSON_GetStringValue(elem);
    strncpy(m_bssid, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "SSID");
    str = cJSON_GetStringValue(elem);
    strncpy(m_ssid, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "SignalStrength");
    m_signal_strength = cJSON_GetNumberValue(elem);
    
    elem = cJSON_GetObjectItem(ob, "ChannelBandwidth");
    str = cJSON_GetStringValue(elem);
    strncpy(m_channel_bw, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "ChannelUtilization");
    m_channel_util = cJSON_GetNumberValue(elem);
    
    elem = cJSON_GetObjectItem(ob, "StationCount");
    m_sta_count = cJSON_GetNumberValue(elem);
    
    elem = cJSON_GetObjectItem(ob, "MLDMACAddress");
    str = cJSON_GetStringValue(elem);
    strncpy(m_mld_mac, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "ReportingBSSID");
    str = cJSON_GetStringValue(elem);
    strncpy(m_rep_bssid, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "MultiBSSID");
    m_multi_bssid = cJSON_IsTrue(elem);
    
    elem = cJSON_GetObjectItem(ob, "BSSLoadElementPresent");
    m_bss_load_elem_present = cJSON_IsTrue(elem);
    
    elem = cJSON_GetObjectItem(ob, "BSSColor");
    m_bss_color = cJSON_GetNumberValue(elem);

    elem = cJSON_GetObjectItem(ob, "SecurityModeEnabled");
    str = cJSON_GetStringValue(elem);
    strncpy(m_security_mode_enabled, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "EncryptionMode");
    str = cJSON_GetStringValue(elem);
    strncpy(m_encryption_mode, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "SupportedStandards");
    str = cJSON_GetStringValue(elem);
    strncpy(m_supp_standards, str, strlen(str) + 1);
    
    elem = cJSON_GetObjectItem(ob, "OperatingStandards");
    str = cJSON_GetStringValue(elem);
    strncpy(m_op_standards, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "BasicDataTransferRates");
    str = cJSON_GetStringValue(elem);
    strncpy(m_basic_data_tx_rates, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "SupportedDataTransferRates");
    str = cJSON_GetStringValue(elem);
    strncpy(m_supp_data_tx_rates, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "SupportedNSS");
    m_supp_nss = cJSON_GetNumberValue(elem);

    elem = cJSON_GetObjectItem(ob, "DTIMPeriod");
    m_dtim_period = cJSON_GetNumberValue(elem);

    elem = cJSON_GetObjectItem(ob, "BeaconPeriod");
    m_beacon_period = cJSON_GetNumberValue(elem);

}


int de_nbr_bss_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_nbr_bss_t::deinit()
{

}

de_nbr_bss_t::de_nbr_bss_t()
{

}

de_nbr_bss_t::~de_nbr_bss_t()
{

}

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

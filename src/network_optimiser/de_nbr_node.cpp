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

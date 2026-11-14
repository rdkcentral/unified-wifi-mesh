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

#ifndef DE_NBR_BSS_H
#define DE_NBR_BSS_H

#include "em_base.h"

class de_nbr_bss_t {

public:
    em_long_string_t m_key;    
    em_string_t m_bssid;
    em_string_t m_ssid;
    int m_signal_strength;
    em_string_t m_channel_bw;
    unsigned int m_channel_util;
    unsigned int m_sta_count;
    em_string_t m_mld_mac;
    em_string_t m_rep_bssid;
    bool    m_multi_bssid;
    bool    m_bss_load_elem_present;
    unsigned int m_bss_color;
    em_string_t m_security_mode_enabled;
    em_string_t m_encryption_mode;
    em_string_t m_supp_standards;
    em_string_t m_op_standards;
    em_string_t m_basic_data_tx_rates;
    em_string_t m_supp_data_tx_rates;
    unsigned int m_supp_nss;
    unsigned int m_dtim_period;
    unsigned int m_beacon_period; 

public:
    int init(const char *key);
    void deinit();
    void update(de_nbr_bss_t& bss);

    de_nbr_bss_t();
    ~de_nbr_bss_t();
};

#endif
